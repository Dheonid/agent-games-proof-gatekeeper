// Proof Gatekeeper agent — zkVerify Agent Games (Season 01).
// Plain Node.js, no framework. One file, ~400 lines.
//
// POST /agent  — signed task envelopes + preflight handshake
// GET  /agent  — health check { ok: true, protocolVersion: "v1" }
// GET  /health — same health payload
//
// Protocol source of truth: https://agentgames.zkverify.io/build
// (full text saved in build.txt). Circuit input schema verified locally
// against the official artifacts — see PROOF_NOTES.md.
//
// Secrets: ONLY from environment variables. Never hardcode, never log.
//   AGENT_GAMES_HMAC_SECRET — required; dashboard -> Rotate Secret
//   KURIER_API_KEY          — optional; without it, zkVerify submission
//                             is skipped and the local proof is returned.
//   GATEKEEPER_VK_HASH      — optional, defaults to the registered hash
//   PORT                    — optional, default 8787
//   CIRCUITS_DIR            — optional, default ./circuits
//   SEEN_STORE_PATH         — optional, default ./data/seen.json
//   KURIER_POLL_BUDGET_MS   — optional, default 15000
//   TASK_SOFT_DEADLINE_MS   — optional, default 50000 (platform: 60s hard)
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const path = require("path");
const snarkjs = require("snarkjs");

// ---------------------------------------------------------------- config
const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
const PREFLIGHT_TYPE = "agent-games.preflight.v1";
const PROTOCOL_VERSION = "v1";
const SIGNATURE_HEADER = "x-agent-games-signature";
const GATEKEEPER_VK_HASH =
  process.env.GATEKEEPER_VK_HASH ||
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const KURIER_API_KEY = process.env.KURIER_API_KEY || "";
const KURIER_API_URL = process.env.KURIER_API_URL || "https://api.kurier.xyz/api/v1";
const KURIER_POLL_BUDGET_MS = Number(process.env.KURIER_POLL_BUDGET_MS || 15000);
const KURIER_POLL_INTERVAL_MS = 3000;
const TASK_SOFT_DEADLINE_MS = Number(process.env.TASK_SOFT_DEADLINE_MS || 50000);
const PORT = Number(process.env.PORT || 8787);
const CIRCUITS_DIR = process.env.CIRCUITS_DIR || path.join(__dirname, "circuits");
const SEEN_STORE_PATH =
  process.env.SEEN_STORE_PATH || path.join(__dirname, "data", "seen.json");
const MAX_BODY_BYTES = 1_048_576;

// ---------------------------------------------------------------- HMAC
function signBody(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

function decodeMac(headerValue) {
  let v = String(headerValue || "").trim();
  if (v.toLowerCase().startsWith("sha256=")) v = v.slice("sha256=".length).trim();
  if (/^[0-9a-fA-F]{64}$/.test(v)) return Buffer.from(v, "hex");
  try {
    const b = Buffer.from(v, "base64");
    if (b.length === 32) return b;
  } catch { /* fall through */ }
  return null;
}

// HMAC-SHA256 over the RAW body. Accepts the same MAC bytes as hex or
// base64 (representation tolerance, not a weakening: caller must know
// the secret). Compared in constant time. Verified BEFORE JSON parsing.
function verifyBodySignature(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return false;
  const candidate = decodeMac(headerValue);
  if (!candidate) return false;
  const expected = crypto.createHmac("sha256", secret).update(rawBody).digest();
  return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
}

// Deterministic per-task salt for the circuit's private `salt` input:
// HMAC(secret, "gatekeeper-salt:" + task_id) mod p. Deterministic so a
// redelivered task reproduces identical proof inputs; secret-bound so it
// is not predictable to third parties.
function deriveSalt(secret, taskId) {
  const digest = crypto
    .createHmac("sha256", secret || "gatekeeper-local-dev")
    .update(`gatekeeper-salt:${taskId}`)
    .digest();
  return BigInt("0x" + digest.toString("hex")) % BN128_PRIME;
}

// ---------------------------------------------------------------- decision
function normalizeHex(v) { return (v || "").trim().toLowerCase(); }

function parseUint(v) {
  if (typeof v === "number") return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  return null;
}

// Structural validation + parsing. Returns null on any malformed field.
function parseInput(input) {
  if (!input || typeof input !== "object") return null;
  const minimum = parseUint(input.minimum);
  const publicBalance = parseUint(input.public_balance);
  const amount = parseUint(input.amount);
  const maxTransfer = parseUint(input.max_transfer);
  const expiryBlock = parseUint(input.expiry_block);
  const currentBlock = parseUint(input.current_block);
  if (minimum === null || publicBalance === null || amount === null ||
      maxTransfer === null || expiryBlock === null || currentBlock === null) return null;
  for (const f of ["registered_vk", "proof_vk", "recipient", "condition_recipient", "proof_tx"]) {
    if (typeof input[f] !== "string" || !input[f]) return null;
  }
  return {
    registeredVk: input.registered_vk, proofVk: input.proof_vk,
    minimum, publicBalance, expiryBlock, currentBlock,
    recipient: input.recipient, conditionRecipient: input.condition_recipient,
    amount, maxTransfer, proofTx: input.proof_tx,
  };
}

// Deterministic policy. APPROVE only when EVERY check passes, else REJECT
// with the trap's reason_code. Check order (VK, reuse, threshold, expiry,
// recipient, amount) fixes which code is reported when several traps
// coincide. Boundaries mirror the circuit exactly: balance >= minimum
// passes, amount <= max_transfer passes, current_block < expiry passes.
// `provable` is false only for PROOF_REUSED — the event page states those
// tasks "have no proof to submit and are excluded" from proof scoring.
function evaluate(parsed, isProofTxSeen) {
  if (normalizeHex(parsed.proofVk) !== normalizeHex(parsed.registeredVk)) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", provable: true };
  }
  if (isProofTxSeen(parsed.proofTx)) {
    return { decision: "REJECT", reason_code: "PROOF_REUSED", provable: false };
  }
  if (parsed.publicBalance < parsed.minimum) {
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", provable: true };
  }
  if (parsed.currentBlock >= parsed.expiryBlock) {
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION", provable: true };
  }
  if (normalizeHex(parsed.recipient) !== normalizeHex(parsed.conditionRecipient)) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", provable: true };
  }
  if (parsed.amount > parsed.maxTransfer) {
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", provable: true };
  }
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", provable: true };
}

// Envelope value -> BN128 field element (decimal string). Hex values are
// reduced mod p (a 32-byte hash does not fit the field); reduction preserves
// equality, which is all the circuit checks. Free-form ids (e.g.
// "gk_8d31_x") are SHA-256 hashed into the field.
function toFieldElement(v) {
  let n;
  if (typeof v === "bigint") n = v;
  else {
    const s = String(v).trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) n = BigInt(s);
    else if (/^[0-9]+$/.test(s)) n = BigInt(s);
    else n = BigInt("0x" + crypto.createHash("sha256").update(s).digest("hex"));
  }
  return (((n % BN128_PRIME) + BN128_PRIME) % BN128_PRIME).toString(10);
}

// Circuit inputs for gatekeeper.wasm — signal names recovered from the
// artifact itself (scripts/probe-signals.js) and confirmed by proving.
// Public signals order: [commitment, registeredVkHash, proofVkHash,
// minimum, publicBalance, expiryBlock, currentBlock, recipient,
// conditionRecipient, amount, maxTransfer, decision, taskId]
// where commitment = Poseidon(taskId, salt) is the only circuit output.
function buildCircuitInputs(taskId, parsed, decision, salt) {
  return {
    taskId: toFieldElement(taskId),
    registeredVkHash: toFieldElement(parsed.registeredVk),
    proofVkHash: toFieldElement(parsed.proofVk),
    minimum: parsed.minimum.toString(10),
    publicBalance: parsed.publicBalance.toString(10),
    expiryBlock: parsed.expiryBlock.toString(10),
    currentBlock: parsed.currentBlock.toString(10),
    recipient: toFieldElement(parsed.recipient),
    conditionRecipient: toFieldElement(parsed.conditionRecipient),
    amount: parsed.amount.toString(10),
    maxTransfer: parsed.maxTransfer.toString(10),
    decision: decision === "APPROVE" ? "1" : "0",
    salt: salt.toString(10),
  };
}

// ---------------------------------------------------------------- seen store
// proof_tx seen-set + task_id -> response cache, JSON-file backed.
// In-memory is authoritative for the process; the file survives restarts.
// Atomic write via tmp + rename. Never logs secrets.
class SeenStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.seenProofTx = new Set();
    this.responseByTaskId = new Map();
    this.load();
  }
  load() {
    try {
      const data = JSON.parse(fs.readFileSync(this.filePath, "utf8"));
      for (const tx of data.proofTx || []) this.seenProofTx.add(normalizeHex(tx));
      for (const [k, v] of Object.entries(data.responses || {})) this.responseByTaskId.set(k, v);
    } catch { /* missing/corrupt -> start empty */ }
  }
  persist() {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      const tmp = `${this.filePath}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify({
        proofTx: [...this.seenProofTx],
        responses: Object.fromEntries(this.responseByTaskId),
      }));
      fs.renameSync(tmp, this.filePath);
    } catch (e) { console.error("[seen-store] persist failed:", e.message); }
  }
  hasProofTx(tx) { return this.seenProofTx.has(normalizeHex(tx)); }
  recordProofTx(tx) {
    const key = normalizeHex(tx);
    if (!key || this.seenProofTx.has(key)) return;
    this.seenProofTx.add(key);
    this.persist();
  }
  getResponse(taskId) { return this.responseByTaskId.get(taskId) || null; }
  recordResponse(taskId, body) {
    if (this.responseByTaskId.has(taskId)) return;
    this.responseByTaskId.set(taskId, body);
    this.persist();
  }
}

// ---------------------------------------------------------------- Kurier
// Optional zkVerify submission (needs KURIER_API_KEY). Never throws, never
// blocks the task answer on finalization: returns as soon as a txHash
// exists (Submitted status, ~4s live), finalization completes server-side.
// Without a key this is a no-op and the local proof is still returned.
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function submitProofAndPoll(proof, publicSignals, budgetMs) {
  if (!KURIER_API_KEY) return null;
  const deadline = Date.now() + Math.max(0, budgetMs);
  try {
    const submitRes = await fetch(`${KURIER_API_URL}/submit-proof/${KURIER_API_KEY}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: GATEKEEPER_VK_HASH },
      }),
    });
    if (!submitRes.ok) { console.error(`[kurier] submit-proof HTTP ${submitRes.status}`); return null; }
    const job = await submitRes.json();
    if (!job.jobId) { console.error("[kurier] submit-proof response missing jobId"); return null; }
    console.log(`[kurier] job ${job.jobId} submitted (optimisticVerify=${job.optimisticVerify ?? "n/a"})`);
    let status = "Submitted";
    let lastTxHash;
    while (Date.now() < deadline) {
      await sleep(Math.min(KURIER_POLL_INTERVAL_MS, Math.max(0, deadline - Date.now())));
      const sRes = await fetch(`${KURIER_API_URL}/job-status/${KURIER_API_KEY}/${job.jobId}`);
      if (!sRes.ok) { console.error(`[kurier] job-status HTTP ${sRes.status}`); continue; }
      const s = await sRes.json();
      status = s.status || status;
      const txHash = s.txHash || (s.transactionInfo && s.transactionInfo.txHash);
      if (txHash) lastTxHash = txHash;
      if (status === "Failed") return { jobId: job.jobId, status, txHash, finalized: false };
      if (txHash) return { jobId: job.jobId, status, txHash, finalized: status === "Finalized" };
    }
    console.log(`[kurier] job ${job.jobId} produced no txHash within budget (last status=${status})`);
    return { jobId: job.jobId, status, txHash: lastTxHash, finalized: false };
  } catch (e) {
    console.error("[kurier] submission error:", e.message);
    return null;
  }
}

// ---------------------------------------------------------------- handler
const store = new SeenStore(SEEN_STORE_PATH);
const WASM_PATH = path.join(CIRCUITS_DIR, "gatekeeper.wasm");
const ZKEY_PATH = path.join(CIRCUITS_DIR, "gatekeeper_final.zkey");

function signed(status, obj) {
  const body = JSON.stringify(obj);
  return { status, body, signature: signBody(HMAC_SECRET, body) };
}
function signedRaw(status, body) {
  return { status, body, signature: signBody(HMAC_SECRET, body) };
}

function parseTimestamp(v) {
  if (typeof v === "number" && Number.isFinite(v)) return v < 1e12 ? v * 1000 : v;
  if (typeof v === "string") {
    if (/^[0-9]+$/.test(v.trim())) {
      const n = Number(v);
      if (Number.isFinite(n)) return n < 1e12 ? n * 1000 : n;
    }
    const t = Date.parse(v);
    return Number.isNaN(t) ? null : t;
  }
  return null;
}

async function handlePost(rawBody, signatureHeader) {
  const startedAt = Date.now();
  if (!HMAC_SECRET) {
    return { status: 500, body: JSON.stringify({ error: "server_misconfigured", detail: "AGENT_GAMES_HMAC_SECRET not set" }), signature: null };
  }
  // 1. Authenticate the raw body BEFORE parsing.
  if (!verifyBodySignature(HMAC_SECRET, rawBody, signatureHeader)) {
    return { status: 401, body: JSON.stringify({ error: "invalid_signature" }), signature: null };
  }
  let envelope;
  try {
    envelope = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return signed(400, { decision: "REJECT", reason_code: "INVALID_TASK" });
  }
  // 2. Preflight handshake.
  if (envelope.type === PREFLIGHT_TYPE) {
    return signed(200, { ok: true, protocolVersion: PROTOCOL_VERSION });
  }
  if (envelope.type !== TASK_TYPE) {
    return signed(400, { decision: "REJECT", reason_code: "INVALID_TASK" });
  }
  // 3. Task — any error fails closed to REJECT, never to an approval.
  try {
    return await handleTask(envelope, startedAt);
  } catch (e) {
    console.error("[agent] task handling error:", e.message);
    return signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
  }
}

async function handleTask(task, startedAt) {
  // Idempotent redelivery: answer from cache, never re-evaluate (a
  // redelivery must not be mistaken for proof reuse).
  if (task.task_id) {
    const cached = store.getResponse(task.task_id);
    if (cached) return signedRaw(200, cached);
  }
  // Timestamp sanity (HMAC already authenticates the sender). Unparseable
  // timestamps are logged, not fatal — only a clearly-past deadline fails.
  const now = Date.now();
  const deadlineMs = parseTimestamp(task.deadline_at);
  const issuedMs = parseTimestamp(task.issued_at);
  if (deadlineMs !== null && now > deadlineMs) {
    return signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
  }
  if (issuedMs !== null && issuedMs > now + 5 * 60_000) {
    return signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
  }
  const parsed = parseInput(task.input);
  if (!parsed || !task.task_id) {
    return signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
  }
  const ev = evaluate(parsed, (tx) => store.hasProofTx(tx));
  const response = { decision: ev.decision, reason_code: ev.reason_code };
  if (ev.provable) {
    const salt = deriveSalt(HMAC_SECRET, task.task_id);
    const circuitInputs = buildCircuitInputs(task.task_id, parsed, ev.decision, salt);
    try {
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        circuitInputs, WASM_PATH, ZKEY_PATH,
      );
      response.proof = proof;
      response.public_signals = publicSignals;
      // Kurier submission, bounded so the response stays well inside 60s.
      // Never blocks the answer on finalization.
      const remaining = TASK_SOFT_DEADLINE_MS - (Date.now() - startedAt);
      const budget = Math.min(KURIER_POLL_BUDGET_MS, Math.max(0, remaining));
      const kurier = await submitProofAndPoll(proof, publicSignals, budget);
      response.proof_tx = kurier && kurier.txHash ? kurier.txHash : parsed.proofTx;
    } catch (e) {
      // Proving failed: fail closed. A claimed APPROVE without a valid
      // proof is the worst outcome, so downgrade to REJECT with no proof.
      console.error("[agent] proof generation failed:", e.message.split("\n")[0]);
      return signed(200, {
        decision: "REJECT",
        reason_code: ev.decision === "APPROVE" ? "INVALID_TASK" : ev.reason_code,
        proof_tx: parsed.proofTx,
      });
    }
  } else {
    // PROOF_REUSED: documented as having no proof to submit; echo the ref.
    response.proof_tx = parsed.proofTx;
  }
  const result = signed(200, response);
  // Record only after a successful evaluation, so a task never flags itself.
  store.recordProofTx(parsed.proofTx);
  store.recordResponse(task.task_id, result.body);
  const ms = Date.now() - startedAt;
  console.log(`[agent] ${task.task_id} ${response.decision}/${response.reason_code} ${ms}ms${response.proof ? " proof=ok" : " proof=none"}`);
  return result;
}

// ---------------------------------------------------------------- HTTP server
const server = http.createServer((req, res) => {
  const url = new URL(req.url || "/", "http://localhost");
  if (req.method === "GET" && (url.pathname === "/agent" || url.pathname === "/health")) {
    const body = JSON.stringify({ ok: true, protocolVersion: PROTOCOL_VERSION });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(body);
    return;
  }
  if (req.method === "POST" && url.pathname === "/agent") {
    const chunks = [];
    let size = 0;
    let tooLarge = false;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        tooLarge = true;
        res.writeHead(413, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "payload_too_large" }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", async () => {
      if (tooLarge) return;
      const result = await handlePost(Buffer.concat(chunks), req.headers[SIGNATURE_HEADER]);
      const headers = { "content-type": "application/json" };
      if (result.signature) headers[SIGNATURE_HEADER] = result.signature;
      res.writeHead(result.status, headers);
      res.end(result.body);
    });
    req.on("error", () => {
      if (!res.headersSent) res.writeHead(400);
      res.end();
    });
    return;
  }
  res.writeHead(404, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: "not_found" }));
});

if (require.main === module) {
  if (!HMAC_SECRET) {
    console.warn("[agent] WARNING: AGENT_GAMES_HMAC_SECRET is not set — POST /agent will return 500 until it is set (dashboard -> Rotate Secret).");
  }
  if (!KURIER_API_KEY) {
    console.log("[agent] KURIER_API_KEY not set — zkVerify submission skipped; local Groth16 proof is still returned.");
  }
  server.listen(PORT, () => {
    console.log(`[agent] Proof Gatekeeper listening on :${PORT} (POST /agent)`);
  });
}

module.exports = { server, handlePost, signBody, verifyBodySignature, evaluate, parseInput, buildCircuitInputs, toFieldElement, deriveSalt };
