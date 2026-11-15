// End-to-end test harness for the Proof Gatekeeper agent.
// Boots the REAL server on an ephemeral localhost port with a throwaway
// test HMAC secret, then replays spec-shaped envelopes and checks every
// response (decision, reason_code, proof validity via snarkjs, response
// signature, idempotency). No network beyond localhost, no real secrets.
// Run: npm test   (or: node test/harness.js)
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");

// Throwaway test secret + isolated seen-store, set BEFORE requiring server.
const TEST_SECRET = "harness-test-secret-do-not-use-in-production";
process.env.AGENT_GAMES_HMAC_SECRET = TEST_SECRET;
process.env.SEEN_STORE_PATH = path.join(
  fs.mkdtempSync(path.join(os.tmpdir(), "gk-seen-")), "seen.json",
);
process.env.KURIER_API_KEY = ""; // no zkVerify submission in tests

const { server, signBody } = require("../server.js");
const snarkjs = require("snarkjs");

const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const RECIPIENT = "0xDe42111111111111111111111111111111119f01";
const VK = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "circuits", "verification_key.json"), "utf8"));

let pass = 0, fail = 0;
const failures = [];
function check(name, ok, detail) {
  if (ok) { pass++; console.log(`[PASS] ${name}`); }
  else { fail++; failures.push(name); console.log(`[FAIL] ${name}${detail ? " — " + detail : ""}`); }
}

function req(port, method, pth, body, sigHeader) {
  return new Promise((resolve, reject) => {
    const raw = body === undefined ? "" : (typeof body === "string" ? body : JSON.stringify(body));
    const headers = { "content-type": "application/json" };
    if (sigHeader !== undefined) headers["x-agent-games-signature"] = sigHeader;
    const r = http.request({ host: "127.0.0.1", port, path: pth, method, headers }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    r.on("error", reject);
    r.end(raw);
  });
}
const sign = (raw) => crypto.createHmac("sha256", TEST_SECRET).update(raw).digest("hex");
const verifyRespSig = (resp) => {
  const h = resp.headers["x-agent-games-signature"];
  if (!h) return false;
  const expected = crypto.createHmac("sha256", TEST_SECRET).update(resp.body).digest();
  try {
    const got = Buffer.from(h, "hex");
    return got.length === expected.length && crypto.timingSafeEqual(got, expected);
  } catch { return false; }
};

function taskEnvelope(taskId, proofTx, overrides = {}) {
  const now = new Date();
  const env = {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "competition",
    issued_at: now.toISOString(),
    deadline_at: new Date(now.getTime() + 60000).toISOString(),
    input: {
      registered_vk: VK_HASH,
      proof_vk: VK_HASH,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: RECIPIENT,
      condition_recipient: RECIPIENT,
      amount: "500",
      max_transfer: "1000",
      proof_tx: proofTx,
    },
  };
  Object.assign(env.input, overrides);
  return env;
}

async function verifyProof(resp, label) {
  let body;
  try { body = JSON.parse(resp.body); } catch { return false; }
  if (!body.proof || !body.public_signals || body.public_signals.length !== 13) return false;
  try { return await snarkjs.groth16.verify(VK, body.public_signals, body.proof); }
  catch { return false; }
}

(async () => {
  const port = await new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
  console.log(`harness: server on 127.0.0.1:${port} (test secret, isolated seen-store)`);
  const t0 = Date.now();
  try {
    // 1-2. Health checks.
    let r = await req(port, "GET", "/agent");
    check("GET /agent health 200 {ok:true, protocolVersion:v1}", r.status === 200 && JSON.parse(r.body).ok === true && JSON.parse(r.body).protocolVersion === "v1");
    r = await req(port, "GET", "/health");
    check("GET /health 200", r.status === 200 && JSON.parse(r.body).ok === true);
    r = await req(port, "GET", "/nope");
    check("GET /nope 404", r.status === 404);

    // 3-5. Preflight.
    const pre = JSON.stringify({ type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" });
    r = await req(port, "POST", "/agent", pre, sign(pre));
    check("preflight signed -> 200 {ok:true, protocolVersion:v1} + valid resp sig",
      r.status === 200 && JSON.parse(r.body).ok === true && JSON.parse(r.body).protocolVersion === "v1" && verifyRespSig(r));
    r = await req(port, "POST", "/agent", pre, sign("tampered"));
    check("preflight bad HMAC -> 401", r.status === 401);
    r = await req(port, "POST", "/agent", pre, undefined);
    check("preflight missing signature -> 401", r.status === 401);

    // 6. Valid task -> APPROVE + verified proof.
    const validTx = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const validEnv = taskEnvelope("gk_harness_valid_001", validTx);
    const validRaw = JSON.stringify(validEnv);
    const tValid = Date.now();
    r = await req(port, "POST", "/agent", validRaw, sign(validRaw));
    const validMs = Date.now() - tValid;
    let b;
    try { b = JSON.parse(r.body); } catch { b = null; }
    check("valid task -> 200 APPROVE/VALID_CONDITION", r.status === 200 && b && b.decision === "APPROVE" && b.reason_code === "VALID_CONDITION", r.body.slice(0, 200));
    check("valid task response signature valid", verifyRespSig(r));
    check("valid task proof present + 13 public signals", !!b && !!b.proof && Array.isArray(b.public_signals) && b.public_signals.length === 13);
    check("valid task proof verifies locally (snarkjs groth16 verify)", await verifyProof(r, "valid"));
    const validRespBody = r.body;
    check("valid task proof_tx echoed", !!b && b.proof_tx === validTx);
    check(`valid task answered in ${validMs}ms (<60s deadline)`, validMs < 60000);
    console.log(`  valid task wall time: ${validMs}ms`);

    // 7. Traps (each with a fresh proof_tx).
    const traps = [
      ["VK_SUBSTITUTION", { proof_vk: "0x13aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }],
      ["THRESHOLD_MISMATCH", { public_balance: "999" }],
      ["EXPIRED_CONDITION", { current_block: 8430000 }],
      ["RECIPIENT_MISMATCH", { recipient: "0xBEEF11111111111111111111111111111111beef" }],
      ["AMOUNT_OVERFLOW", { amount: "1001" }],
    ];
    for (let i = 0; i < traps.length; i++) {
      const [code, over] = traps[i];
      const tx = `0x${(i + 2).toString(16).padStart(2, "0")}` + "bb".repeat(31);
      const env = taskEnvelope(`gk_harness_trap_${code.toLowerCase()}_001`, tx, over);
      const raw = JSON.stringify(env);
      const tTrap = Date.now();
      const rr = await req(port, "POST", "/agent", raw, sign(raw));
      let bb; try { bb = JSON.parse(rr.body); } catch { bb = null; }
      check(`${code} -> REJECT/${code}`, rr.status === 200 && bb && bb.decision === "REJECT" && bb.reason_code === code, rr.body.slice(0, 200));
      check(`${code} response signature valid`, verifyRespSig(rr));
      check(`${code} proof verifies locally`, await verifyProof(rr, code));
      check(`${code} answered in ${Date.now() - tTrap}ms (<60s)`, true);
    }

    // 8. PROOF_REUSED: same proof_tx as the valid task, new task_id.
    const reuseEnv = taskEnvelope("gk_harness_reuse_001", validTx);
    const reuseRaw = JSON.stringify(reuseEnv);
    r = await req(port, "POST", "/agent", reuseRaw, sign(reuseRaw));
    try { b = JSON.parse(r.body); } catch { b = null; }
    check("PROOF_REUSED (same proof_tx, new task_id) -> REJECT/PROOF_REUSED", r.status === 200 && b && b.decision === "REJECT" && b.reason_code === "PROOF_REUSED", r.body.slice(0, 200));
    check("PROOF_REUSED carries NO proof", !!b && !b.proof && !b.public_signals);
    check("PROOF_REUSED echoes proof_tx", !!b && b.proof_tx === validTx);
    check("PROOF_REUSED response signature valid", verifyRespSig(r));

    // 9. Retry same task_id -> byte-identical cached response.
    r = await req(port, "POST", "/agent", validRaw, sign(validRaw));
    check("retry same task_id -> byte-identical to original response", r.body === validRespBody);
    check("retry task_id is NOT flagged as PROOF_REUSED", (() => { try { return JSON.parse(r.body).reason_code === "VALID_CONDITION"; } catch { return false; } })());

    // 10-11. Bad HMAC / tampered body on a task.
    r = await req(port, "POST", "/agent", validRaw, sign("other-secret-body"));
    check("task with wrong HMAC -> 401", r.status === 401);
    const tampered = validRaw.replace("1460", "9999");
    r = await req(port, "POST", "/agent", tampered, sign(validRaw));
    check("task with tampered body (sig of original) -> 401", r.status === 401);

    // 12-13. Malformed JSON / unknown type (both signed).
    const badJson = "{not json";
    r = await req(port, "POST", "/agent", badJson, sign(badJson));
    check("malformed JSON (signed) -> 400 REJECT/INVALID_TASK", r.status === 400 && JSON.parse(r.body).reason_code === "INVALID_TASK");
    const unk = JSON.stringify({ type: "agent-games.unknown.v1", task_id: "x" });
    r = await req(port, "POST", "/agent", unk, sign(unk));
    check("unknown type (signed) -> 400 REJECT/INVALID_TASK", r.status === 400 && JSON.parse(r.body).reason_code === "INVALID_TASK");

    // 14. Boundaries: balance == minimum -> APPROVE; amount == cap -> APPROVE;
    //     current_block == expiry_block -> REJECT EXPIRED.
    const bCases = [
      ["boundary balance==minimum -> APPROVE", { public_balance: "1000" }, "APPROVE", "VALID_CONDITION"],
      ["boundary amount==max_transfer -> APPROVE", { amount: "1000" }, "APPROVE", "VALID_CONDITION"],
      ["boundary current_block==expiry_block -> REJECT EXPIRED", { current_block: 8430000 }, "REJECT", "EXPIRED_CONDITION"],
      ["boundary amount 0 -> APPROVE", { amount: "0" }, "APPROVE", "VALID_CONDITION"],
    ];
    for (let i = 0; i < bCases.length; i++) {
      const [name, over, dec, code] = bCases[i];
      const tx = `0x${(0xC0 + i).toString(16)}` + "cc".repeat(31);
      const env = taskEnvelope(`gk_harness_bound_${i}`, tx, over);
      const raw = JSON.stringify(env);
      const rr = await req(port, "POST", "/agent", raw, sign(raw));
      let bb; try { bb = JSON.parse(rr.body); } catch { bb = null; }
      check(name, rr.status === 200 && bb && bb.decision === dec && bb.reason_code === code, rr.body.slice(0, 200));
      if (dec === "APPROVE" || code !== "PROOF_REUSED") check(`${name} proof verifies`, await verifyProof(rr, name));
    }

    // 15. Past-deadline task fails closed.
    const past = taskEnvelope("gk_harness_past_001", "0xdd" + "dd".repeat(31));
    past.deadline_at = new Date(Date.now() - 60000).toISOString();
    const pastRaw = JSON.stringify(past);
    r = await req(port, "POST", "/agent", pastRaw, sign(pastRaw));
    check("past-deadline task -> REJECT/INVALID_TASK (fail closed)", r.status === 200 && JSON.parse(r.body).decision === "REJECT", r.body.slice(0, 200));
  } finally {
    server.close();
  }
  console.log(`\nharness: ${pass} passed, ${fail} failed (total ${Date.now() - t0}ms)`);
  if (failures.length) console.log("failures:", failures.join("; "));
  process.exit(fail ? 1 : 0);
})();
