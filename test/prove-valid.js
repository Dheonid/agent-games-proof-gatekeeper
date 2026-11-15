// Standalone proof check: does the official gatekeeper circuit accept the
// claimed input schema, and does it refuse wrong decisions?
// Run: node test/prove-valid.js
// No server, no secrets, no network. Uses only circuits/ + snarkjs.
"use strict";

const crypto = require("crypto");
const path = require("path");
const snarkjs = require("snarkjs");

const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const WASM = path.join(__dirname, "..", "circuits", "gatekeeper.wasm");
const ZKEY = path.join(__dirname, "..", "circuits", "gatekeeper_final.zkey");
const VK = path.join(__dirname, "..", "circuits", "verification_key.json");

function toField(v) {
  let n;
  const s = String(v).trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) n = BigInt(s);
  else if (/^[0-9]+$/.test(s)) n = BigInt(s);
  else n = BigInt("0x" + crypto.createHash("sha256").update(s).digest("hex"));
  return (((n % BN128_PRIME) + BN128_PRIME) % BN128_PRIME).toString(10);
}

function inputs(o) {
  return {
    taskId: toField(o.taskId),
    registeredVkHash: toField(o.registeredVk),
    proofVkHash: toField(o.proofVk),
    minimum: String(o.minimum),
    publicBalance: String(o.publicBalance),
    expiryBlock: String(o.expiryBlock),
    currentBlock: String(o.currentBlock),
    recipient: toField(o.recipient),
    conditionRecipient: toField(o.conditionRecipient),
    amount: String(o.amount),
    maxTransfer: String(o.maxTransfer),
    decision: String(o.decision),
    salt: String(o.salt),
  };
}

const BASE = {
  taskId: "gk_test_valid_001",
  registeredVk: VK_HASH,
  proofVk: VK_HASH,
  minimum: 1000,
  publicBalance: 1460,
  expiryBlock: 8430000,
  currentBlock: 8420000,
  recipient: "0xDe42111111111111111111111111111111119f01",
  conditionRecipient: "0xDe42111111111111111111111111111111119f01",
  amount: 500,
  maxTransfer: 1000,
  decision: 1,
  salt: 12345,
};

async function tryProve(name, inp, expectOk) {
  const t0 = Date.now();
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      inp, WASM, ZKEY,
    );
    const ms = Date.now() - t0;
    const vk = JSON.parse(require("fs").readFileSync(VK, "utf8"));
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    const bytes = Buffer.byteLength(JSON.stringify(proof));
    const status = ok && expectOk ? "PASS" : ok && !expectOk ? "FAIL(unexpected verify)" : "FAIL";
    console.log(`[${status}] ${name}: proved in ${ms}ms, verify=${ok}, proof=${bytes} bytes, publicSignals=${publicSignals.length}`);
    console.log(`  publicSignals: ${JSON.stringify(publicSignals)}`);
    return { ok, proof, publicSignals, ms, bytes };
  } catch (e) {
    const ms = Date.now() - t0;
    const status = !expectOk ? "PASS" : "FAIL";
    console.log(`[${status}] ${name}: fullProve threw after ${ms}ms (expected=${!expectOk}): ${String(e.message).split("\n")[0]}`);
    return { ok: false, error: e, ms };
  }
}

(async () => {
  let pass = 0, fail = 0;
  const check = (r, want) => { if ((r.ok === want) || (r.error && !want)) pass++; else fail++; };

  // 1. Valid scenario (Diki article values): APPROVE must prove + verify.
  const r1 = await tryProve("valid APPROVE (1460>=1000, 500<=1000, recipient match, 8420000<8430000, vk match)", inputs(BASE), true);
  check(r1, true);
  // Public-signal order check: [commitment, registeredVkHash, proofVkHash,
  // minimum, publicBalance, expiryBlock, currentBlock, recipient,
  // conditionRecipient, amount, maxTransfer, decision, taskId]
  if (r1.publicSignals) {
    const ps = r1.publicSignals;
    const expected = [
      null, // [0] commitment = Poseidon(taskId, salt), opaque
      toField(VK_HASH), toField(VK_HASH), "1000", "1460", "8430000", "8420000",
      toField(BASE.recipient), toField(BASE.conditionRecipient), "500", "1000", "1",
      toField(BASE.taskId),
    ];
    let orderOk = ps.length === 13;
    for (let i = 1; i < 13; i++) if (ps[i] !== expected[i]) { orderOk = false; console.log(`  !! publicSignals[${i}] = ${ps[i]}, expected ${expected[i]}`); }
    console.log(`[${orderOk ? "PASS" : "FAIL"}] public-signals order matches [commitment, registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision, taskId]`);
    if (orderOk) pass++; else fail++;
  }

  // 2. Approve a trap (recipient mismatch, decision=1) must FAIL witness gen.
  const r2 = await tryProve("APPROVE on recipient-mismatch trap (decision=1)", inputs({ ...BASE, taskId: "gk_test_trap_recipient", recipient: "0xBEEF11111111111111111111111111111111beef", decision: 1 }), false);
  check(r2, false);

  // 3. Reject a valid request (decision=0, all checks pass) must FAIL.
  const r3 = await tryProve("REJECT on valid request (decision=0, all checks pass)", inputs({ ...BASE, taskId: "gk_test_reject_valid", decision: 0 }), false);
  check(r3, false);

  // 4. Reject a trap (recipient mismatch, decision=0) must prove + verify.
  const r4 = await tryProve("REJECT on recipient-mismatch trap (decision=0)", inputs({ ...BASE, taskId: "gk_test_reject_trap", recipient: "0xBEEF11111111111111111111111111111111beef", decision: 0 }), true);
  check(r4, true);

  // 5. Approve a VK-substitution trap must FAIL.
  const r5 = await tryProve("APPROVE on VK_SUBSTITUTION trap (decision=1)", inputs({ ...BASE, taskId: "gk_test_trap_vk", proofVk: "0x13aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", decision: 1 }), false);
  check(r5, false);

  console.log(`\nprove-valid: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
