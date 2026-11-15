# PROOF_NOTES — gatekeeper circuit input schema

Status: **VERIFIED with independent local evidence** (15 Nov 2026, ~10:35–10:45 WITA).
Nothing in this file is guessed: every claim below cites a command that was
actually run against the official artifacts downloaded from
`agentgames.zkverify.io` in this workspace.

## 1. Artifacts (downloaded 15 Nov 02:35 UTC)

| File | Size | SHA-256 |
|---|---|---|
| `circuits/gatekeeper.wasm` | 1.7 MB | `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f` |
| `circuits/gatekeeper_final.zkey` | 303 KB | `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d` |
| `circuits/verification_key.json` | 5.0 KB | `6ce4899b3bc74d6a5c10ede61daf8820716982e1ef7e6778a5a8872ddaf28221` |

Source: `https://agentgames.zkverify.io/api/circuit-info` (live, 15 Nov):
`gatekeeper.vkHash = 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`,
wasm/zkey URLs as above. Groth16/BN128, Circom 2.x, snarkjs 0.7.6.

Cross-check: the verification key extracted from OUR zkey
(`snarkjs zkey export verificationkey`) is **byte-identical** (same SHA-256)
to the `verification_key.json` shipped in the public reference implementation
`github.com/andruu21/proof-gatekeeper-agent` — independent confirmation our
artifacts are the tournament circuit.

## 2. Input signal names — recovered from OUR wasm, not copied

`node scripts/probe-signals.js circuits/gatekeeper.wasm` (FNV-1a hash oracle
over the wasm `getInputSignalSize` export; script in `scripts/`):

```
getInputSize(): 13
  input signal: taskId (size 1)
  input signal: registeredVkHash (size 1)
  input signal: proofVkHash (size 1)
  input signal: minimum (size 1)
  input signal: publicBalance (size 1)
  input signal: expiryBlock (size 1)
  input signal: currentBlock (size 1)
  input signal: recipient (size 1)
  input signal: conditionRecipient (size 1)
  input signal: amount (size 1)
  input signal: maxTransfer (size 1)
  input signal: decision (size 1)
  input signal: salt (size 1)
```

13 inputs, all size 1. This matches the signal list published by Diki Ardian
(Medium, 14 Nov 2026) who recovered the same names the same way — but the
above output is from OUR artifact, run here.

## 3. Value encoding (verified by proving, §4)

Implemented in `server.js` (`toFieldElement`, `buildCircuitInputs`):

- Hex values (vk hashes, addresses) → `BigInt(hex) mod p`, decimal string.
  A 32-byte hash does not fit the BN128 field; reduction preserves the
  equality checks the circuit performs.
- Decimal strings / numbers → used directly as decimal strings.
- Free-form `task_id` (e.g. `gk_8d31_…`) → SHA-256, then mod p.
- `decision`: `"1"` = APPROVE, `"0"` = REJECT.
- `salt` (private): `HMAC-SHA256(secret, "gatekeeper-salt:" + task_id) mod p`
  — deterministic per task, secret-bound, so a redelivered task reproduces
  identical proof inputs.
- Public signals order (confirmed, §4):
  `[commitment, registeredVkHash, proofVkHash, minimum, publicBalance,
  expiryBlock, currentBlock, recipient, conditionRecipient, amount,
  maxTransfer, decision, taskId]` where `commitment = Poseidon(taskId, salt)`
  is the circuit's only output.

## 4. Proof behaviour — `node test/prove-valid.js` (6/6 PASS, log: `test/proof-log.txt`)

Valid scenario (values from the Medium reference: balance 1460 vs min 1000,
amount 500 vs cap 1000, recipient match, current 8,420,000 < expiry 8,430,000,
vk = registered `0x6b79c6…77b0`):

| Case | Result |
|---|---|
| Valid APPROVE (decision=1) | PASS — proved in ~1.0 s cold / ~0.3–0.4 s warm, `snarkjs groth16 verify` OK, proof ≈ 720 bytes JSON, 13 public signals, order matches §3 |
| APPROVE on recipient-mismatch trap (decision=1) | PASS — `fullProve` throws `Assert Failed. Error in template GatekeeperEvaluation_79 line: 102` |
| REJECT on valid request (decision=0, all checks pass) | PASS — same assert failure at line 102 |
| REJECT on recipient-mismatch trap (decision=0) | PASS — proved, verify OK |
| APPROVE on VK_SUBSTITUTION trap (decision=1) | PASS — same assert failure at line 102 |

So the circuit enforces `decision == (all five field checks)`:
a wrong decision cannot even produce a witness. The endpoint mirrors this
exactly in `server.js` `evaluate()` (same five checks, same boundaries:
`balance >= minimum`, `amount <= max_transfer`, `current_block < expiry_block`).

## 5. What is NOT verified here

- **HMAC key encoding**: the /build page mandates HMAC over the raw body but
  never names the algorithm/encoding. We use HMAC-SHA256, hex digest
  outbound; inbound accepts the same MAC as hex or base64 (optional
  `sha256=` prefix), constant-time compare. The public reference
  implementation used exactly this and reports platform preflight
  "Healthy, 579 ms" plus 4/4 practice tasks correct — but OUR preflight
  against the live platform has NOT run yet (no public URL — see README §
  Deployment). If the platform rejects our preflight with a signature
  error, this encoding is the first thing to re-check.
- **Kurier submission**: code path is implemented per /build, but no
  `KURIER_API_KEY` exists, so no live submission has been attempted.
  Submission is optional and never blocks the task response.
- **Live platform behaviour**: no task has been received from the real
  platform yet. The harness (`npm test`, 51/51) replays spec-shaped
  envelopes locally only.
