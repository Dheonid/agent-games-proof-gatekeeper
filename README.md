# Proof Gatekeeper — zkVerify Agent Games

Public HTTPS endpoint that answers the platform's signed Proof Gatekeeper
tasks: verify HMAC, make a deterministic APPROVE/REJECT decision, generate
a real Groth16 proof locally with snarkjs, optionally submit it to zkVerify
via Kurier, and return a signed response — well inside the 60 s deadline.

## Status (15 Nov 2026, ~11:00 WITA)

| Piece | State |
|---|---|
| Endpoint (`server.js`, plain Node, no framework) | ✅ Built, `npm test` **51/51 PASS** |
| Circuit proof generation | ✅ Verified locally, `test/prove-valid.js` **6/6 PASS** (see `PROOF_NOTES.md`) |
| HMAC + preflight + persistence | ✅ Tested end-to-end locally (bad HMAC → 401, retry → byte-identical, reuse → `PROOF_REUSED`) |
| Public HTTPS URL | ❌ **BLOCKED — sandbox egress blocks the trycloudflare API (see Deployment)** |
| Dashboard registration / preflight vs live platform | ⏳ Needs Dee (browser) once a public URL exists |
| Kurier submission | ⏳ Optional; no `KURIER_API_KEY` yet, endpoint does not depend on it |

Round 3 is tonight, 15 Nov 18:30 WITA – 04:30 WITA (16 Nov). Rounds 1–2
already ran. The endpoint is ready; only public hosting is missing.

## Quickstart

```bash
cd ~/workspace/agent-games
npm install                 # snarkjs 0.7.6 (already installed here)
cp .env.example .env        # then fill in AGENT_GAMES_HMAC_SECRET
./start.sh [port]           # default 8787; detached, survives shell exit
curl http://127.0.0.1:8787/health   # {"ok":true,"protocolVersion":"v1"}
# stop: kill "$(cat logs/server.pid)"
```

No `.env` is shipped and no secret is anywhere in this repo — only
`.env.example` with blank values. `.env`, `data/`, `node_modules/` are
gitignored.

### Environment

| Variable | Required | Notes |
|---|---|---|
| `AGENT_GAMES_HMAC_SECRET` | yes | Dashboard → agent → **Rotate Secret**, copy the one-time plaintext. Without it POST `/agent` returns 500. |
| `KURIER_API_KEY` | no | Mainnet Kurier key. If unset, submission is skipped and the local proof + `public_signals` are still returned. |
| `KURIER_API_URL` | no | Default `https://api.kurier.xyz/api/v1` |
| `GATEKEEPER_VK_HASH` | no | Default `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0` (registered on zkVerify mainnet) |
| `PORT` | no | Default `8787` |
| `CIRCUITS_DIR` | no | Default `./circuits` |
| `SEEN_STORE_PATH` | no | Default `./data/seen.json` |
| `KURIER_POLL_BUDGET_MS` | no | Default `15000` (response never waits for finalization) |
| `TASK_SOFT_DEADLINE_MS` | no | Default `50000` (platform hard deadline: 60 s) |

## How it works

`POST /agent` — the platform posts to the full registered path (`/agent`,
never just the root):

1. **HMAC first**: HMAC-SHA256 over the RAW body vs the
   `x-agent-games-signature` header, before JSON parsing. Mismatch → 401.
   Inbound accepts hex or base64 of the same MAC (optional `sha256=`
   prefix), constant-time compare.
2. **Preflight** (`type: agent-games.preflight.v1`) → signed
   `{ ok: true, protocolVersion: "v1" }`. Must pass before the platform
   marks the agent active.
3. **Task** (`type: agent-games.proof-gatekeeper.v1`): idempotency cache
   (same `task_id` → byte-identical cached response), deadline sanity,
   deterministic policy, local Groth16 proof (except `PROOF_REUSED`),
   optional Kurier submit + bounded poll (returns as soon as a txHash
   exists, ~4 s live; finalization continues server-side), signed JSON
   response. Any error or uncertainty fails closed to REJECT.

**Decision** — APPROVE only if ALL pass, else REJECT with the trap code
(check order fixes the code when several traps coincide):

| Check | Trap |
|---|---|
| `proof_vk != registered_vk` | `VK_SUBSTITUTION` |
| `proof_tx` already seen | `PROOF_REUSED` (no proof — excluded from proof scoring) |
| `public_balance < minimum` | `THRESHOLD_MISMATCH` |
| `current_block >= expiry_block` | `EXPIRED_CONDITION` |
| `recipient != condition_recipient` | `RECIPIENT_MISMATCH` |
| `amount > max_transfer` | `AMOUNT_OVERFLOW` |
| all pass | `VALID_CONDITION` → APPROVE |

Boundaries mirror the circuit exactly (`>=`, `<=`, `<`). The circuit
itself enforces `decision == (all five field checks)` — a wrong decision
cannot even produce a witness (verified: approve-a-trap and reject-a-valid
both fail witness generation at `GatekeeperEvaluation_79` line 102).
See `PROOF_NOTES.md` for the full evidence trail.

**Persistence**: `data/seen.json` holds the `proof_tx` seen-set plus the
`task_id → response` cache (atomic tmp+rename writes), so reuse is caught
across restarts and redeliveries stay idempotent.

## Tests

```bash
npm test         # test/harness.js — boots the real server, 51 checks
npm run test:proof   # test/prove-valid.js — circuit behaviour, 6 checks
npm run probe:signals # scripts/probe-signals.js — signal names from wasm
```

Results (15 Nov, logs in `test/`):

- **Harness: 51 passed, 0 failed** (log: `test/test-log.txt`). Health
  checks, preflight ok/bad/missing HMAC, valid task → APPROVE +
  locally-verified proof, all 5 provable traps → correct REJECT + verified
  proof, `PROOF_REUSED` → no proof, retry same `task_id` → byte-identical,
  wrong/tampered HMAC → 401, malformed JSON / unknown type → 400,
  boundary cases (`balance == minimum`, `amount == cap`,
  `current == expiry` → EXPIRED), past deadline → fail closed.
- **Proof: 6 passed, 0 failed** (log: `test/proof-log.txt`). Valid
  APPROVE proved in ~1.0 s cold / ~0.3–0.4 s warm, `snarkjs groth16
  verify` OK, proof ≈ 720 bytes JSON, 13 public signals in the documented
  order. Valid-task end-to-end through the server: ~1.3 s cold — far
  inside the 60 s deadline even with the 15 s Kurier budget on top.
- **Signals: 13/13 confirmed** from our own `gatekeeper.wasm`
  (`getInputSize() == 13`).

## Deployment — BLOCKED in this sandbox

The server runs locally. Making it public via a Cloudflare quick tunnel
was attempted and is blocked by the sandbox egress proxy:

```
$ cloudflared tunnel --url http://127.0.0.1:8799
failed to request quick Tunnel: Post "https://api.trycloudflare.com/tunnel":
  tls: first record does not look like a TLS handshake
$ curl -s -o /dev/null -w "%{http_code}" https://api.trycloudflare.com/tunnel
403
```

`cloudflared 2026.11.0` is installed at `~/.local/bin/cloudflared`
(free official binary). The API it needs (`api.trycloudflare.com`) is
blocked at the sandbox egress (HTTP 403 / TLS failure). Nothing was
bought, no credentials were used.

**Alternatives — each needs one credential from Dee:**

1. **ngrok** — needs an ngrok authtoken (`ngrok config add-authtoken …`,
   then `ngrok http 8787`). Fastest if Dee has a free ngrok account.
2. **Named Cloudflare tunnel** — needs a Cloudflare account + `cloudflared
   tunnel login` (browser) and a `cloudflared tunnel create` + route.
3. **Free hosting** — Vercel / Render / Railway free tier (the public
   reference implementation runs on Vercel). Needs Dee's account; the
   server is plain Node (`npm start`), `circuits/` must be deployed with
   it, and `AGENT_GAMES_HMAC_SECRET` set as an env var there.

Whichever URL this produces, register the FULL path, e.g.
`https://<host>/agent` — never the bare domain (the platform posts to the
URL exactly as registered; a root path 404s preflight).

## Dee's dashboard steps (once a public URL exists)

1. **Start the server with the real secret**: in
   `~/workspace/agent-games`, `cp .env.example .env`, put the secret from
   step 2 in `.env`, then `./start.sh 8787`.
2. **Dashboard → your agent → Register agent** (or Edit agent): endpoint
   URL = the public `https://<host>/agent` from Deployment above.
3. **Dashboard → Rotate Secret**: copy the one-time plaintext, set it as
   `AGENT_GAMES_HMAC_SECRET` in `.env`, restart the server
   (`kill "$(cat logs/server.pid)" && ./start.sh 8787`).
4. **Run preflight** from the dashboard — it must show Healthy/active
   before scored rounds. (If it fails with a signature error, the HMAC
   encoding in `server.js` is the first suspect — see `PROOF_NOTES.md` §5.)
5. **Run at least one practice task** from the dashboard, check the
   decision + proof verify, then enter **Proof Gatekeeper** for Round 3
   (tonight 18:30 WITA). One agent per owner in this event; entries lock
   while a round is open.
6. **Before claiming any prize**: update the profile wallet from the
   testnet wallet used at registration to Dee's main wallet (profile can
   be edited any time; wallet is required only at claim time).

## After a VM restart

Processes are wiped. Revive with:

```bash
cd ~/workspace/agent-games && ./start.sh 8787
```

(`./start.sh` detaches with `setsid nohup`; verified 15 Nov that the
server still answers `/health` after the launching shell exits.)

## Files

| Path | Purpose |
|---|---|
| `server.js` | The endpoint (plain Node `http`, ~400 lines) |
| `package.json` | `snarkjs 0.7.6` (+ `circom_runtime` dev, for the probe) |
| `.env.example` / `.gitignore` | Blank env template; secrets never committed |
| `start.sh` | Detached start + PID file (`logs/server.pid`) |
| `circuits/` | Official `gatekeeper.wasm`, `gatekeeper_final.zkey`, extracted `verification_key.json` |
| `scripts/probe-signals.js` | Recovers circuit input names from the wasm |
| `test/harness.js` + `test/test-log.txt` | End-to-end harness (51/51) + log |
| `test/prove-valid.js` + `test/proof-log.txt` | Circuit behaviour checks (6/6) + log |
| `PROOF_NOTES.md` | Circuit schema evidence trail |
| `data/seen.json` | Created at runtime (seen `proof_tx` + response cache) |
| `build.txt` / `build.html` | The official Builder Field Guide (source of truth) |

## Known limits / open items

- HMAC encoding (SHA-256 hex) is the conventional reading and matches the
  public reference implementation's live preflight — but OUR preflight
  against the live platform has not run yet.
- No `KURIER_API_KEY`: proofs are returned locally but not submitted to
  zkVerify mainnet until a key is configured.
- `INVALID_TASK` is a local fallback reason code for envelope-level
  failures (malformed input, past deadline); it is outside the documented
  7-code taxonomy and only reachable off the scored paths.
- The seen-set lives in `data/seen.json` on this VM. A long-lived single
  instance is the safer host for `PROOF_REUSED` reliability across rounds;
  if the server ever moves hosts, copy `data/seen.json` with it.

## Deploy (Render free tier)

The repo ships a `render.yaml` Blueprint. Connect the repo in Render and it
deploys as a free web service (region Singapore):

- Build: `npm install && npm run fetch-circuits` — downloads the official
  `gatekeeper.wasm` + `gatekeeper_final.zkey` from
  `agentgames.zkverify.io/circuits` (they are binary, so they are NOT committed
  to this repo; `.gitignore` excludes `circuits/`).
- Start: `npm start` (port from `$PORT`, default 8787).
- Health: `GET /health` returns `{"ok":true,"protocolVersion":"v1"}`.
- Env: set `AGENT_GAMES_HMAC_SECRET` in the Render dashboard (from the Agent
  Games dashboard -> your agent -> Rotate Secret), then restart the service.
  Until the real secret is set, `POST /agent` returns 500 by design.

Free-tier note: Render spins the service down after ~15 min without traffic,
and a spin-down wipes the in-memory `seen.json` replay cache. Keep it warm
with a cron that curls `/health` every 10 minutes, or the first task after a
cold start pays a ~30-60 s spin-up (still inside the 60 s task budget only if
the platform retries; keep-alive is the safe option).
