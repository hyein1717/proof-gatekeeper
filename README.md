# Proof Gatekeeper — zkVerify Agent Games

A production-ready HTTP agent for the **Proof Gatekeeper** track of the
zkVerify Agent Games. The platform POSTs signed task envelopes describing a
transfer request; this agent decides **APPROVE** or **REJECT** with
deterministic code (never a language model), proves the decision locally with
the official Groth16 gatekeeper circuit (snarkjs), confirms it on zkVerify
via Kurier, and returns a signed response — inside the platform's 60-second
hard deadline, failing closed on any doubt.

Protocol source of truth: <https://agentgames.zkverify.io/build> (§02 agent
interface, §02.5 circuit artifacts, §03 zkVerify integration, §04 Security
checklist) and <https://agentgames.zkverify.io/guide> (registration).

## File structure

```
proof-gatekeeper/
├── circuits/
│   ├── gatekeeper.wasm          # official circuit (from /build artifacts)
│   ├── gatekeeper_final.zkey    # official proving key
│   └── vk.json                  # verification key extracted from the zkey
├── src/
│   ├── config.ts      # env loading + validation (secrets from env only)
│   ├── hmac.ts        # HMAC-SHA256 sign/verify over RAW bodies, timing-safe
│   ├── keccak.ts      # dependency-free Keccak-256 (taskId encoding)
│   ├── types.ts       # wire schemas + reason codes
│   ├── circuit.ts     # envelope validation + circuit input building
│   ├── decide.ts      # THE decision engine (deterministic checklist)
│   ├── prover.ts      # snarkjs fullProve + local verify before sending
│   ├── kurier.ts      # Kurier submit-proof + poll job-status → Finalized
│   ├── store.ts       # seen proof refs + idempotent task responses (JSON)
│   ├── handler.ts     # preflight + task pipeline (budget-aware, fail-closed)
│   └── server.ts      # node:http(s) server, raw body, watchdog deadline
├── test/
│   └── harness.ts     # end-to-end replay of sample envelopes + stub Kurier
├── scripts/
│   ├── probe-circuit.mjs  # how the circuit's signals/predicate were verified
│   └── probe2.mjs         # VK-constant + salt-binding probes
├── .env.example       # blank template — copy to .env, fill locally
└── package.json
```

## The protocol, as implemented

**Preflight** — platform sends `{ "type": "agent-games.preflight.v1", ... }`;
agent replies `{ "ok": true, "protocolVersion": "v1" }`, signed.

**Task** — platform sends:

```json
{
  "type": "agent-games.proof-gatekeeper.v1",
  "task_id": "gk_...",
  "mode": "competition",
  "issued_at": "<ISO>", "deadline_at": "<ISO>",
  "input": {
    "registered_vk": "0x…", "proof_vk": "0x…",
    "minimum": "1000", "public_balance": "1460",
    "expiry_block": 8430000, "current_block": 8420000,
    "recipient": "0x…", "condition_recipient": "0x…",
    "amount": "500", "max_transfer": "1000",
    "proof_tx": "0x…"
  }
}
```

**Response** — `{ decision, reason_code, proof, public_signals, proof_tx }`.
Every response to an authenticated request carries a valid
`x-agent-games-signature` header (HMAC over the raw response body).

**Authentication** — every inbound request's `x-agent-games-signature` is
verified against the **raw body before JSON parsing** (constant-time
compare). Mismatch → bare `401`, no work performed.

## The circuit (verified empirically, not assumed)

The /build page does not publish the circuit's signal layout, so it was
recovered from the official artifacts and proven by experiment
(`npm run probe`, `node scripts/probe2.mjs`):

- **Inputs (13):** `registeredVkHash, proofVkHash, minimum, publicBalance,
  expiryBlock, currentBlock, recipient, conditionRecipient, amount,
  maxTransfer, decision, taskId, salt` (only `salt` is private).
- **Public signals (13):** a commitment output (bound to all inputs and the
  private salt), then the 12 public inputs in the order above.
- **Enforced predicate:** a witness exists ⟺
  `decision == 1` exactly when **all** checks pass. A wrong decision — in
  either direction — cannot even produce a witness.
- **Boundary semantics:** `public_balance >= minimum` (inclusive),
  `amount <= max_transfer` (inclusive), `current_block < expiry_block`
  (**strict** — equality is expired).
- **The circuit does NOT embed the registered VK hash:** an equal-but-wrong
  VK pair proves `decision=1`. The decision engine therefore also pins
  `registered_vk` to the competition's registered VK hash from
  `/api/circuit-info`
  (`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`).
  That trap class is rejected without a proof (a `decision=0` witness is
  mathematically impossible there).

## Decision table (mirrors the /build Security checklist, in order)

| Check | On failure |
|---|---|
| HMAC signature over raw body | HTTP 401, no processing |
| `issued_at`/`deadline_at` valid, deadline not passed | `REJECT / INVALID_TIMESTAMP` or `TASK_EXPIRED` |
| Envelope fields well-formed | `REJECT / MALFORMED_INPUT` |
| `registered_vk` == registered VK hash ∧ `proof_vk` == `registered_vk` | `REJECT / VK_SUBSTITUTION` |
| `proof_tx` never seen before | `REJECT / PROOF_REUSED` (decision alone, no proof) |
| `public_balance >= minimum` | `REJECT / BELOW_MINIMUM` |
| `recipient == condition_recipient` | `REJECT / RECIPIENT_MISMATCH` |
| `amount <= max_transfer` | `REJECT / AMOUNT_EXCEEDS_MAX` |
| `current_block < expiry_block` | `REJECT / EXPIRED` |
| Proof of the decision generates + locally verifies | `REJECT / PROOF_GENERATION_FAILED` |
| Kurier job reaches **Finalized** in budget (APPROVE only) | `REJECT / FINALIZATION_TIMEOUT` or `KURIER_ERROR` |
| All pass | `APPROVE / OK` + proof + finalized `proof_tx` |

Platform retries of the same `task_id` return the byte-identical cached
response; every `proof_tx` ever presented is remembered across restarts
(`data/store.json`).

## Setup

```bash
npm install
npm run build

# Circuit artifacts (already vendored in circuits/; refresh like this):
curl -o circuits/gatekeeper.wasm       https://agentgames.zkverify.io/circuits/gatekeeper.wasm
curl -o circuits/gatekeeper_final.zkey https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
npx snarkjs zkey export verificationkey circuits/gatekeeper_final.zkey circuits/vk.json

cp .env.example .env   # then fill it in LOCALLY — see below
npm start              # or: npm run dev (no build step)
npm test               # end-to-end harness: 24 checks, incl. every trap class
```

### Secrets — read carefully

- `AGENT_GAMES_HMAC_SECRET`: dashboard → **Rotate Secret** → copy the
  one-time plaintext into your local `.env`. Never paste it into chat, a
  prompt, or a commit; `.env` is gitignored.
- `KURIER_API_KEY`: from kurier.xyz. Sent only to the Kurier API.
- Without a Kurier key the agent runs in practice mode: proofs are generated
  and locally verified, but APPROVEs do not wait for zkVerify finalization.

### Testnet vs mainnet

`/api/circuit-info` reports `"network": "mainnet"` and /build states the
VK hashes are *registered on zkVerify mainnet* — so the default
`KURIER_API_URL` is mainnet. For plumbing tests you can point
`KURIER_API_URL` at `https://api-testnet.kurier.xyz/api/v1` with a testnet
key, but the competition VK hash will not resolve there (you would register
the extracted `circuits/vk.json` yourself via Kurier's `register-vk`).
Scored play needs the mainnet key.

## Going live (from /guide + /build §05)

1. Register at agentgames.zkverify.io (X account or wallet) and create the
   agent for the Proof Gatekeeper track.
2. Deploy this service behind a **public HTTPS URL on the standard port**
   (terminate TLS at your host/reverse proxy, or set `TLS_CERT_FILE` /
   `TLS_KEY_FILE`). Register the **full handler path** — `https://host/agent`,
   not the root.
3. Rotate the agent secret on the dashboard; set it as
   `AGENT_GAMES_HMAC_SECRET`; restart the agent.
4. Run preflight from the dashboard — it must pass before the platform marks
   the agent active.
5. Play the **unscored practice tasks** first and confirm the documented
   assumptions below (signature format, taskId encoding) hold; then enter
   scored rounds.

## Spec gaps — documented assumptions

The /build page is the source of truth, but it leaves four details
unstated. Each is isolated behind one config knob so a failed practice task
costs minutes, not a rewrite:

1. **HMAC encoding** — the page mandates HMAC over the raw body but does not
   name the digest/encoding. Implemented as HMAC-SHA256 hex; inbound also
   accepts a `sha256=` prefix; outbound format switches via
   `SIGNATURE_FORMAT=hex|sha256-hex`. Preflight is the arbiter.
2. **Reason codes** — only `VK_SUBSTITUTION` is published. The rest follow
   the same convention and map 1:1 to the Security checklist; `APPROVE`
   carries `reason_code: "OK"`. Scoring turns on `decision`.
3. **`proof_tx` in the response** — the response carries this agent's own
   Kurier-finalized tx hash when available (the "finalized reference used
   for scoring", §01/§03); otherwise it echoes the task's `input.proof_tx`
   (the /build sample pair shows the same value in envelope and response).
4. **`taskId` field encoding** — not published. `TASK_ID_ENCODING=keccak`
   (default; keccak256 of the UTF-8 task_id, mod p), `numeric`, or `hex`.
   Validate on practice tasks.

Also: timestamp validity is enforced as "deadline not passed" plus a 120 s
future-skew allowance on `issued_at`; a request with a bad signature gets a
bare 401 (it is not an authenticated platform message, so there is nothing
to sign for it).

## Operations

- `GET /healthz` → `{ ok: true }` (unsigned, for deploy health checks).
- Logs are single-line JSON (task id, decision, reason, durations). Secrets,
  signatures, and request bodies are never logged.
- `data/store.json` persists seen proof references and task responses
  (checklist: "references are retained for disputes"). Single-instance
  design — swap `Store` for Redis/Postgres before scaling out.
- The server enforces a hard response budget (`RESPONSE_BUDGET_MS`, default
  55 s) with a watchdog that fails closed with a signed `REJECT / TIMEOUT`
  rather than ever missing the platform's 60 s deadline silently.
