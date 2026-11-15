/**
 * Local end-to-end harness. Spins up the real agent server (subprocess) plus
 * a stub Kurier, then replays signed envelopes the way the platform would:
 * preflight, a valid task, every trap class from the /build Security
 * checklist, replay/retry handling, and the Kurier-finalization gate.
 *
 * Run: npm test
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createHmac } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";

// The harness imports circuit.js (which loads config) only to cross-check
// the taskId encoding — give this process a dummy secret first. The agent
// subprocess gets the real harness secret via its own environment below.
process.env.AGENT_GAMES_HMAC_SECRET ??= "harness-local-placeholder";
const { encodeTaskId } = await import("../src/circuit.js");
const { keccak256Hex } = await import("../src/keccak.js");

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const SECRET = "harness-test-secret-not-a-real-one";
const REAL_VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const OTHER_VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b1";
const RECIPIENT = "0xDe42000000000000000000000000000000009f01";
const OTHER_RECIPIENT = "0xDe42000000000000000000000000000000009f02";
const STUB_TX = "0x" + "ab".repeat(32);
const VK = JSON.parse(fs.readFileSync(path.join(ROOT, "circuits", "vk.json"), "utf8"));

let failures = 0;
function check(name: string, cond: boolean, extra?: string): void {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${extra ? " — " + extra : ""}`);
  if (!cond) failures++;
}

const sign = (body: string, secret = SECRET) =>
  createHmac("sha256", secret).update(body).digest("hex");

// ── Stub Kurier ──────────────────────────────────────────────────────────────
let kurierMode: "finalize" | "never" = "finalize";
let pollCount = 0;
const kurier = http.createServer((req, res) => {
  const url = req.url ?? "";
  res.setHeader("content-type", "application/json");
  if (req.method === "POST" && url.startsWith("/api/v1/submit-proof/")) {
    pollCount = 0;
    res.end(JSON.stringify({ jobId: "job-stub-1", optimisticVerify: "success" }));
    return;
  }
  if (req.method === "GET" && url.startsWith("/api/v1/job-status/")) {
    pollCount++;
    if (kurierMode === "finalize" && pollCount >= 2) {
      res.end(JSON.stringify({ status: "Finalized", txHash: STUB_TX }));
    } else {
      res.end(JSON.stringify({ status: kurierMode === "finalize" ? "IncludedInBlock" : "Submitted" }));
    }
    return;
  }
  res.writeHead(404);
  res.end("{}");
});
await new Promise<void>((r) => kurier.listen(18742, r));

// ── Agent server lifecycle ───────────────────────────────────────────────────
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "gk-harness-"));
async function startAgent(port: number, extraEnv: Record<string, string>): Promise<ChildProcess> {
  const child = spawn("node", [path.join(ROOT, "dist", "src", "server.js")], {
    cwd: ROOT,
    env: {
      ...process.env,
      AGENT_GAMES_HMAC_SECRET: SECRET,
      PORT: String(port),
      AGENT_PATH: "/agent",
      KURIER_API_KEY: "stub-key",
      KURIER_API_URL: "http://127.0.0.1:18742/api/v1",
      KURIER_POLL_INTERVAL_MS: "300",
      STORE_PATH: path.join(tmp, `store-${port}.json`),
      ...extraEnv,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stderr.on("data", (d) => process.stderr.write(`[agent] ${d}`));
  const deadline = Date.now() + 20_000;
  for (;;) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/healthz`);
      if (r.ok) return child;
    } catch { /* not up yet */ }
    if (Date.now() > deadline) throw new Error("agent did not start");
    await new Promise((r) => setTimeout(r, 200));
  }
}

interface Resp { status: number; bodyText: string; json: any; sigOk: boolean }
async function post(port: number, bodyObj: unknown, secret = SECRET): Promise<Resp> {
  const bodyText = JSON.stringify(bodyObj);
  const res = await fetch(`http://127.0.0.1:${port}/agent`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": sign(bodyText, secret) },
    body: bodyText,
  });
  const text = await res.text();
  const header = res.headers.get("x-agent-games-signature");
  return {
    status: res.status,
    bodyText: text,
    json: JSON.parse(text),
    sigOk: header !== null && header === sign(text),
  };
}

let txCounter = 0;
function envelope(overrides: Record<string, any> = {}, inputOverrides: Record<string, any> = {}): any {
  txCounter++;
  const now = Date.now();
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: `gk_harness_${txCounter}`,
    mode: "practice",
    issued_at: new Date(now).toISOString(),
    deadline_at: new Date(now + 60_000).toISOString(),
    input: {
      registered_vk: REAL_VK,
      proof_vk: REAL_VK,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: RECIPIENT,
      condition_recipient: RECIPIENT,
      amount: "500",
      max_transfer: "1000",
      proof_tx: "0x" + txCounter.toString(16).padStart(64, "0"),
      ...inputOverrides,
    },
    ...overrides,
  };
}

async function proofVerifies(r: Resp): Promise<boolean> {
  if (!r.json.proof || !r.json.public_signals) return false;
  return snarkjs.groth16.verify(VK, r.json.public_signals, r.json.proof);
}

// ── Unit: keccak vectors + taskId encoding ───────────────────────────────────
check("keccak256(\"\") vector", keccak256Hex("") === "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
check("keccak256(\"abc\") vector", keccak256Hex("abc") === "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");

// ── Phase 1: Kurier finalizes ────────────────────────────────────────────────
const agent = await startAgent(18741, {});

const pre = await post(18741, { type: "agent-games.preflight.v1", agent_id: "agt_harness", issued_at: new Date().toISOString(), nonce: "n1" });
check("preflight ok + protocolVersion + signed", pre.status === 200 && pre.json.ok === true && pre.json.protocolVersion === "v1" && pre.sigOk);

const bad = await post(18741, envelope(), "the-wrong-secret");
check("bad HMAC → 401", bad.status === 401);

const validEnv = envelope();
const valid = await post(18741, validEnv);
check("valid task → APPROVE/OK", valid.json.decision === "APPROVE" && valid.json.reason_code === "OK");
check("valid task → response signed", valid.sigOk);
check("valid task → 13 public signals, decision=1", Array.isArray(valid.json.public_signals) && valid.json.public_signals.length === 13 && valid.json.public_signals[11] === "1");
check("valid task → taskId signal matches encoding", valid.json.public_signals?.[12] === encodeTaskId(validEnv.task_id));
check("valid task → proof verifies locally", await proofVerifies(valid));
check("valid task → proof_tx is Kurier finalized tx", valid.json.proof_tx === STUB_TX);

const vkTrap = await post(18741, envelope({}, { proof_vk: OTHER_VK }));
check("proof_vk ≠ registered_vk → REJECT/VK_SUBSTITUTION", vkTrap.json.decision === "REJECT" && vkTrap.json.reason_code === "VK_SUBSTITUTION");
check("VK trap → proof of rejection verifies", await proofVerifies(vkTrap));

const wrongPair = await post(18741, envelope({}, { registered_vk: OTHER_VK, proof_vk: OTHER_VK }));
check("equal-but-wrong VK pair → REJECT/VK_SUBSTITUTION", wrongPair.json.decision === "REJECT" && wrongPair.json.reason_code === "VK_SUBSTITUTION");
check("equal-but-wrong VK pair → no proof (unprovable class)", wrongPair.json.proof === undefined);

const recipTrap = await post(18741, envelope({}, { condition_recipient: OTHER_RECIPIENT }));
check("recipient mismatch → REJECT/RECIPIENT_MISMATCH + proof", recipTrap.json.reason_code === "RECIPIENT_MISMATCH" && (await proofVerifies(recipTrap)));

const amountTrap = await post(18741, envelope({}, { amount: "1001" }));
check("amount > max → REJECT/AMOUNT_EXCEEDS_MAX + proof", amountTrap.json.reason_code === "AMOUNT_EXCEEDS_MAX" && (await proofVerifies(amountTrap)));

const balanceTrap = await post(18741, envelope({}, { public_balance: "999" }));
check("balance < minimum → REJECT/BELOW_MINIMUM + proof", balanceTrap.json.reason_code === "BELOW_MINIMUM" && (await proofVerifies(balanceTrap)));

const expiryTrap = await post(18741, envelope({}, { current_block: 8430000 }));
check("current == expiry → REJECT/EXPIRED + proof", expiryTrap.json.reason_code === "EXPIRED" && (await proofVerifies(expiryTrap)));

const boundary = await post(18741, envelope({}, { public_balance: "1000", amount: "1000", current_block: 8429999 }));
check("boundaries (balance==min, amount==max, current==expiry-1) → APPROVE", boundary.json.decision === "APPROVE" && (await proofVerifies(boundary)));

const replay = await post(18741, envelope({}, { proof_tx: validEnv.input.proof_tx }));
check("reused proof_tx → REJECT/PROOF_REUSED, no proof", replay.json.reason_code === "PROOF_REUSED" && replay.json.proof === undefined);

const retry = await post(18741, validEnv);
check("same task_id retried → byte-identical response", retry.bodyText === valid.bodyText);

const expired = await post(18741, envelope({ issued_at: new Date(Date.now() - 120_000).toISOString(), deadline_at: new Date(Date.now() - 60_000).toISOString() }));
check("past deadline_at → REJECT/TASK_EXPIRED", expired.json.reason_code === "TASK_EXPIRED");

const malformed = await post(18741, envelope({}, { minimum: "not-a-number" }));
check("malformed minimum → REJECT/MALFORMED_INPUT", malformed.json.reason_code === "MALFORMED_INPUT");

agent.kill();

// ── Phase 2: Kurier never finalizes → APPROVE must fail closed ───────────────
kurierMode = "never";
const agent2 = await startAgent(18743, { RESPONSE_BUDGET_MS: "6000", KURIER_POLL_INTERVAL_MS: "400" });
const noFin = await post(18743, envelope());
check("Kurier never finalizes → REJECT/FINALIZATION_TIMEOUT, no proof", noFin.json.decision === "REJECT" && noFin.json.reason_code === "FINALIZATION_TIMEOUT" && noFin.json.proof === undefined);
agent2.kill();

kurier.close();
console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
