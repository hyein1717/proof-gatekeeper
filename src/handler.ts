import { config } from "./config.js";
import { buildCircuitInput, validateTaskInput } from "./circuit.js";
import { decideTask } from "./decide.js";
import { signBody } from "./hmac.js";
import { submitAndWaitFinalized } from "./kurier.js";
import { proveDecision } from "./prover.js";
import type { Store } from "./store.js";
import {
  PROTOCOL_VERSION,
  ReasonCode,
  type TaskEnvelope,
  type TaskResponseBody,
} from "./types.js";

export interface SignedResponse {
  status: number;
  body: string;
  signature: string;
}

/** Serializes a response body once and signs the exact bytes that are sent. */
export function makeResponse(status: number, bodyObj: unknown): SignedResponse {
  const body = JSON.stringify(bodyObj);
  return { status, body, signature: signBody(body) };
}

function log(event: string, fields: Record<string, unknown>): void {
  console.log(JSON.stringify({ ts: new Date().toISOString(), event, ...fields }));
}

/** Preflight: the platform checks the endpoint can authenticate and sign. */
export function handlePreflight(): SignedResponse {
  log("preflight", {});
  return makeResponse(200, { ok: true, protocolVersion: PROTOCOL_VERSION });
}

const FUTURE_SKEW_MS = 120_000;
/** Keep a safety margin inside the hard deadline for serialization/sending. */
const RESPONSE_RESERVE_MS = 750;

/**
 * The full task pipeline. Deterministic, fail-closed at every step:
 * timestamps → schema → idempotency/replay → decision engine → proof →
 * (Kurier finalization gates APPROVE) → signed response. Whatever response
 * is produced is cached under task_id, so a platform retry of the same task
 * returns byte-identical bytes.
 */
export async function handleTask(
  parsed: unknown,
  store: Store,
  startedAt: number
): Promise<SignedResponse> {
  const envelope = parsed as Partial<TaskEnvelope>;
  const taskId = typeof envelope?.task_id === "string" ? envelope.task_id : undefined;

  const finish = (status: number, bodyObj: TaskResponseBody): SignedResponse => {
    const res = makeResponse(status, bodyObj);
    if (taskId) {
      store.saveTaskResponse(taskId, {
        status: res.status,
        body: res.body,
        signature: res.signature,
        storedAt: new Date().toISOString(),
      });
    }
    log("task_response", {
      task_id: taskId ?? null,
      decision: bodyObj.decision,
      reason_code: bodyObj.reason_code,
      proved: Boolean(bodyObj.proof),
      ms: Date.now() - startedAt,
    });
    return res;
  };
  const reject = (reasonCode: ReasonCode, proofTx?: string): SignedResponse =>
    finish(200, { decision: "REJECT", reason_code: reasonCode, proof_tx: proofTx });

  try {
    if (!taskId || typeof envelope.issued_at !== "string" || typeof envelope.deadline_at !== "string") {
      return reject(ReasonCode.MALFORMED_INPUT);
    }

    // Idempotent retry: return the exact response already sent for this task.
    const cached = store.getTaskResponse(taskId);
    if (cached) {
      log("task_cache_hit", { task_id: taskId });
      return { status: cached.status, body: cached.body, signature: cached.signature };
    }

    // Checklist: "The task signature and timestamp are valid before any work
    // begins." (The HMAC signature is verified by the server before parsing.)
    const issuedAt = Date.parse(envelope.issued_at);
    const deadlineAt = Date.parse(envelope.deadline_at);
    if (Number.isNaN(issuedAt) || Number.isNaN(deadlineAt)) {
      return reject(ReasonCode.INVALID_TIMESTAMP);
    }
    if (issuedAt > Date.now() + FUTURE_SKEW_MS) {
      return reject(ReasonCode.INVALID_TIMESTAMP);
    }
    if (Date.now() > deadlineAt) {
      return reject(ReasonCode.TASK_EXPIRED);
    }
    const hardDeadline = Math.min(startedAt + config.responseBudgetMs, deadlineAt);

    if (!validateTaskInput(envelope.input)) {
      return reject(ReasonCode.MALFORMED_INPUT);
    }
    const input = envelope.input;

    // Replay guard: a proof reference is consumed the first time it is seen.
    const proofRefAlreadySeen = !store.markProofRefSeen(input.proof_tx, taskId);

    const outcome = decideTask(envelope as TaskEnvelope, proofRefAlreadySeen);
    if (!outcome.approve && outcome.skipProof) {
      // Proof-reference replay: decision alone, no new proof.
      return reject(outcome.reasonCode, input.proof_tx);
    }

    // Prove the decision. The circuit enforces decision ⟺ all checks pass,
    // so a witness failure here means the engine and the circuit disagree
    // (or an unprovable rejection class, e.g. an equal-but-wrong VK pair).
    let proved;
    try {
      proved = await proveDecision(buildCircuitInput(input, taskId, outcome.approve ? 1 : 0));
    } catch (e) {
      log("proof_failed", {
        task_id: taskId,
        approve: outcome.approve,
        error: e instanceof Error ? e.message.slice(0, 200) : String(e),
      });
      if (outcome.approve) {
        // Fail closed: an approval that cannot be proven is not an approval.
        return reject(ReasonCode.PROOF_GENERATION_FAILED, input.proof_tx);
      }
      return reject(outcome.reasonCode, input.proof_tx);
    }

    // zkVerify confirmation via Kurier. Finalization gates APPROVE when a
    // Kurier key is configured; it never gates a REJECT.
    const kurierBudget = Math.max(0, hardDeadline - Date.now() - RESPONSE_RESERVE_MS);
    if (outcome.approve) {
      const fin = await submitAndWaitFinalized(
        proved.proof,
        proved.publicSignals,
        kurierBudget
      );
      if (fin.kind === "finalized") {
        return finish(200, {
          decision: "APPROVE",
          reason_code: ReasonCode.OK,
          proof: proved.proof,
          public_signals: proved.publicSignals,
          proof_tx: fin.txHash ?? input.proof_tx,
        });
      }
      if (fin.kind === "disabled") {
        log("kurier_disabled_practice_mode", { task_id: taskId });
        return finish(200, {
          decision: "APPROVE",
          reason_code: ReasonCode.OK,
          proof: proved.proof,
          public_signals: proved.publicSignals,
          proof_tx: input.proof_tx,
        });
      }
      log("kurier_not_finalized", { task_id: taskId, kind: fin.kind });
      return reject(
        fin.kind === "timeout" ? ReasonCode.FINALIZATION_TIMEOUT : ReasonCode.KURIER_ERROR,
        input.proof_tx
      );
    }

    // REJECT with proof: give Kurier a short, bounded chance to finalize so
    // proof_tx can carry our own finalized reference; otherwise echo the task's.
    const rejectWait = Math.min(config.rejectKurierWaitMs, kurierBudget);
    let proofTx = input.proof_tx;
    if (rejectWait > 0 && config.kurierApiKey) {
      const fin = await submitAndWaitFinalized(proved.proof, proved.publicSignals, rejectWait);
      if (fin.kind === "finalized" && fin.txHash) proofTx = fin.txHash;
    }
    return finish(200, {
      decision: "REJECT",
      reason_code: outcome.reasonCode,
      proof: proved.proof,
      public_signals: proved.publicSignals,
      proof_tx: proofTx,
    });
  } catch (e) {
    log("task_internal_error", {
      task_id: taskId ?? null,
      error: e instanceof Error ? e.message.slice(0, 200) : String(e),
    });
    return reject(ReasonCode.INTERNAL_ERROR);
  }
}
