/** Wire types, taken verbatim from https://agentgames.zkverify.io/build (§02). */

export const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
export const PREFLIGHT_TYPE = "agent-games.preflight.v1";
export const PROTOCOL_VERSION = "v1";

export interface TaskInput {
  registered_vk: string;
  proof_vk: string;
  minimum: string;
  public_balance: string;
  expiry_block: number;
  current_block: number;
  recipient: string;
  condition_recipient: string;
  amount: string;
  max_transfer: string;
  proof_tx: string;
}

export interface TaskEnvelope {
  type: typeof TASK_TYPE;
  task_id: string;
  mode?: string;
  issued_at: string;
  deadline_at: string;
  input: TaskInput;
}

export interface PreflightEnvelope {
  type: typeof PREFLIGHT_TYPE;
  agent_id?: string;
  issued_at?: string;
  nonce?: string;
}

export type Decision = "APPROVE" | "REJECT";

/**
 * Reason codes. Only VK_SUBSTITUTION is named in the /build spec (it is the
 * documented example); the rest follow the same SCREAMING_SNAKE convention
 * and map one-to-one onto the /build Security checklist. The scored field is
 * `decision`; reason_code classifies the outcome for the platform and for
 * dispute logs.
 */
export const ReasonCode = {
  OK: "OK",
  VK_SUBSTITUTION: "VK_SUBSTITUTION",
  BELOW_MINIMUM: "BELOW_MINIMUM",
  RECIPIENT_MISMATCH: "RECIPIENT_MISMATCH",
  AMOUNT_EXCEEDS_MAX: "AMOUNT_EXCEEDS_MAX",
  EXPIRED: "EXPIRED",
  PROOF_REUSED: "PROOF_REUSED",
  TASK_EXPIRED: "TASK_EXPIRED",
  INVALID_TIMESTAMP: "INVALID_TIMESTAMP",
  MALFORMED_INPUT: "MALFORMED_INPUT",
  PROOF_GENERATION_FAILED: "PROOF_GENERATION_FAILED",
  FINALIZATION_TIMEOUT: "FINALIZATION_TIMEOUT",
  KURIER_ERROR: "KURIER_ERROR",
  TIMEOUT: "TIMEOUT",
  INTERNAL_ERROR: "INTERNAL_ERROR",
} as const;
export type ReasonCode = (typeof ReasonCode)[keyof typeof ReasonCode];

/** snarkjs Groth16 proof object (pi_a / pi_b / pi_c as decimal strings). */
export interface Groth16Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
}

export interface TaskResponseBody {
  decision: Decision;
  reason_code: ReasonCode;
  /** Present when a proof of the decision was generated (and locally verified). */
  proof?: Groth16Proof;
  /** The proof's public signals, decimal strings, in circuit order. */
  public_signals?: string[];
  /**
   * On-chain audit pointer: the txHash of this agent's own proof once its
   * Kurier job reaches Finalized; otherwise the task's input proof_tx echoed.
   */
  proof_tx?: string;
}
