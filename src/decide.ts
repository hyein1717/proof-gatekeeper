import { config } from "./config.js";
import { ReasonCode, type TaskEnvelope } from "./types.js";

export interface DecisionOutcome {
  approve: boolean;
  reasonCode: ReasonCode;
  /**
   * True when the rejection is a proof-reference replay: the response
   * carries the decision alone, with no new proof (a reused reference is
   * excluded from the reliability bonus, and re-proving it would only
   * re-bless the same statement).
   */
  skipProof?: boolean;
}

/**
 * The deterministic decision engine — the ONLY place a decision is made.
 * No language model is involved. It mirrors, in the /build Security
 * checklist's own order, the predicate the gatekeeper circuit enforces
 * (verified empirically, scripts/probe-circuit.mjs):
 *
 *   APPROVE ⟺ proof_vk == registered_vk == the competition's registered VK
 *             ∧ public_balance >= minimum            (inclusive)
 *             ∧ recipient == condition_recipient
 *             ∧ amount <= max_transfer               (inclusive)
 *             ∧ current_block <  expiry_block        (STRICT — equality is expired)
 *             ∧ proof_tx not seen before             (replay guard)
 *
 * Anything uncertain fails closed to REJECT.
 */
export function decideTask(
  envelope: TaskEnvelope,
  proofRefAlreadySeen: boolean
): DecisionOutcome {
  const input = envelope.input;

  // Checklist: "The verification key matches the key registered for this
  // condition." The circuit only enforces proofVkHash == registeredVkHash,
  // so the registered key itself must ALSO be pinned to the competition's
  // registered VK hash — otherwise an equal-but-wrong VK pair would prove.
  const registeredVk = input.registered_vk.toLowerCase();
  const proofVk = input.proof_vk.toLowerCase();
  if (registeredVk !== config.gatekeeperVkHash || proofVk !== registeredVk) {
    return { approve: false, reasonCode: ReasonCode.VK_SUBSTITUTION };
  }

  // Checklist: "The proof reference has not already been used for another task."
  if (proofRefAlreadySeen) {
    return { approve: false, reasonCode: ReasonCode.PROOF_REUSED, skipProof: true };
  }

  // Checklist: "Public inputs prove the required threshold, recipient, and action."
  if (BigInt(input.public_balance) < BigInt(input.minimum)) {
    return { approve: false, reasonCode: ReasonCode.BELOW_MINIMUM };
  }
  if (input.recipient.toLowerCase() !== input.condition_recipient.toLowerCase()) {
    return { approve: false, reasonCode: ReasonCode.RECIPIENT_MISMATCH };
  }
  if (BigInt(input.amount) > BigInt(input.max_transfer)) {
    return { approve: false, reasonCode: ReasonCode.AMOUNT_EXCEEDS_MAX };
  }

  // Checklist: "The verification reached a finalized state before approval" —
  // the in-envelope finality window: the condition must not have expired.
  // The circuit treats current_block == expiry_block as expired (strict <).
  if (input.current_block >= input.expiry_block) {
    return { approve: false, reasonCode: ReasonCode.EXPIRED };
  }

  return { approve: true, reasonCode: ReasonCode.OK };
}
