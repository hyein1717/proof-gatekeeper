import { randomBytes } from "node:crypto";
import { config } from "./config.js";
import { keccak256Hex } from "./keccak.js";
import type { TaskInput } from "./types.js";

/** BN254 (bn128) scalar field prime. snarkjs reduces inputs mod p. */
export const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const HEX_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const HEX_HASH_RE = /^0x[0-9a-fA-F]{64}$/;
const DECIMAL_RE = /^(0|[1-9][0-9]*)$/;

export function isHashHex(v: unknown): v is string {
  return typeof v === "string" && HEX_HASH_RE.test(v);
}
export function isAddressHex(v: unknown): v is string {
  return typeof v === "string" && HEX_ADDRESS_RE.test(v);
}
export function isDecimalString(v: unknown): v is string {
  return typeof v === "string" && DECIMAL_RE.test(v) && BigInt(v) < FIELD_PRIME;
}
export function isBlockNumber(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}

/** Structural validation of the task input — anything off is fail-closed. */
export function validateTaskInput(input: unknown): input is TaskInput {
  if (typeof input !== "object" || input === null) return false;
  const i = input as Record<string, unknown>;
  return (
    isHashHex(i.registered_vk) &&
    isHashHex(i.proof_vk) &&
    isDecimalString(i.minimum) &&
    isDecimalString(i.public_balance) &&
    isBlockNumber(i.expiry_block) &&
    isBlockNumber(i.current_block) &&
    isAddressHex(i.recipient) &&
    isAddressHex(i.condition_recipient) &&
    isDecimalString(i.amount) &&
    isDecimalString(i.max_transfer) &&
    typeof i.proof_tx === "string" &&
    i.proof_tx.length > 0
  );
}

/**
 * Encodes the envelope's string task_id into the circuit's `taskId` field
 * element. The /build spec does not publish this encoding, so it is
 * configurable (TASK_ID_ENCODING) and must be validated against the
 * platform's unscored practice tasks before a scored round:
 *  - "keccak":  keccak256(utf8(task_id)) mod p (default)
 *  - "numeric": task_id parsed as a decimal integer
 *  - "hex":     task_id (or its trailing hex segment) parsed as hex
 * Unparseable values fall back to "keccak" rather than failing the task.
 */
export function encodeTaskId(taskId: string): string {
  try {
    if (config.taskIdEncoding === "numeric" && DECIMAL_RE.test(taskId)) {
      return (BigInt(taskId) % FIELD_PRIME).toString();
    }
    if (config.taskIdEncoding === "hex") {
      const m = taskId.match(/(?:0x)?([0-9a-fA-F]{4,})$/);
      if (m) return (BigInt("0x" + m[1]) % FIELD_PRIME).toString();
    }
  } catch {
    // fall through to keccak
  }
  return (BigInt(keccak256Hex(taskId)) % FIELD_PRIME).toString();
}

/** A fresh random field element for the circuit's private `salt` input. */
export function randomSalt(): string {
  return BigInt("0x" + randomBytes(31).toString("hex")).toString();
}

export interface CircuitInput {
  registeredVkHash: string;
  proofVkHash: string;
  minimum: string;
  publicBalance: string;
  expiryBlock: string;
  currentBlock: string;
  recipient: string;
  conditionRecipient: string;
  amount: string;
  maxTransfer: string;
  decision: string;
  taskId: string;
  salt: string;
  [key: string]: string;
}

/**
 * Builds the gatekeeper circuit witness input from the task envelope.
 * Signal names/order were verified empirically against the official
 * artifacts (see scripts/probe-circuit.mjs):
 *   inputs:  registeredVkHash, proofVkHash, minimum, publicBalance,
 *            expiryBlock, currentBlock, recipient, conditionRecipient,
 *            amount, maxTransfer, decision, taskId, salt (private)
 *   outputs/public signals: [commitment, registeredVkHash, proofVkHash,
 *            minimum, publicBalance, expiryBlock, currentBlock, recipient,
 *            conditionRecipient, amount, maxTransfer, decision, taskId]
 * The circuit enforces decision == 1 ⟺ every check passes, so a wrong
 * decision cannot even produce a witness.
 */
export function buildCircuitInput(input: TaskInput, taskId: string, decision: 0 | 1): CircuitInput {
  return {
    registeredVkHash: input.registered_vk,
    proofVkHash: input.proof_vk,
    minimum: input.minimum,
    publicBalance: input.public_balance,
    expiryBlock: String(input.expiry_block),
    currentBlock: String(input.current_block),
    recipient: input.recipient,
    conditionRecipient: input.condition_recipient,
    amount: input.amount,
    maxTransfer: input.max_transfer,
    decision: String(decision),
    taskId: encodeTaskId(taskId),
    salt: randomSalt(),
  };
}
