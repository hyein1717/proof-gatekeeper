import fs from "node:fs";
import * as snarkjs from "snarkjs";
import { config } from "./config.js";
import type { CircuitInput } from "./circuit.js";
import type { Groth16Proof } from "./types.js";

export interface ProveResult {
  proof: Groth16Proof;
  publicSignals: string[];
}

let cachedVk: unknown;

/** The verification key extracted from gatekeeper_final.zkey (circuits/vk.json). */
function loadVk(): unknown {
  if (cachedVk === undefined) {
    cachedVk = JSON.parse(fs.readFileSync(config.vkPath, "utf8"));
  }
  return cachedVk;
}

/**
 * Generates a Groth16 proof of the decision with snarkjs, using the official
 * gatekeeper.wasm / gatekeeper_final.zkey, then re-verifies it locally
 * against the extracted VK before it leaves the process — a proof that does
 * not verify is never sent (an invalid proof costs points and trust).
 *
 * Throws when the witness is unsatisfiable, i.e. when the requested decision
 * contradicts the circuit's enforced predicate. Callers treat that as
 * fail-closed evidence, never as something to retry with a flipped decision
 * the engine did not make.
 */
export async function proveDecision(circuitInput: CircuitInput): Promise<ProveResult> {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    config.wasmPath,
    config.zkeyPath
  );
  const ok = await snarkjs.groth16.verify(loadVk(), publicSignals, proof);
  if (!ok) {
    throw new Error("local verification of freshly generated proof failed");
  }
  return { proof: proof as Groth16Proof, publicSignals };
}
