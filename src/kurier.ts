import { config } from "./config.js";
import type { Groth16Proof } from "./types.js";

/**
 * Kurier (zkVerify) REST client, per https://agentgames.zkverify.io/build §03
 * and the official Kurier guide:
 *   POST {base}/submit-proof/{apiKey}  → { jobId, optimisticVerify }
 *   GET  {base}/job-status/{apiKey}/{jobId}
 *        → { status: Queued|Valid|Submitted|IncludedInBlock|Finalized|Failed,
 *            txHash, blockHash, ... }
 * The API key travels in the URL path (Kurier's design); it is never logged.
 */

export type FinalizationOutcome =
  | { kind: "finalized"; txHash?: string; jobId: string }
  | { kind: "failed"; jobId?: string; detail: string }
  | { kind: "timeout"; jobId?: string }
  | { kind: "disabled" };

interface SubmitResponse {
  jobId?: string;
  optimisticVerify?: string;
}

interface JobStatusResponse {
  status?: string;
  txHash?: string;
}

async function fetchJson(url: string, init: RequestInit, timeoutMs: number): Promise<any> {
  const res = await fetch(url, { ...init, signal: AbortSignal.timeout(Math.max(1, timeoutMs)) });
  const text = await res.text();
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`Kurier returned non-JSON (HTTP ${res.status})`);
  }
  if (!res.ok) {
    throw new Error(`Kurier HTTP ${res.status}: ${json?.message ?? json?.error ?? "request failed"}`);
  }
  return json;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Submits a proof for the gatekeeper circuit's registered VK hash and polls
 * until the job reaches Finalized or the budget runs out. Never throws —
 * every failure is reported as an outcome so the caller can fail closed.
 */
export async function submitAndWaitFinalized(
  proof: Groth16Proof,
  publicSignals: string[],
  budgetMs: number
): Promise<FinalizationOutcome> {
  if (!config.kurierApiKey) return { kind: "disabled" };
  const deadline = Date.now() + budgetMs;
  const remaining = () => deadline - Date.now();

  let jobId: string | undefined;
  try {
    const submit = (await fetchJson(
      `${config.kurierApiUrl}/submit-proof/${config.kurierApiKey}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          proofType: "groth16",
          vkRegistered: true,
          proofOptions: { library: "snarkjs", curve: "bn128" },
          proofData: { proof, publicSignals, vk: config.gatekeeperVkHash },
        }),
      },
      Math.min(remaining(), 15_000)
    )) as SubmitResponse;

    jobId = submit.jobId;
    if (!jobId) return { kind: "failed", detail: "Kurier response carried no jobId" };
    if (submit.optimisticVerify !== "success") {
      return { kind: "failed", jobId, detail: `optimisticVerify=${submit.optimisticVerify ?? "missing"}` };
    }
  } catch (e) {
    return { kind: "failed", jobId, detail: e instanceof Error ? e.message : String(e) };
  }

  while (remaining() > 0) {
    try {
      const status = (await fetchJson(
        `${config.kurierApiUrl}/job-status/${config.kurierApiKey}/${jobId}`,
        { method: "GET" },
        Math.min(remaining(), 10_000)
      )) as JobStatusResponse;
      if (status.status === "Finalized") {
        return { kind: "finalized", txHash: status.txHash, jobId };
      }
      if (status.status === "Failed") {
        return { kind: "failed", jobId, detail: "Kurier job status=Failed" };
      }
    } catch {
      // Transient poll errors are tolerated until the budget expires.
    }
    if (remaining() <= 0) break;
    await sleep(Math.min(config.kurierPollIntervalMs, remaining()));
  }
  return { kind: "timeout", jobId };
}
