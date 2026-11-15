import fs from "node:fs";
import path from "node:path";
import { config } from "./config.js";

export interface CachedResponse {
  status: number;
  body: string;
  signature: string;
  storedAt: string;
}

interface StoreData {
  /** proof_tx references presented by tasks → when first seen (replay guard). */
  seenProofRefs: Record<string, { taskId: string; firstSeenAt: string }>;
  /** task_id → the exact response already sent (idempotent retries). */
  taskResponses: Record<string, CachedResponse>;
}

/**
 * Durable record of proof references and task responses (deploy checklist:
 * "Proof and transaction references are retained for disputes"). Backed by a
 * single JSON file with atomic replace; single-instance by design — swap for
 * Redis/Postgres before running multiple replicas.
 */
export class Store {
  private data: StoreData = { seenProofRefs: {}, taskResponses: {} };
  private writeChain: Promise<void> = Promise.resolve();

  constructor(private readonly filePath: string = config.storePath) {
    try {
      const raw = fs.readFileSync(filePath, "utf8");
      const parsed = JSON.parse(raw) as Partial<StoreData>;
      this.data.seenProofRefs = parsed.seenProofRefs ?? {};
      this.data.taskResponses = parsed.taskResponses ?? {};
    } catch {
      // Missing or unreadable store → start empty. A corrupt store must not
      // take the agent down; replay protection degrades to in-memory only.
    }
  }

  hasSeenProofRef(proofTx: string): boolean {
    return Object.prototype.hasOwnProperty.call(this.data.seenProofRefs, proofTx.toLowerCase());
  }

  /** Records a proof reference. Returns false if it was already present. */
  markProofRefSeen(proofTx: string, taskId: string): boolean {
    const key = proofTx.toLowerCase();
    if (this.data.seenProofRefs[key]) return false;
    this.data.seenProofRefs[key] = { taskId, firstSeenAt: new Date().toISOString() };
    this.persist();
    return true;
  }

  getTaskResponse(taskId: string): CachedResponse | undefined {
    return this.data.taskResponses[taskId];
  }

  /** First response wins: an idempotent retry must return the original bytes. */
  saveTaskResponse(taskId: string, response: CachedResponse): void {
    if (this.data.taskResponses[taskId]) return;
    this.data.taskResponses[taskId] = response;
    this.persist();
  }

  private persist(): void {
    const snapshot = JSON.stringify(this.data, null, 2);
    const filePath = this.filePath;
    this.writeChain = this.writeChain.then(async () => {
      await fs.promises.mkdir(path.dirname(filePath), { recursive: true });
      const tmp = `${filePath}.tmp`;
      await fs.promises.writeFile(tmp, snapshot, "utf8");
      await fs.promises.rename(tmp, filePath);
    }).catch(() => {
      // Persistence failure must never break request handling.
    });
  }
}
