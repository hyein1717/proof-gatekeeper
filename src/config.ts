import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** Project root: the nearest ancestor directory containing package.json
 *  (works from src/, dist/src/, and dist/test/ alike). */
function findRoot(): string {
  let dir = path.dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 5; i++) {
    if (fs.existsSync(path.join(dir, "package.json"))) return dir;
    dir = path.dirname(dir);
  }
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}
export const ROOT = findRoot();

/**
 * Minimal .env loader (KEY=VALUE lines, # comments). Real environment
 * variables always win over file values. Secrets are read from the
 * environment ONLY — never hardcoded, never logged.
 */
function loadDotEnv(): void {
  const envPath = path.join(ROOT, ".env");
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, "utf8").split("\n")) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/i);
    if (!m) continue;
    const key = m[1];
    let value = m[2];
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

function str(name: string, fallback?: string): string | undefined {
  const v = process.env[name];
  return v === undefined || v === "" ? fallback : v;
}

function int(name: string, fallback: number): number {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) throw new Error(`Invalid ${name}: must be a positive number`);
  return n;
}

function bool(name: string, fallback: boolean): boolean {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  return v.toLowerCase() === "true" || v === "1";
}

loadDotEnv();

const hmacSecret = str("AGENT_GAMES_HMAC_SECRET");
if (!hmacSecret) {
  // Fail fast: a missing/placeholder secret fails preflight anyway, and
  // running without one would silently reject (or worse, mis-sign) tasks.
  throw new Error(
    "AGENT_GAMES_HMAC_SECRET is not set. Copy the platform-generated value from the dashboard (Rotate Secret) into .env — never a local placeholder."
  );
}

const signatureFormat = str("SIGNATURE_FORMAT", "hex");
if (signatureFormat !== "hex" && signatureFormat !== "sha256-hex") {
  throw new Error(`Invalid SIGNATURE_FORMAT: ${signatureFormat} (expected "hex" or "sha256-hex")`);
}

const taskIdEncoding = str("TASK_ID_ENCODING", "keccak");
if (taskIdEncoding !== "keccak" && taskIdEncoding !== "numeric" && taskIdEncoding !== "hex") {
  throw new Error(`Invalid TASK_ID_ENCODING: ${taskIdEncoding} (expected "keccak", "numeric" or "hex")`);
}

export const config = {
  hmacSecret,
  port: int("PORT", 8080),
  agentPath: str("AGENT_PATH", "/agent")!,
  kurierApiKey: str("KURIER_API_KEY"),
  kurierApiUrl: str("KURIER_API_URL", "https://api.kurier.xyz/api/v1")!.replace(/\/$/, ""),
  /** Registered gatekeeper VK hash, from https://agentgames.zkverify.io/api/circuit-info */
  gatekeeperVkHash: str(
    "GATEKEEPER_VK_HASH",
    "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"
  )!.toLowerCase(),
  responseBudgetMs: int("RESPONSE_BUDGET_MS", 55_000),
  kurierRequiredForApprove: bool("KURIER_REQUIRED_FOR_APPROVE", true),
  kurierPollIntervalMs: int("KURIER_POLL_INTERVAL_MS", 2_000),
  rejectKurierWaitMs: int("REJECT_KURIER_WAIT_MS", 5_000),
  signatureFormat: signatureFormat as "hex" | "sha256-hex",
  taskIdEncoding: taskIdEncoding as "keccak" | "numeric" | "hex",
  tlsCertFile: str("TLS_CERT_FILE"),
  tlsKeyFile: str("TLS_KEY_FILE"),
  storePath: path.resolve(ROOT, str("STORE_PATH", "data/store.json")!),
  wasmPath: path.join(ROOT, "circuits", "gatekeeper.wasm"),
  zkeyPath: path.join(ROOT, "circuits", "gatekeeper_final.zkey"),
  vkPath: path.join(ROOT, "circuits", "vk.json"),
} as const;

export type Config = typeof config;
