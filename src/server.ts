import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import { config } from "./config.js";
import { handlePreflight, handleTask, makeResponse, type SignedResponse } from "./handler.js";
import { SIGNATURE_HEADER, verifySignature } from "./hmac.js";
import { Store } from "./store.js";
import { PREFLIGHT_TYPE, ReasonCode, TASK_TYPE } from "./types.js";

const MAX_BODY_BYTES = 256 * 1024;
const store = new Store();

function send(res: http.ServerResponse, out: SignedResponse & { signed?: boolean }): void {
  if (res.writableEnded) return;
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (out.signed !== false) headers[SIGNATURE_HEADER] = out.signature;
  res.writeHead(out.status, headers);
  res.end(out.body);
}

function sendPlain(res: http.ServerResponse, status: number, bodyObj: unknown): void {
  if (res.writableEnded) return;
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(bodyObj));
}

function readRawBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error("body_too_large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function onRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  const startedAt = Date.now();
  const url = new URL(req.url ?? "/", "http://localhost");

  if (req.method === "GET" && url.pathname === "/healthz") {
    sendPlain(res, 200, { ok: true });
    return;
  }
  if (req.method !== "POST" || url.pathname !== config.agentPath) {
    sendPlain(res, 404, { error: "not_found" });
    return;
  }

  let raw: Buffer;
  try {
    raw = await readRawBody(req);
  } catch {
    sendPlain(res, 413, { error: "body_too_large" });
    return;
  }

  // HMAC over the RAW body, verified BEFORE parsing (spec §02/§04).
  // An unauthenticated request gets a bare 401 — no signed content, no work.
  if (!verifySignature(raw, req.headers[SIGNATURE_HEADER] as string | undefined)) {
    sendPlain(res, 401, { error: "invalid_signature" });
    return;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch {
    send(res, makeResponse(400, { error: "invalid_json" }));
    return;
  }

  const type = (parsed as { type?: unknown })?.type;
  if (type === PREFLIGHT_TYPE) {
    send(res, handlePreflight());
    return;
  }
  if (type !== TASK_TYPE) {
    send(res, makeResponse(400, { error: "unknown_type" }));
    return;
  }

  // Hard-deadline watchdog: the pipeline is budget-aware internally, but if
  // anything ever overruns, fail closed with a signed REJECT instead of
  // letting the platform hit its 60s timeout (-2) with no response at all.
  const taskId = (parsed as { task_id?: unknown }).task_id;
  let settled = false;
  const watchdog = setTimeout(() => {
    if (settled) return;
    settled = true;
    const out = makeResponse(200, {
      decision: "REJECT",
      reason_code: ReasonCode.TIMEOUT,
    });
    if (typeof taskId === "string") {
      store.saveTaskResponse(taskId, {
        status: out.status,
        body: out.body,
        signature: out.signature,
        storedAt: new Date().toISOString(),
      });
    }
    console.log(JSON.stringify({ ts: new Date().toISOString(), event: "watchdog_timeout", task_id: taskId ?? null }));
    send(res, out);
  }, config.responseBudgetMs + 1_000);

  try {
    const out = await handleTask(parsed, store, startedAt);
    if (!settled) {
      settled = true;
      clearTimeout(watchdog);
      send(res, out);
    }
  } catch {
    if (!settled) {
      settled = true;
      clearTimeout(watchdog);
      send(res, makeResponse(200, { decision: "REJECT", reason_code: ReasonCode.INTERNAL_ERROR }));
    }
  }
}

const server =
  config.tlsCertFile && config.tlsKeyFile
    ? https.createServer(
        { cert: fs.readFileSync(config.tlsCertFile), key: fs.readFileSync(config.tlsKeyFile) },
        onRequest
      )
    : http.createServer(onRequest);

server.listen(config.port, () => {
  console.log(
    JSON.stringify({
      ts: new Date().toISOString(),
      event: "listening",
      port: config.port,
      path: config.agentPath,
      tls: Boolean(config.tlsCertFile),
      kurier: config.kurierApiKey ? "configured" : "disabled (practice mode)",
    })
  );
});
