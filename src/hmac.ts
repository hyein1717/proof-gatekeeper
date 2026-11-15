import { createHmac, timingSafeEqual } from "node:crypto";
import { config } from "./config.js";

export const SIGNATURE_HEADER = "x-agent-games-signature";

/**
 * HMAC over the RAW body bytes. The /build spec mandates verifying the
 * inbound signature against the raw request body BEFORE any JSON parsing,
 * and signing every response over its raw body the same way. The digest is
 * HMAC-SHA256, hex-encoded (an optional "sha256=" prefix is accepted
 * inbound; the outbound format is configurable — see SIGNATURE_FORMAT).
 * The secret itself is never logged or returned anywhere.
 */
export function computeSignature(rawBody: Buffer | string, secret: string): string {
  return createHmac("sha256", secret).update(rawBody).digest("hex");
}

export function formatSignature(hexDigest: string): string {
  return config.signatureFormat === "sha256-hex" ? `sha256=${hexDigest}` : hexDigest;
}

export function signBody(rawBody: string): string {
  return formatSignature(computeSignature(rawBody, config.hmacSecret));
}

/** Constant-time verification of an inbound signature header value. */
export function verifySignature(rawBody: Buffer, headerValue: string | undefined): boolean {
  if (!headerValue) return false;
  const presented = headerValue.trim().toLowerCase().replace(/^sha256=/, "");
  if (!/^[0-9a-f]{64}$/.test(presented)) return false;
  const expected = computeSignature(rawBody, config.hmacSecret);
  const a = Buffer.from(presented, "hex");
  const b = Buffer.from(expected, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}
