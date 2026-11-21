/**
 * Didit webhook authentication (v3 destinations): X-Signature = hex HMAC-SHA256 of the exact raw
 * body bytes under DIDIT_WEBHOOK_SECRET, X-Timestamp = Unix seconds of dispatch. During a secret
 * rotation Didit also sends X-Signature-Previous (made with the replaced secret); a match on either
 * is accepted. Comparison is constant time (node:crypto timingSafeEqual on equal-length buffers);
 * the length check reveals only that a header is not a 32-byte hex digest.
 */
import { createHmac, timingSafeEqual } from "node:crypto";

export const MAX_SKEW_SECONDS = 300;

export type SignatureCheck = { ok: true } | { ok: false; reason: "no_secret" | "no_timestamp" | "stale" | "no_signature" | "bad_signature" };

function digestOf(secret: string, raw: Uint8Array): Buffer {
  return createHmac("sha256", secret).update(raw).digest();
}

function parseHex(header: string | null): Buffer | null {
  const v = (header ?? "").trim().toLowerCase();
  return /^[0-9a-f]{64}$/.test(v) ? Buffer.from(v, "hex") : null;
}

/** Constant-time equality of two digests; false for any length mismatch. */
export function digestsEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length || a.length === 0) return false;
  return timingSafeEqual(a, b);
}

export function verifyDiditSignature(input: {
  raw: Uint8Array;
  secret: string | undefined;
  signature: string | null;
  previousSignature?: string | null;
  timestamp: string | null;
  nowSeconds?: number;
}): SignatureCheck {
  if (!input.secret) return { ok: false, reason: "no_secret" };
  const ts = Number(input.timestamp ?? "");
  if (!Number.isInteger(ts) || ts <= 0) return { ok: false, reason: "no_timestamp" };
  const now = input.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (Math.abs(now - ts) > MAX_SKEW_SECONDS) return { ok: false, reason: "stale" };
  const candidates = [parseHex(input.signature), parseHex(input.previousSignature ?? null)].filter((x): x is Buffer => x !== null);
  if (!candidates.length) return { ok: false, reason: "no_signature" };
  const expected = digestOf(input.secret, input.raw);
  try {
    // Evaluate every candidate (no early exit) so timing does not reveal which header matched.
    let match = false;
    for (const c of candidates) match = digestsEqual(c, expected) || match;
    return match ? { ok: true } : { ok: false, reason: "bad_signature" };
  } finally {
    expected.fill(0);
  }
}
