/**
 * universal_nullifier = BLAKE3( Poseidon256(canonical_id) || PEPPER_SECRET )
 *
 * Poseidon256 is the fixed 32-byte digest of poseidon.ts, so the concatenation is unambiguous and
 * BLAKE3 (no length extension) acts as a keyed PRF over it. The pepper is server-only
 * (IDENTITY_HASH_PEPPER or PEPPER_SECRET, see pepper.server.ts); without it a nullifier cannot be recomputed from a guessed document number.
 * The same document gives the same nullifier through every provider, which is what lets the
 * database refuse a second account across providers.
 */
import { blake3 } from "@noble/hashes/blake3.js";
import { Buffer } from "node:buffer";
import { poseidon256 } from "./poseidon";
import { secretBuffer, wipe } from "./secure-buffer";

export const MIN_PEPPER_LENGTH = 32;

export class NullifierError extends Error {
  constructor(readonly code: "pepper_missing" | "pepper_too_short") {
    super(code);
    this.name = "NullifierError";
  }
}

function hex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/** 64 lower-case hex characters. Every intermediate buffer is zero-filled before returning. */
export function universalNullifier(canonical: Uint8Array, pepper: string): string {
  if (!pepper) throw new NullifierError("pepper_missing");
  if (pepper.length < MIN_PEPPER_LENGTH) throw new NullifierError("pepper_too_short");
  const p = poseidon256(canonical);
  const k = secretBuffer(pepper);
  const msg = Buffer.alloc(p.length + k.length);
  let digest: Uint8Array | null = null;
  try {
    msg.set(p, 0);
    msg.set(k, p.length);
    // A plain Uint8Array view over the same memory: hash libraries check the exact class, and the
    // view shares the Buffer's bytes, so wiping msg wipes what was hashed.
    digest = blake3(new Uint8Array(msg.buffer, msg.byteOffset, msg.byteLength));
    return hex(digest);
  } finally {
    wipe(p, k, msg, digest);
  }
}

/** Format check used before any database call. */
export function isNullifier(v: unknown): v is string {
  return typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
}
