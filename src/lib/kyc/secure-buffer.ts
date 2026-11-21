/**
 * Node.js Buffer helpers for transient identity material (server-only).
 *
 * Sensitive bytes live in Buffer objects allocated with Buffer.alloc (never the shared pool of
 * Buffer.allocUnsafe / small Buffer.from(string)), so fill(0) overwrites the only copy this code
 * made. Limit, stated plainly: JSON.parse and every string operation create V8 strings, which
 * JavaScript cannot overwrite; those are dropped right after reading instead.
 */
import { Buffer } from "node:buffer";

/** UTF-8 bytes of `text` in a freshly allocated, unpooled Buffer. */
export function secretBuffer(text: string): Buffer {
  const out = Buffer.alloc(Buffer.byteLength(text, "utf8"));
  out.write(text, 0, "utf8");
  return out;
}

/** Copies `bytes` into a freshly allocated, unpooled Buffer. */
export function copyToBuffer(bytes: Uint8Array): Buffer {
  const out = Buffer.alloc(bytes.byteLength);
  out.set(bytes);
  return out;
}

/** Zero-fills every given buffer; null/undefined entries are skipped. */
export function wipe(...buffers: (Uint8Array | null | undefined)[]): void {
  for (const b of buffers) b?.fill(0);
}

/** True when every byte is zero (used by tests and the post-hash assertion). */
export function isWiped(b: Uint8Array): boolean {
  for (const x of b) if (x !== 0) return false;
  return true;
}
