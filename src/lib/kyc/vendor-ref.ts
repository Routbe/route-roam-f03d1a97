/**
 * Opaque Didit vendor_data: "rk1." + base64url(nonce 24 | XChaCha20-Poly1305(member id 16 | state 24)).
 * Didit never learns the ROUT member id, and a webhook can name the member only with a reference
 * this server sealed. The key is HKDF-SHA256(pepper (IDENTITY_HASH_PEPPER or PEPPER_SECRET), info "rout.kyc.vendor.v1");
 * the AAD binds the version. The state is still checked single-use against
 * identity_verification_sessions inside the member's own RLS context.
 */
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

const PREFIX = "rk1.";
const INFO = new TextEncoder().encode("rout.kyc.vendor.v1");
const AAD = new TextEncoder().encode("rout.kyc.vendor.v1|member|state");
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const STATE_RE = /^[0-9a-f]{48}$/;

function key(secret: string): Uint8Array {
  if (!secret || secret.length < 32) throw new Error("kyc_not_configured");
  return hkdf(sha256, new TextEncoder().encode(secret), undefined, INFO, 32);
}

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function bytesToHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}
function b64url(b: Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}

export function sealVendorRef(userId: string, state: string, secret: string): string {
  const id = userId.toLowerCase();
  if (!UUID_RE.test(id) || !STATE_RE.test(state)) throw new Error("kyc_invalid_ref");
  const k = key(secret);
  const pt = new Uint8Array(40);
  try {
    pt.set(hexToBytes(id.replace(/-/g, "")), 0);
    pt.set(hexToBytes(state), 16);
    const nonce = crypto.getRandomValues(new Uint8Array(24));
    const ct = xchacha20poly1305(k, nonce, AAD).encrypt(pt);
    const out = new Uint8Array(24 + ct.length);
    out.set(nonce, 0);
    out.set(ct, 24);
    return PREFIX + b64url(out);
  } finally {
    k.fill(0);
    pt.fill(0);
  }
}

/** Member id and state, or null for anything this server did not seal. Never throws on input. */
export function openVendorRef(ref: unknown, secret: string): { userId: string; state: string } | null {
  if (typeof ref !== "string" || !ref.startsWith(PREFIX) || ref.length > 200) return null;
  let raw: Uint8Array;
  try {
    raw = new Uint8Array(Buffer.from(ref.slice(PREFIX.length), "base64url"));
  } catch {
    return null;
  }
  if (raw.length !== 24 + 40 + 16) return null;
  const k = key(secret);
  let pt: Uint8Array | null = null;
  try {
    pt = xchacha20poly1305(k, raw.subarray(0, 24), AAD).decrypt(raw.subarray(24));
    const h = bytesToHex(pt.subarray(0, 16));
    const userId = `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
    return { userId, state: bytesToHex(pt.subarray(16)) };
  } catch {
    return null;
  } finally {
    k.fill(0);
    pt?.fill(0);
    raw.fill(0);
  }
}
