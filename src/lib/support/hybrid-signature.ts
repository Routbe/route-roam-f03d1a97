/**
 * Hybrid signatures for the treasury: Ed25519 ‖ ML-DSA-65 (NIST FIPS 204) over the same
 * domain-separated message. A signature counts only when every present component verifies;
 * callers that demand post-quantum strength pass requirePq. Used by the server signer, the
 * crypto worker (support.verify_*) and tests; nothing here touches a secret key.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

export const TREASURY_ROOT_DOMAIN = "rout.treasury.root.v1";
export const RECEIPT_DOMAIN = "rout.support.receipt.v1";
export const PARTNER_DOMAIN = "rout.partner.attestation.v1";
export const ML_DSA65_PUBLIC_KEY_BYTES = 1952;
export const ML_DSA65_SIGNATURE_BYTES = 3309;

const enc = new TextEncoder();

export type HybridPublicKey = { kid: string; ed25519: string; mldsa65: string | null };
export type HybridSignature = { kid: string; ed25519: string; mldsa65: string | null };

export function b64uEncode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function b64uDecode(text: string): Uint8Array {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) throw new RangeError("b64u_invalid");
  const pad = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
  const bin = atob(pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** One message per purpose; the domain line keeps a signature from being replayed elsewhere. */
export function domainMessage(domain: string, lines: readonly string[]): Uint8Array {
  for (const l of lines) if (l.includes("\n")) throw new RangeError("line_break");
  return enc.encode([domain, ...lines].join("\n"));
}

export const treasuryRootMessage = (size: string, rootHex: string) => domainMessage(TREASURY_ROOT_DOMAIN, [size, rootHex]);

export function verifyHybridBytes(
  message: Uint8Array,
  sig: { ed25519: Uint8Array; mldsa65: Uint8Array | null },
  pk: { ed25519: Uint8Array; mldsa65: Uint8Array | null },
  opts: { requirePq?: boolean } = {},
): { valid: boolean; pq: boolean } {
  try {
    if (sig.ed25519.length !== 64 || pk.ed25519.length !== 32) return { valid: false, pq: false };
    if (!ed25519.verify(sig.ed25519, message, pk.ed25519)) return { valid: false, pq: false };
    const hasPq = sig.mldsa65 !== null;
    if (!hasPq) return { valid: !opts.requirePq, pq: false };
    if (!pk.mldsa65 || pk.mldsa65.length !== ML_DSA65_PUBLIC_KEY_BYTES || sig.mldsa65!.length !== ML_DSA65_SIGNATURE_BYTES) return { valid: false, pq: false };
    const ok = ml_dsa65.verify(sig.mldsa65!, message, pk.mldsa65);
    return { valid: ok, pq: ok };
  } catch {
    return { valid: false, pq: false };
  }
}

export function verifyHybrid(message: Uint8Array, sig: HybridSignature, pk: HybridPublicKey, opts: { requirePq?: boolean } = {}) {
  if (sig.kid !== pk.kid) return { valid: false, pq: false };
  try {
    return verifyHybridBytes(
      message,
      { ed25519: b64uDecode(sig.ed25519), mldsa65: sig.mldsa65 ? b64uDecode(sig.mldsa65) : null },
      { ed25519: b64uDecode(pk.ed25519), mldsa65: pk.mldsa65 ? b64uDecode(pk.mldsa65) : null },
      opts,
    );
  } catch {
    return { valid: false, pq: false };
  }
}
