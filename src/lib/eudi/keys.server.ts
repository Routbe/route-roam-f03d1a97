/**
 * EUDI issuer keys (server-only), all HKDF-SHA256 over ROUT_SUBJECT_MASTER_KEY with their own salt:
 *  - ES256 (P-256) for SD-JWT VCs and the Token Status List: 48 seed bytes reduced to a scalar;
 *  - HMAC-SHA256 for stateless OID4VCI c_nonce values and (separate key) RFC 9449 DPoP nonces.
 * Seeds and scalars are zero-filled after use. No master key = issuance is off.
 */
import { b64uEncode } from "@/lib/support/hybrid-signature";
import { p256Jwk, type PublicJwk } from "./jose";

const enc = new TextEncoder();

async function derive(salt: string, info: string, length: number): Promise<Uint8Array | null> {
  const master = process.env["ROUT_SUBJECT_MASTER_KEY"] ?? "";
  if (master.length < 32) return null;
  const { hkdf } = await import("@noble/hashes/hkdf.js");
  const { sha256 } = await import("@noble/hashes/sha2.js");
  return hkdf(sha256, enc.encode(master), enc.encode(salt), enc.encode(info), length);
}

async function withIssuerKey<T>(run: (sk: Uint8Array, pk: Uint8Array) => T | Promise<T>): Promise<T | null> {
  const seed = await derive("rout.eudi.issuer", "p-256.v1", 48);
  if (!seed) return null;
  const { p256 } = await import("@noble/curves/nist.js");
  const sk = p256.utils.randomSecretKey(seed);
  try {
    return await run(sk, p256.getPublicKey(sk, false));
  } finally {
    seed.fill(0);
    sk.fill(0);
  }
}

export type IssuerKey = { kid: string; jwk: PublicJwk };
let issuerCache: IssuerKey | null = null;

export async function issuerKey(): Promise<IssuerKey | null> {
  if (issuerCache) return issuerCache;
  const k = await withIssuerKey(async (_sk, pk) => {
    const { sha256 } = await import("@noble/hashes/sha2.js");
    return { kid: Array.from(sha256(pk).subarray(0, 8), (b) => b.toString(16).padStart(2, "0")).join(""), jwk: p256Jwk(pk) };
  });
  if (k) issuerCache = k;
  return k;
}

/** ES256 signature (raw r‖s, low-S) over the JWS signing input. */
export async function signEs256(input: Uint8Array): Promise<Uint8Array | null> {
  return withIssuerKey(async (sk) => {
    const { p256 } = await import("@noble/curves/nist.js");
    return p256.sign(input, sk);
  });
}

/** JWKS entry as published in /.well-known/jwt-vc-issuer. */
export async function issuerJwks(): Promise<{ keys: Array<PublicJwk & { kid: string; alg: "ES256"; use: "sig" }> }> {
  const k = await issuerKey();
  return { keys: k ? [{ ...k.jwk, kid: k.kid, alg: "ES256", use: "sig" }] : [] };
}

// ---------------------------------------------------------------- c_nonce

const NONCE_TTL_S = 300;
async function hmac(data: Uint8Array, salt = "rout.eudi.nonce"): Promise<Uint8Array | null> {
  const key = await derive(salt, "hmac-sha256.v1", 32);
  if (!key) return null;
  try {
    const { hmac: h } = await import("@noble/hashes/hmac.js");
    const { sha256 } = await import("@noble/hashes/sha2.js");
    return h(sha256, key, data);
  } finally {
    key.fill(0);
  }
}

export const newCNonce = (now = Date.now()) => newNonce(now, "rout.eudi.nonce");
export const checkCNonce = (nonce: unknown, now = Date.now()) => checkNonce(nonce, now, "rout.eudi.nonce");
/** RFC 9449 server-provided DPoP nonce: same stateless format, its own HMAC key (never interchangeable with c_nonce). */
export const newDpopNonce = (now = Date.now()) => newNonce(now, "rout.eudi.dpop-nonce");
export const checkDpopNonce = (nonce: unknown, now = Date.now()) => checkNonce(nonce, now, "rout.eudi.dpop-nonce");

async function newNonce(now: number, salt: string): Promise<string | null> {
  const body = new Uint8Array(24);
  new DataView(body.buffer).setBigUint64(0, BigInt(Math.floor(now / 1000)));
  body.set(crypto.getRandomValues(new Uint8Array(16)), 8);
  const mac = await hmac(body, salt);
  if (!mac) return null;
  const out = new Uint8Array(40);
  out.set(body);
  out.set(mac.subarray(0, 16), 24);
  return b64uEncode(out);
}

async function checkNonce(nonce: unknown, now: number, salt: string): Promise<boolean> {
  if (typeof nonce !== "string" || !/^[A-Za-z0-9_-]{54}$/.test(nonce)) return false;
  const { b64uDecode } = await import("@/lib/support/hybrid-signature");
  const raw = b64uDecode(nonce);
  if (raw.length !== 40) return false;
  const body = raw.subarray(0, 24);
  const mac = await hmac(body, salt);
  if (!mac) return false;
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= mac[i]! ^ raw[24 + i]!;
  if (diff !== 0) return false;
  const ts = Number(new DataView(body.buffer, body.byteOffset).getBigUint64(0));
  const age = Math.floor(now / 1000) - ts;
  return age >= -30 && age <= NONCE_TTL_S;
}

/** Test hook. */
export function resetEudiKeyCache() {
  issuerCache = null;
}
