/**
 * ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381, suite 0x03), pure and synchronous.
 *
 * A verifiable random function: only the holder of the secret key can compute beta = VRF(sk, alpha),
 * and anyone holding the public key can check a proof that beta belongs to alpha. ROUT uses it for
 * per-app nullifiers: without the server key an app nullifier cannot be computed from a leaked
 * universal nullifier, and two apps comparing their values learn nothing about each other's users.
 * Checked against the RFC 9381 Appendix B.3 test vectors in ecvrf.test.ts.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";

const Point = ed25519.Point;
type EdPoint = InstanceType<typeof ed25519.Point>;
const Q = Point.Fn.ORDER;
const SUITE = 0x03;
const C_LEN = 16;

const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};
const leToInt = (b: Uint8Array) => { let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]); return n; };
const intToLe = (n: bigint, len: number) => { const out = new Uint8Array(len); for (let i = 0; i < len; i++) { out[i] = Number(n & 0xffn); n >>= 8n; } return out; };
const mod = (a: bigint) => ((a % Q) + Q) % Q;
const mul = (p: EdPoint, n: bigint) => (n === 0n ? Point.ZERO : p.multiply(n));

/** RFC 8032 secret expansion: clamped scalar x and the nonce prefix. */
function expand(secret: Uint8Array) {
  if (secret.length !== 32) throw new Error("ecvrf_secret_length");
  const h = sha512(secret);
  const a = h.slice(0, 32);
  a[0] &= 248; a[31] &= 127; a[31] |= 64;
  return { x: mod(leToInt(a)), prefix: h.slice(32, 64) };
}

export function ecvrfPublicKey(secret: Uint8Array): Uint8Array {
  return Point.BASE.multiply(expand(secret).x).toBytes();
}

function decodePoint(b: Uint8Array): EdPoint | null {
  try { return Point.fromBytes(b); } catch { return null; }
}

/** encode_to_curve_try_and_increment (RFC 9381 5.4.1.1). */
function encodeToCurve(pk: Uint8Array, alpha: Uint8Array): EdPoint {
  for (let ctr = 0; ctr < 256; ctr++) {
    const hash = sha512(concat(Uint8Array.of(SUITE, 0x01), pk, alpha, Uint8Array.of(ctr, 0x00)));
    const p = decodePoint(hash.slice(0, 32));
    if (!p) continue;
    const h = p.clearCofactor();
    if (!h.equals(Point.ZERO)) return h;
  }
  throw new Error("ecvrf_encode_failed");
}

function challenge(points: EdPoint[]): bigint {
  const c = sha512(concat(Uint8Array.of(SUITE, 0x02), ...points.map((p) => p.toBytes()), Uint8Array.of(0x00)));
  return leToInt(c.slice(0, C_LEN));
}

function gammaToHash(gamma: EdPoint): Uint8Array {
  return sha512(concat(Uint8Array.of(SUITE, 0x03), gamma.clearCofactor().toBytes(), Uint8Array.of(0x00)));
}

/** pi = Gamma (32) || c (16) || s (32). */
export function ecvrfProve(secret: Uint8Array, alpha: Uint8Array): Uint8Array {
  const { x, prefix } = expand(secret);
  const pk = Point.BASE.multiply(x).toBytes();
  const H = encodeToCurve(pk, alpha);
  const gamma = H.multiply(x);
  const k = mod(leToInt(sha512(concat(prefix, H.toBytes()))));
  const c = challenge([Point.fromBytes(pk), H, gamma, mul(Point.BASE, k), mul(H, k)]);
  const s = mod(k + c * x);
  return concat(gamma.toBytes(), intToLe(c, C_LEN), intToLe(s, 32));
}

/** beta (64 bytes) from a proof; does not verify it. */
export function ecvrfProofToHash(pi: Uint8Array): Uint8Array {
  const gamma = pi.length === 80 ? decodePoint(pi.slice(0, 32)) : null;
  if (!gamma) throw new Error("ecvrf_invalid_proof");
  return gammaToHash(gamma);
}

/** beta when the proof is valid for (pk, alpha), otherwise null. */
export function ecvrfVerify(publicKey: Uint8Array, pi: Uint8Array, alpha: Uint8Array): Uint8Array | null {
  if (pi.length !== 80 || publicKey.length !== 32) return null;
  const Y = decodePoint(publicKey);
  const gamma = decodePoint(pi.slice(0, 32));
  if (!Y || !gamma || Y.isSmallOrder()) return null;
  const c = leToInt(pi.slice(32, 48));
  const s = leToInt(pi.slice(48, 80));
  if (s >= Q) return null;
  const H = encodeToCurve(publicKey, alpha);
  const U = mul(Point.BASE, s).subtract(mul(Y, c));
  const V = mul(H, s).subtract(mul(gamma, c));
  return challenge([Y, H, gamma, U, V]) === c ? gammaToHash(gamma) : null;
}
