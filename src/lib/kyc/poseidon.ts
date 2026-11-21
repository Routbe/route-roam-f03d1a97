/**
 * Poseidon x5_255_3 over the BLS12-381 scalar field, the same instance as wasm/rout-zk/src/poseidon.rs
 * (hadeshash reference, t = 3, x^5, 8 full + 57 partial rounds), built on @noble/curves' audited
 * permutation. poseidon.test.ts pins it to the reference vector and to the rout-zk empty SMT root.
 *
 * Not constant time: JavaScript BigInt arithmetic is variable-time. Callers hash a short canonical
 * identifier once per verification, server-side, without returning timing to the provider.
 */
import { Field } from "@noble/curves/abstract/modular.js";
import { poseidon } from "@noble/curves/abstract/poseidon.js";
import { POSEIDON_MDS, POSEIDON_PRIME, POSEIDON_ROUND_CONSTANTS } from "./poseidon-constants";

const Fp = Field(POSEIDON_PRIME);
const T = 3;

const roundConstants: bigint[][] = [];
for (let i = 0; i < POSEIDON_ROUND_CONSTANTS.length; i += T) roundConstants.push(POSEIDON_ROUND_CONSTANTS.slice(i, i + T));

/** The bare permutation (state of three field elements). */
export const poseidonPermutation = poseidon({
  Fp,
  t: T,
  roundsFull: 8,
  roundsPartial: 57,
  sboxPower: 5,
  mds: POSEIDON_MDS.map((row) => [...row]),
  roundConstants,
});

/** Capacity tag of an arity-2 Merkle node (rout-zk TAG_MERKLE_2). */
export const TAG_MERKLE_2 = 3n;

/** hash2(tag, a, b) = Permutation([tag, a, b])[1], identical to rout-zk poseidon::hash2. */
export function poseidonHash2(tag: bigint, a: bigint, b: bigint): bigint {
  return poseidonPermutation([Fp.create(tag), Fp.create(a), Fp.create(b)])[1]!;
}

const CHUNK = 31; // 248 bits, always below the 255-bit modulus.
const MAX_INPUT = 512;
/** ASCII "ROUT" in the low 32 bits of the capacity tag; the byte length sits above bit 64. */
const DOMAIN = 0x524f5554n;

function chunkToField(bytes: Uint8Array, from: number): bigint {
  let v = 0n;
  for (let i = from; i < from + CHUNK; i++) v = (v << 8n) | BigInt(i < bytes.length ? bytes[i]! : 0);
  return v;
}

function toBytes32(v: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * Poseidon256(bytes): a 32-byte big-endian digest of a variable-length input.
 *   tag = 2^64 * len + "ROUT"   (length-binding capacity tag, so zero padding is unambiguous)
 *   h_0 = 0;  h_i = hash2(tag, h_{i-1}, chunk_i)   for 31-byte big-endian chunks (last one zero-padded)
 * An empty input still absorbs one (all-zero) chunk.
 */
export function poseidon256(bytes: Uint8Array): Uint8Array {
  if (bytes.length > MAX_INPUT) throw new RangeError("poseidon_input_too_long");
  const tag = (BigInt(bytes.length) << 64n) | DOMAIN;
  const chunks = Math.max(1, Math.ceil(bytes.length / CHUNK));
  let h = 0n;
  for (let c = 0; c < chunks; c++) h = poseidonHash2(tag, h, chunkToField(bytes, c * CHUNK));
  return toBytes32(h);
}
