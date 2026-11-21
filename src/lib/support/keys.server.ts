/**
 * Treasury signing keys: Ed25519 and ML-DSA-65 seeds are HKDF-SHA256 over
 * ROUT_SUBJECT_MASTER_KEY with their own salt/info (same pattern as the blue-mark card), read
 * per call and zero-filled after use. No master key = nothing is signed and the pages say so.
 */
import type { HybridPublicKey, HybridSignature } from "./hybrid-signature";
import { b64uEncode } from "./hybrid-signature";

async function seed(info: string): Promise<Uint8Array | null> {
  const master = process.env["ROUT_SUBJECT_MASTER_KEY"] ?? "";
  if (master.length < 32) return null;
  const { hkdf } = await import("@noble/hashes/hkdf.js");
  const { sha256 } = await import("@noble/hashes/sha2.js");
  const enc = new TextEncoder();
  return hkdf(sha256, enc.encode(master), enc.encode("rout.support_treasury"), enc.encode(info), 32);
}

async function kidOf(edPk: Uint8Array, pqPk: Uint8Array): Promise<string> {
  const { sha256 } = await import("@noble/hashes/sha2.js");
  const joined = new Uint8Array(edPk.length + pqPk.length);
  joined.set(edPk);
  joined.set(pqPk, edPk.length);
  return Array.from(sha256(joined).subarray(0, 8), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function withKeys<T>(run: (k: { edSeed: Uint8Array; edPk: Uint8Array; pqSk: Uint8Array; pqPk: Uint8Array; kid: string }) => Promise<T> | T): Promise<T | null> {
  const edSeed = await seed("ed25519.v1");
  const pqSeed = await seed("ml-dsa-65.v1");
  if (!edSeed || !pqSeed) return null;
  const { ed25519 } = await import("@noble/curves/ed25519.js");
  const { ml_dsa65 } = await import("@noble/post-quantum/ml-dsa.js");
  const pq = ml_dsa65.keygen(pqSeed);
  try {
    const edPk = ed25519.getPublicKey(edSeed);
    return await run({ edSeed, edPk, pqSk: pq.secretKey, pqPk: pq.publicKey, kid: await kidOf(edPk, pq.publicKey) });
  } finally {
    edSeed.fill(0);
    pqSeed.fill(0);
    pq.secretKey.fill(0);
  }
}

let publicCache: HybridPublicKey | null = null;
export async function supportPublicKey(): Promise<HybridPublicKey | null> {
  if (publicCache) return publicCache;
  const pk = await withKeys(({ edPk, pqPk, kid }) => ({ kid, ed25519: b64uEncode(edPk), mldsa65: b64uEncode(pqPk) }));
  if (pk) publicCache = pk;
  return pk;
}

export async function signHybrid(message: Uint8Array): Promise<HybridSignature | null> {
  return withKeys(async ({ edSeed, pqSk, kid }) => {
    const { ed25519 } = await import("@noble/curves/ed25519.js");
    const { ml_dsa65 } = await import("@noble/post-quantum/ml-dsa.js");
    return { kid, ed25519: b64uEncode(ed25519.sign(message, edSeed)), mldsa65: b64uEncode(ml_dsa65.sign(message, pqSk)) };
  });
}

/** Ed25519-only signer for the SD-JWT VC (JOSE EdDSA). */
export async function edSigner(): Promise<{ kid: string; sign: (input: Uint8Array) => Promise<Uint8Array> } | null> {
  const pk = await supportPublicKey();
  if (!pk) return null;
  return {
    kid: pk.kid,
    sign: async (input) => {
      const sig = await withKeys(async ({ edSeed }) => {
        const { ed25519 } = await import("@noble/curves/ed25519.js");
        return ed25519.sign(input, edSeed);
      });
      if (!sig) throw new Error("support_key_unavailable");
      return sig;
    },
  };
}

/** Test hook. */
export function resetSupportKeyCache() {
  publicCache = null;
}
