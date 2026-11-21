/**
 * Shared hybrid signer (server-only). Per purpose, the Ed25519 and ML-DSA-65 seeds are
 * HKDF-SHA256 over ROUT_SUBJECT_MASTER_KEY (salt "rout.pq.<purpose>", info per algorithm), read
 * per call and zero-filled after use; the ML-DSA secret key is wiped after each signature.
 * No master key = nothing is signed, and callers simply omit the attestation.
 */
import { b64uEncode, type HybridPublicKey, type HybridSignature } from "@/lib/support/hybrid-signature";
import { PQ_PURPOSES, pqMessage, type PqKeySet, type PqPurpose } from "./pq-purposes";

const enc = new TextEncoder();

async function seed(purpose: PqPurpose, info: string): Promise<Uint8Array | null> {
  const master = process.env["ROUT_SUBJECT_MASTER_KEY"] ?? "";
  if (master.length < 32) return null;
  const { hkdf } = await import("@noble/hashes/hkdf.js");
  const { sha256 } = await import("@noble/hashes/sha2.js");
  return hkdf(sha256, enc.encode(master), enc.encode(`rout.pq.${purpose}`), enc.encode(info), 32);
}

async function kidOf(edPk: Uint8Array, pqPk: Uint8Array): Promise<string> {
  const { sha256 } = await import("@noble/hashes/sha2.js");
  const joined = new Uint8Array(edPk.length + pqPk.length);
  joined.set(edPk);
  joined.set(pqPk, edPk.length);
  return Array.from(sha256(joined).subarray(0, 8), (b) => b.toString(16).padStart(2, "0")).join("");
}

type Keys = { edSeed: Uint8Array; edPk: Uint8Array; pqSk: Uint8Array; pqPk: Uint8Array; kid: string };
async function withKeys<T>(purpose: PqPurpose, run: (k: Keys) => Promise<T> | T): Promise<T | null> {
  const edSeed = await seed(purpose, "ed25519.v1");
  const pqSeed = await seed(purpose, "ml-dsa-65.v1");
  if (!edSeed || !pqSeed) {
    edSeed?.fill(0);
    pqSeed?.fill(0);
    return null;
  }
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

const publicCache = new Map<PqPurpose, HybridPublicKey>();
export async function pqPublicKey(purpose: PqPurpose): Promise<HybridPublicKey | null> {
  const hit = publicCache.get(purpose);
  if (hit) return hit;
  const pk = await withKeys(purpose, ({ edPk, pqPk, kid }) => ({ kid, ed25519: b64uEncode(edPk), mldsa65: b64uEncode(pqPk) }));
  if (pk) publicCache.set(purpose, pk);
  return pk;
}

/** Hybrid signature over the purpose's domain message; null without a master key. */
export async function signPq(purpose: PqPurpose, lines: readonly string[]): Promise<HybridSignature | null> {
  const message = pqMessage(purpose, lines);
  return withKeys(purpose, async ({ edSeed, pqSk, kid }) => {
    const { ed25519 } = await import("@noble/curves/ed25519.js");
    const { ml_dsa65 } = await import("@noble/post-quantum/ml-dsa.js");
    return { kid, ed25519: b64uEncode(ed25519.sign(message, edSeed)), mldsa65: b64uEncode(ml_dsa65.sign(message, pqSk)) };
  });
}

/** Everything /.well-known/rout-pq-keys.json publishes; empty without a master key. */
export async function pqKeySet(): Promise<PqKeySet> {
  const keys: PqKeySet["keys"] = [];
  for (const purpose of Object.keys(PQ_PURPOSES) as PqPurpose[]) {
    const pk = await pqPublicKey(purpose);
    if (pk) keys.push({ purpose, domain: PQ_PURPOSES[purpose], ...pk });
  }
  return { v: 1, alg: "Ed25519+ML-DSA-65", keys };
}

/** Test hook. */
export function resetPqKeyCache() {
  publicCache.clear();
}
