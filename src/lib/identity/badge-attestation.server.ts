/**
 * Server half of the signed blue-mark card. The Ed25519 key is HKDF-SHA256 over
 * ROUT_SUBJECT_MASTER_KEY with its own salt and info (same pattern as the app-nullifier
 * ECVRF key), read per call and wiped after use. No master key = no attestation, and the
 * card then simply shows no signature line.
 */
import { b64u } from "@/lib/e2ee/crypto";
import { badgeMessage, canonicalBadgePayload, type BadgeAttestation, type BadgeClaims } from "./badge-attestation";

async function badgeSeed(): Promise<Uint8Array | null> {
  const master = process.env["ROUT_SUBJECT_MASTER_KEY"] ?? "";
  if (master.length < 32) return null;
  const { hkdf } = await import("@noble/hashes/hkdf.js");
  const { sha256 } = await import("@noble/hashes/sha2.js");
  const enc = new TextEncoder();
  return hkdf(sha256, enc.encode(master), enc.encode("rout.badge_attestation"), enc.encode("ed25519.v1"), 32);
}

export async function badgeKeyId(publicKey: Uint8Array): Promise<string> {
  const { sha256 } = await import("@noble/hashes/sha2.js");
  return Array.from(sha256(publicKey).subarray(0, 8), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** The public verification key, or null when the server has no master key. */
export async function badgePublicKey(): Promise<{ kid: string; publicKey: string } | null> {
  const seed = await badgeSeed();
  if (!seed) return null;
  try {
    const { ed25519 } = await import("@noble/curves/ed25519.js");
    const pk = ed25519.getPublicKey(seed);
    return { kid: await badgeKeyId(pk), publicKey: b64u.encode(pk) };
  } finally {
    seed.fill(0);
  }
}

export async function signBadgeClaims(claims: BadgeClaims): Promise<BadgeAttestation | null> {
  const seed = await badgeSeed();
  if (!seed) return null;
  try {
    const { ed25519 } = await import("@noble/curves/ed25519.js");
    const payload = canonicalBadgePayload(claims);
    const sig = ed25519.sign(badgeMessage(payload), seed);
    let pq: BadgeAttestation["pq"] = null;
    if (claims.method === "didit") {
      const { signPq } = await import("@/lib/crypto/hybrid-signer.server");
      pq = await signPq("didit", [payload]).catch(() => null);
    }
    return { kid: await badgeKeyId(ed25519.getPublicKey(seed)), payload, sig: b64u.encode(sig), ...(pq ? { pq } : {}) };
  } finally {
    seed.fill(0);
  }
}
