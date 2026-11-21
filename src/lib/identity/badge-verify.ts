/**
 * Browser check of the blue-mark card attestation. The Ed25519 verification runs in the crypto
 * worker (enclave.badge.verify); this module only fetches ROUT's public badge key and compares
 * the signed claims with what the card shows.
 */
import { b64u } from "@/lib/e2ee/crypto";
import { badgeMessage, claimsMatchShown, decodeSignature, parseBadgeClaims, type BadgeAttestation, type BadgeMethod } from "./badge-attestation";

export type BadgeSignatureState = "checking" | "valid" | "valid_pq" | "invalid" | "unavailable";

type BadgeKey = { kid: string; publicKey: Uint8Array };
let keyPromise: Promise<BadgeKey | null> | null = null;

async function loadKey(): Promise<BadgeKey | null> {
  const res = await fetch("/api/badge/key", { credentials: "omit", headers: { accept: "application/json" } });
  if (!res.ok) return null;
  const body = (await res.json()) as { kid?: unknown; publicKey?: unknown; alg?: unknown };
  if (body.alg !== "Ed25519" || typeof body.kid !== "string" || typeof body.publicKey !== "string") return null;
  const publicKey = b64u.decode(body.publicKey);
  return publicKey.length === 32 ? { kid: body.kid, publicKey } : null;
}

export function badgeKey(): Promise<BadgeKey | null> {
  if (!keyPromise) {
    keyPromise = loadKey().catch(() => null).then((k) => {
      if (!k) keyPromise = null; // retry on the next open
      return k;
    });
  }
  return keyPromise;
}

/** Test hook. */
export function resetBadgeKey() {
  keyPromise = null;
}

export async function verifyBadgeAttestation(
  attestation: BadgeAttestation,
  shown: { handle: string | null | undefined; method: BadgeMethod | null | undefined; name: string | null | undefined; country: string | null | undefined; verifiedAt: string | null | undefined },
): Promise<Exclude<BadgeSignatureState, "checking">> {
  const claims = parseBadgeClaims(attestation.payload);
  const signature = decodeSignature(attestation.sig);
  if (!claims || !signature || !claimsMatchShown(claims, shown)) return "invalid";
  const key = await badgeKey();
  if (!key) return "unavailable";
  if (key.kid !== attestation.kid) return "invalid";
  try {
    const { enclave } = await import("@/lib/crypto-enclave/client");
    const { valid } = await enclave.badge.verify(badgeMessage(attestation.payload), signature, key.publicKey);
    if (!valid) return "invalid";
    if (!attestation.pq) return "valid";
    const { isPqAttestation } = await import("@/lib/crypto/pq-purposes");
    if (claims.method !== "didit" || !isPqAttestation(attestation.pq)) return "invalid";
    const { verifyPqAttestation } = await import("@/lib/crypto/pq-verify");
    const pq = await verifyPqAttestation("didit", [attestation.payload], attestation.pq);
    // A PQ signature that is present but wrong voids the card; an unreachable key leaves Ed25519 standing.
    return pq === "valid" ? "valid_pq" : pq === "invalid" ? "invalid" : "valid";
  } catch {
    return "unavailable";
  }
}
