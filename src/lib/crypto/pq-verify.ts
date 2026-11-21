/**
 * Browser check of a hybrid attestation: fetches ROUT's published key for the purpose and lets the
 * crypto worker (op pq.verify) rebuild the domain message and check both signatures. Nothing here
 * decides validity itself.
 */
import { parsePqKeySet, type PqAttestation, type PqKeyEntry, type PqPurpose } from "./pq-purposes";

export type PqState = "valid" | "invalid" | "unavailable";

let keysPromise: Promise<PqKeyEntry[]> | null = null;
function pqKeys(): Promise<PqKeyEntry[]> {
  if (!keysPromise) {
    keysPromise = fetch("/.well-known/rout-pq-keys.json", { credentials: "omit", headers: { accept: "application/json" } })
      .then((r) => (r.ok ? r.json() : null))
      .then(parsePqKeySet)
      .catch(() => [])
      .then((keys) => {
        if (keys.length === 0) keysPromise = null;
        return keys;
      });
  }
  return keysPromise;
}

/** Test hook. */
export function resetPqKeys() {
  keysPromise = null;
}

export async function verifyPqAttestation(purpose: PqPurpose, lines: readonly string[], attestation: PqAttestation): Promise<PqState> {
  const key = (await pqKeys()).find((k) => k.purpose === purpose);
  if (!key) return "unavailable";
  if (key.kid !== attestation.kid) return "invalid";
  try {
    const { enclave } = await import("@/lib/crypto-enclave/client");
    const { valid, pq } = await enclave.pq.verify(purpose, lines, attestation, key);
    return valid && pq ? "valid" : "invalid";
  } catch {
    return "unavailable";
  }
}
