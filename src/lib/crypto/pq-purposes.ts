/**
 * Hybrid Ed25519 ‖ ML-DSA-65 (NIST FIPS 204) signatures outside the treasury. Browser-safe: no keys.
 * Every purpose has its own domain line and its own key pair, so a signature made for one purpose
 * can never be replayed as another. The server signs in hybrid-signer.server.ts; browsers verify
 * only in the crypto worker (op pq.verify) against /.well-known/rout-pq-keys.json.
 */
import { domainMessage, type HybridPublicKey, type HybridSignature } from "@/lib/support/hybrid-signature";

export const PQ_PURPOSES = {
  /** ROUT Sign: {request id, source SHA-256, signed envelope SHA-256, signed at}. */
  sign: "rout.sign.attest.v1",
  /** Didit-verified blue-mark card: {canonical card payload}. */
  didit: "rout.didit.attest.v1",
  /** Identity credentials (OID4VCI SD-JWT VC): {issuer-signed JWT payload without rout_pq}. */
  identity: "rout.identity.doc.v1",
} as const;
export type PqPurpose = keyof typeof PQ_PURPOSES;
export const isPqPurpose = (v: unknown): v is PqPurpose => typeof v === "string" && Object.hasOwn(PQ_PURPOSES, v);

export const pqMessage = (purpose: PqPurpose, lines: readonly string[]) => domainMessage(PQ_PURPOSES[purpose], lines);

export type PqKeyEntry = HybridPublicKey & { purpose: PqPurpose; domain: string };
export type PqKeySet = { v: 1; alg: "Ed25519+ML-DSA-65"; keys: PqKeyEntry[] };
export type PqAttestation = HybridSignature;

const B64U = /^[A-Za-z0-9_-]+$/;
/** Strict parse of the published key set; anything unexpected is dropped. */
export function parsePqKeySet(raw: unknown): PqKeyEntry[] {
  if (!raw || typeof raw !== "object") return [];
  const body = raw as { v?: unknown; keys?: unknown };
  if (body.v !== 1 || !Array.isArray(body.keys)) return [];
  return body.keys.flatMap((k): PqKeyEntry[] => {
    if (!k || typeof k !== "object") return [];
    const e = k as Record<string, unknown>;
    if (!isPqPurpose(e["purpose"]) || e["domain"] !== PQ_PURPOSES[e["purpose"]]) return [];
    if (typeof e["kid"] !== "string" || !/^[0-9a-f]{16}$/.test(e["kid"])) return [];
    if (typeof e["ed25519"] !== "string" || !B64U.test(e["ed25519"]) || typeof e["mldsa65"] !== "string" || !B64U.test(e["mldsa65"])) return [];
    return [{ purpose: e["purpose"], domain: e["domain"] as string, kid: e["kid"], ed25519: e["ed25519"], mldsa65: e["mldsa65"] }];
  });
}

export function isPqAttestation(v: unknown): v is PqAttestation {
  if (!v || typeof v !== "object") return false;
  const a = v as Record<string, unknown>;
  return typeof a["kid"] === "string" && /^[0-9a-f]{16}$/.test(a["kid"]) && typeof a["ed25519"] === "string" && B64U.test(a["ed25519"])
    && typeof a["mldsa65"] === "string" && B64U.test(a["mldsa65"]);
}
