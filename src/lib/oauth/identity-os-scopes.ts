/**
 * Sovereign Identity OS scopes for "Login met ROUT" (pure, browser-safe, tested).
 *
 *   sybil_proof     app_nullifier = first 32 bytes of ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) under a
 *                   server-only key over "rout.app_nullifier.v2" 0x00 universal_nullifier 0x00 client_id:
 *                   one human = one account per app; two apps cannot link their users, and a leaked
 *                   universal nullifier alone cannot reproduce any app nullifier.
 *   real_human      is_real_human, true only from a zero-knowledge humanity proof (green shield).
 *   age_gate:N      age_over_N for N = 13..21 (the app picks one), from the capped age floor of a KYC
 *                   attestation; no date of birth leaves ROUT. A signed claim, not a zk-SNARK.
 *   legal_identity  has_legal_identity, plus the legal name only where ROUT still holds one (legacy
 *                   tier-2 records); Didit attestations since 2026-11-17 keep no name, so it is null.
 *                   Off by default on the consent screen: the member must tick it.
 */
import { ecvrfProofToHash, ecvrfProve } from "@/lib/crypto/ecvrf";
import { ageGatePasses, AGE_GATE_MAX, AGE_GATE_MIN } from "@/lib/kyc/age-vector";

export const AGE_GATE_SCOPES = Array.from({ length: AGE_GATE_MAX - AGE_GATE_MIN + 1 }, (_, i) => `age_gate:${AGE_GATE_MIN + i}`);
/** Dynamic notation `age_gate?min_age=N` (N 13..21); bare `age_gate` means 18. */
export const AGE_GATE_DEFAULT = 18;
export const AGE_GATE_PARAM_SCOPES = Array.from({ length: AGE_GATE_MAX - AGE_GATE_MIN + 1 }, (_, i) => `age_gate?min_age=${AGE_GATE_MIN + i}`);
export const IDENTITY_OS_SCOPES: readonly string[] = ["sybil_proof", "real_human", "legal_identity", "age_gate", ...AGE_GATE_SCOPES, ...AGE_GATE_PARAM_SCOPES];
/** Scopes that release personal data; never released for a member under 18. */
export const MINOR_BLOCKED_SCOPES: readonly string[] = ["legal_identity", "identity:legal_name", "identity:national_id", "email", "phone", "address", "profile", "profile:read"];

/** The minimum age of an age_gate scope (`age_gate`, `age_gate:N`, `age_gate?min_age=N`), or null. */
export function ageGateMin(scope: string): number | null {
  if (scope === "age_gate") return AGE_GATE_DEFAULT;
  const m = /^age_gate(?::|\?min_age=)(\d{2})$/.exec(scope);
  if (!m) return null;
  const n = Number(m[1]);
  return n >= AGE_GATE_MIN && n <= AGE_GATE_MAX ? n : null;
}

/** The strictest requested age gate, or null when none was requested. */
export function requestedMinAge(scopes: readonly string[]): number | null {
  let min: number | null = null;
  for (const s of scopes) {
    const n = ageGateMin(s);
    if (n !== null && (min === null || n > min)) min = n;
  }
  return min;
}

/**
 * Minor firewall: when the member's attested age is below 18, every personal-data scope is removed,
 * even when the app asked for it or the member ticked it. Only zero-knowledge scopes remain.
 */
export function applyMinorFirewall(granted: readonly string[], ageVector: number | null): string[] {
  if (!isKnownMinor(ageVector)) return [...granted];
  return granted.filter((s) => !MINOR_BLOCKED_SCOPES.includes(s));
}

/** True when an attested age exists and it is below 18. No attestation means no age is known. */
export function isKnownMinor(ageVector: number | null): boolean {
  return ageVector !== null && ageVector !== undefined && !ageGatePasses(ageVector, 18);
}

const HEX64 = /^[0-9a-f]{64}$/;

/** Per-app nullifier via RFC 9381 ECVRF; deterministic for (person, app, key), unlinkable across apps. */
export function appNullifier(universalNullifier: string, clientId: string, vrfSecret: Uint8Array): string {
  if (!HEX64.test(universalNullifier)) throw new Error("app_nullifier_input");
  if (!clientId || clientId.length > 200) throw new Error("app_nullifier_input");
  if (vrfSecret.length !== 32) throw new Error("app_nullifier_key");
  const alpha = new TextEncoder().encode(`rout.app_nullifier.v2\u0000${universalNullifier}\u0000${clientId}`);
  const beta = ecvrfProofToHash(ecvrfProve(vrfSecret, alpha));
  return [...beta.subarray(0, 32)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export type IdentityOsInput = {
  legalIdentity: boolean;
  realHuman: boolean;
  /** Age-threshold vector (kyc/age-vector.ts); null without a KYC attestation. */
  ageVector: number | null;
  /** The member's primary universal nullifier; null without a KYC attestation (or before db/0290). */
  rootNullifier: string | null;
  legalName: { first_name: string | null; last_name: string | null; full_legal_name: string | null } | null;
};

/** Claims for the granted identity-OS scopes and the scopes that were answered (for the disclosure log). */
export function identityOsClaims(granted: readonly string[], clientId: string, input: IdentityOsInput, vrfSecret: Uint8Array | null = null): { claims: Record<string, unknown>; disclosed: string[] } {
  const claims: Record<string, unknown> = {};
  const disclosed: string[] = [];
  if (granted.includes("sybil_proof")) {
    // No server key = no nullifier (fails closed: sybil_proof false), never an unkeyed fallback.
    const n = vrfSecret && input.rootNullifier && HEX64.test(input.rootNullifier) ? appNullifier(input.rootNullifier, clientId, vrfSecret) : null;
    claims["sybil_proof"] = n !== null;
    if (n) claims["app_nullifier"] = n;
    disclosed.push("sybil_proof");
  }
  if (granted.includes("real_human")) {
    claims["is_real_human"] = input.realHuman === true;
    disclosed.push("real_human");
  }
  const minAge = requestedMinAge(granted);
  if (minAge !== null) {
    // Strictly minimal: only whether the threshold is met and which threshold was asked.
    claims["age_verified"] = ageGatePasses(input.ageVector, minAge);
    claims["min_age"] = minAge;
    for (const scope of granted) if (ageGateMin(scope) !== null) disclosed.push(scope);
  }
  if (granted.includes("legal_identity") && !isKnownMinor(input.ageVector)) {
    claims["has_legal_identity"] = input.legalIdentity === true;
    if (input.legalIdentity && input.legalName?.full_legal_name) Object.assign(claims, input.legalName);
    disclosed.push("legal_identity");
  }
  return { claims, disclosed };
}
