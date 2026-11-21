/**
 * Owner rule (2026-11-21): before a successful Didit identity verification a member can only use
 * a private alias at rout.be/u/<alias>. The root handle rout.be/<handle> is chosen only afterwards.
 * Admin- and team-granted handles are separate paths and are not decided here.
 */
export type DiditEvidence = {
  /** Rows from verified_identity_nullifiers for this member (0288+). */
  attestations: { provider: string; evidence: string; has_legal_identity: boolean }[];
  /** Row from identity_verifications (legacy record written by the same engine). */
  legacy: { is_verified: boolean; verification_provider: string | null } | null;
};

export function rootHandleAllowed(e: DiditEvidence): boolean {
  if (e.attestations.some((a) => a.provider === "didit" && a.evidence === "kyc_document" && a.has_legal_identity)) return true;
  return Boolean(e.legacy?.is_verified && e.legacy.verification_provider === "didit");
}

export const ROOT_HANDLE_KYC_REASON =
  "Je rout.be-adres kies je na je identiteitsverificatie. Tot dan gebruik je een privé-alias op rout.be/u/…";
