/**
 * Blue mark for members verified before Didit (owner decision 2026-11-18): an admin approved
 * them with a confirmed legal name (bank transfer review), recorded as profiles.verified plus a
 * non-empty verified_legal_name and verified_at. Payment alone, Pro or is_paid never qualify, and
 * a banned or suspended profile never shows the mark.
 */
export type LegacyReviewRow = {
  verified?: unknown;
  verified_legal_name?: unknown;
  verified_at?: unknown;
  is_banned?: unknown;
  is_suspended?: unknown;
};

export function isLegacyReviewed(row: LegacyReviewRow | null | undefined): boolean {
  if (!row) return false;
  if (row.verified !== true) return false;
  if (row.is_banned === true || row.is_suspended === true) return false;
  const name = typeof row.verified_legal_name === "string" ? row.verified_legal_name.trim() : "";
  if (!name) return false;
  const at = row.verified_at;
  if (at == null || at === "") return false;
  const time = at instanceof Date ? at.getTime() : new Date(String(at)).getTime();
  return Number.isFinite(time);
}
