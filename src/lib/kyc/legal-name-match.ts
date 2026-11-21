/**
 * Holder-name matching against the sealed legal name (pure, tested). The comparison is the same
 * normalisation the database uses for workspace support (db/0283 rout_ws_support_norm: NFKD,
 * lowercase, letters and digits only), and accepts first+last or last+first order.
 */
export function normName(s: string | null | undefined): string {
  return (s ?? "").normalize("NFKD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

export function holderMatchesLegalName(holder: string | null | undefined, legal: { first: string | null; last: string | null } | null): boolean {
  const h = normName(holder);
  if (!h || !legal?.first || !legal.last) return false;
  const a = normName(`${legal.first}${legal.last}`);
  const b = normName(`${legal.last}${legal.first}`);
  return a.length > 1 && (h === a || h === b);
}
