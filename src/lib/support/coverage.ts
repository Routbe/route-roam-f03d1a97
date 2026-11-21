/**
 * Infrastructure health bar: how much of this month's server bill the treasury covers.
 * Costs are the owner's real monthly invoices; with an empty list the bar says so instead of
 * showing an invented number.
 */
export type MonthlyCost = { provider: string; cents: number };

/** Monthly infrastructure costs in whole euro cents, as supplied by the owner (2026-11-18). */
export const MONTHLY_COSTS: readonly MonthlyCost[] = [
  { provider: "Infomaniak Cloud & Mail", cents: 4850 },
  { provider: "Scaleway S3 Multi-Region Vault", cents: 2840 },
  { provider: "Neon Serverless Postgres", cents: 2900 },
  { provider: "Didit NFC API & Liveness", cents: 4500 },
];

export type Coverage =
  | { state: "unknown"; collectedCents: number }
  | { state: "known"; collectedCents: number; costCents: number; percent: number; shortfallCents: number };

export function coverage(collectedCents: number, costs: readonly MonthlyCost[] = MONTHLY_COSTS): Coverage {
  const collected = Math.max(0, Math.floor(Number.isFinite(collectedCents) ? collectedCents : 0));
  const costCents = costs.reduce((sum, c) => sum + (Number.isInteger(c.cents) && c.cents > 0 ? c.cents : 0), 0);
  if (costCents === 0) return { state: "unknown", collectedCents: collected };
  return {
    state: "known",
    collectedCents: collected,
    costCents,
    // Floor: the bar never claims more than is actually covered.
    percent: Math.floor((collected * 100) / costCents),
    shortfallCents: Math.max(0, costCents - collected),
  };
}
