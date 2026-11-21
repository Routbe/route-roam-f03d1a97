/**
 * The nullifier pepper (server-only, read per call). Accepted names: IDENTITY_HASH_PEPPER and
 * PEPPER_SECRET. When both are set they must be identical: two different peppers would split the
 * registry, so the same document would yield two different nullifiers and pass the cross-provider
 * check. In that case, or when the value is shorter than MIN_PEPPER_LENGTH, KYC is not configured.
 */
import { MIN_PEPPER_LENGTH } from "./nullifier";

export const PEPPER_ENV_NAMES = ["IDENTITY_HASH_PEPPER", "PEPPER_SECRET"] as const;

export type PepperState = { ok: true; pepper: string } | { ok: false; reason: "missing" | "too_short" | "conflict" };

export function readPepper(env: Record<string, string | undefined> = process.env): PepperState {
  const values = PEPPER_ENV_NAMES.map((n) => env[n]).filter((v): v is string => typeof v === "string" && v.length > 0);
  if (!values.length) return { ok: false, reason: "missing" };
  if (values.some((v) => v !== values[0])) return { ok: false, reason: "conflict" };
  if (values[0]!.length < MIN_PEPPER_LENGTH) return { ok: false, reason: "too_short" };
  return { ok: true, pepper: values[0]! };
}

/** The pepper, or throws "kyc_not_configured". */
export function identityPepper(env: Record<string, string | undefined> = process.env): string {
  const s = readPepper(env);
  if (!s.ok) throw new Error("kyc_not_configured");
  return s.pepper;
}
