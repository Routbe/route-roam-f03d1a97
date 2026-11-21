/**
 * Server gate for issuing developer credentials (new OAuth clients, API keys): the caller must hold
 * a KYC legal identity, read from the same source as the blue mark. Fails closed: an unreachable
 * database or an older schema means no legal identity.
 */
import { canIssueDeveloperCredentials, LEGAL_IDENTITY_REQUIRED } from "./console-access-rules";

export async function hasDeveloperLegalIdentity(userId: string): Promise<boolean> {
  const { readPublicIdentity } = await import("@/lib/identity/public-identity.server");
  const { sql } = await import("@/lib/neon");
  const [pub, profile] = await Promise.all([
    readPublicIdentity(userId),
    (sql`select is_banned, is_suspended from public.profiles where id = ${userId} limit 1` as Promise<Record<string, unknown>[]>).catch(() => []),
  ]);
  const p = profile[0] ?? {};
  return canIssueDeveloperCredentials({ legalIdentity: pub.diditVerified, isBanned: p["is_banned"] === true, isSuspended: p["is_suspended"] === true });
}

export async function assertDeveloperLegalIdentity(userId: string): Promise<void> {
  if (!(await hasDeveloperLegalIdentity(userId))) {
    throw new Error(`${LEGAL_IDENTITY_REQUIRED}: Nieuwe apps en API-sleutels maken kan alleen met een geverifieerde wettelijke identiteit (KYC). Verifieer je identiteit en probeer opnieuw.`);
  }
}
