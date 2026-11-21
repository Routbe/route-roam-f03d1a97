import { sql } from "@/lib/neon";
import { hasSchemaFeature } from "@/lib/schema-features.server";
import { isLegacyReviewed } from "./legacy-mark";

/**
 * diditVerified = the blue mark: a KYC attestation (db/0282) or a pre-Didit admin review with a
 * confirmed legal name (legacy-mark.ts). kycAttested is the strict KYC-only answer.
 */
export type PublicIdentity = { diditVerified: boolean; kycAttested: boolean; legacyReviewed: boolean; realHuman: boolean };

const NONE: PublicIdentity = { diditVerified: false, kycAttested: false, legacyReviewed: false, realHuman: false };

/**
 * Public identity result per member id, read through db/0282 (rout_public_identity_badges) plus
 * the legacy admin review on profiles. profiles.verified alone (payment, Pro) never sets the mark.
 * realHuman is the green "Real Human" shield and comes EXCLUSIVELY from a zero-knowledge proof
 * (db/0288, evidence = 'zk_proof'); before 0288 is live it stays false.
 * Fails closed: an unreachable database or an older schema gives no mark.
 */
export async function readPublicIdentities(userIds: readonly string[]): Promise<Map<string, PublicIdentity>> {
  const ids = [...new Set(userIds.filter(Boolean))].slice(0, 200);
  const out = new Map<string, PublicIdentity>();
  if (!ids.length) return out;
  try {
    const zkOnly = await hasSchemaFeature("0288");
    const rows = (await sql`select user_id, didit_legal_identity, real_human
        from public.rout_public_identity_badges(${ids}::uuid[])`) as Record<string, unknown>[];
    for (const r of rows) {
      const kyc = r["didit_legal_identity"] === true;
      out.set(String(r["user_id"]), { diditVerified: kyc, kycAttested: kyc, legacyReviewed: false, realHuman: zkOnly && r["real_human"] === true });
    }
  } catch (error) {
    console.warn("[public-identity:skipped]", error);
  }
  try {
    const legacy = (await sql`select id, verified, verified_legal_name, verified_at, is_banned, is_suspended
        from public.profiles where id = any(${ids}::uuid[])`) as Record<string, unknown>[];
    for (const r of legacy) {
      if (!isLegacyReviewed(r)) continue;
      const id = String(r["id"]);
      const cur = out.get(id) ?? NONE;
      out.set(id, { ...cur, diditVerified: true, legacyReviewed: !cur.kycAttested });
    }
  } catch (error) {
    console.warn("[public-identity:legacy-skipped]", error);
  }
  return out;
}

export async function readPublicIdentity(userId: string): Promise<PublicIdentity> {
  return (await readPublicIdentities([userId])).get(userId) ?? NONE;
}
