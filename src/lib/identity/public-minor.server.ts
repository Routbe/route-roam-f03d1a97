import { sql } from "@/lib/neon";
import { hasSchemaFeature } from "@/lib/schema-features.server";

/**
 * Is the owner of a public profile under 18? From db-pending/0292 on this is
 * rout_public_owner_is_minor (self-declared age floor or KYC age floor, under 18). Before 0292
 * is live it falls back to rout_user_is_minor, which only knows "under 16". Unknown age = false
 * (same rule as the OIDC minor firewall); a failing lookup = true, so the name is masked.
 */
export async function isPublicOwnerMinor(userId: string): Promise<boolean> {
  try {
    const rows = (await hasSchemaFeature("0292"))
      ? ((await sql`select public.rout_public_owner_is_minor(${userId}::uuid) as m`) as { m: unknown }[])
      : ((await sql`select public.rout_user_is_minor(${userId}::uuid) as m`) as { m: unknown }[]);
    return rows[0]?.m === true;
  } catch (error) {
    console.warn("[public-minor:failed-closed]", error);
    return true;
  }
}
