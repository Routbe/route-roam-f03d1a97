import { rootHandleAllowed, type DiditEvidence } from "./root-handle-gate";

/** True only after a successful Didit KYC for this member. Fails closed on read errors. */
export async function memberMayHoldRootHandle(userId: string): Promise<boolean> {
  try {
    const { sql } = await import("@/lib/neon");
    const { hasSchemaFeature } = await import("@/lib/schema-features.server");
    const attestations = (await hasSchemaFeature("0288"))
      ? ((await sql`select provider, evidence, has_legal_identity from public.verified_identity_nullifiers
           where user_id = ${userId}::uuid`) as DiditEvidence["attestations"])
      : [];
    const legacy = (await sql`select is_verified, verification_provider from public.identity_verifications
        where user_id = ${userId}::uuid limit 1`) as NonNullable<DiditEvidence["legacy"]>[];
    return rootHandleAllowed({ attestations, legacy: legacy[0] ?? null });
  } catch (error) {
    console.error("[root-handle-gate] read failed", error);
    return false;
  }
}
