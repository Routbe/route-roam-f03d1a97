/**
 * Runtime detection of held-back EXPAND migrations, so code that already uses
 * them keeps working on a database that is one migration behind (deploy order
 * free). A positive answer is cached for the isolate; a negative one for a minute.
 * Remove a detector together with its legacy path once the CONTRACT is in db/.
 */
import { sql } from "@/lib/neon";

const MARKERS = {
  /** db-pending/0276_tenant_column_expand.sql */
  "0276": "public.rout_profile_private_mine()",
  /** db/0287_profile_field_encryption.sql (A1 sealed profile fields) */
  "0287": "public.rout_profile_field_keys()",
  /** db/0288_universal_identity_nullifiers.sql (cross-provider identity anchors) */
  "0288": "public.rout_kyc_attest(text,text[],text[],boolean,boolean,text)",
  /** db/0290_identity_os_sign.sql (identity OS claims, IBAN via KYC, ROUT Sign) */
  "0290": "public.rout_my_identity_claims()",
  /** db/0291_age_floor_zero_dob.sql (whole-year age floor, no stored date of birth) */
  "0291": "public.rout_my_age_floor()",
  /** db/0292_public_owner_minor.sql (under-18 check for the public blue-mark card) */
  "0292": "public.rout_public_owner_is_minor(uuid)",
  /** db/0293_support_treasury.sql (support treasury, supporter credentials, partner attestations) */
  "0293": "public.rout_support_create(smallint,text,integer,text,text)",
  /** db/0294_eudi_wallet.sql (OID4VCI offers, wallet credential status list, OID4VP requests) */
  "0294": "public.rout_vci_offer_create(text,text,text)",
  /** db/0295_dpop_jti_replays.sql (DPoP jti replay ledger shared by every server instance) */
  "0295": "public.rout_dpop_jti_claim(text,integer)",
  "0296": "public.rout_identity_records_purge(uuid)",
  /** db/0298_handle_registry_dual_profile.sql (handle registry, dual-profile claim) */
  "0298": "public.rout_claim_verified_root_handle(text,boolean,boolean)",
  /** db-pending/0299_handle_namespace_contract.sql (root policy + alias cooldown guards) */
  "0299": "public.rout_enforce_alias_rename_cooldown()",
} as const;
export type SchemaFeature = keyof typeof MARKERS;

const cache = new Map<SchemaFeature, { ok: boolean; at: number }>();
const NEGATIVE_TTL_MS = 60_000;

export async function hasSchemaFeature(feature: SchemaFeature): Promise<boolean> {
  const hit = cache.get(feature);
  if (hit && (hit.ok || Date.now() - hit.at < NEGATIVE_TTL_MS)) return hit.ok;
  try {
    const rows = (await sql`select pg_catalog.to_regprocedure(${MARKERS[feature]}) is not null as ok`) as { ok: boolean }[];
    const ok = rows[0]?.ok === true;
    cache.set(feature, { ok, at: Date.now() });
    return ok;
  } catch {
    return false;
  }
}

/** Test hook: forget cached answers. */
export function resetSchemaFeatures() {
  cache.clear();
}
