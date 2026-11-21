/**
 * Sealed legal name (server-only). Didit's document name is written only as RPF1 ciphertext into
 * profiles.legal_first_name_sealed / legal_last_name_sealed (db/0287 columns, key ring wrapped by
 * ROUT_VAULT_KEK), in the member's own context; plaintext never reaches Neon. For IBAN holder checks the name is opened in this process only,
 * compared, and dropped: callers get a boolean, never the name. The one exception is
 * openPublicLegalName: the owner-approved blue-mark card of a KYC-attested root profile.
 */
import { Buffer } from "node:buffer";
import { holderMatchesLegalName } from "./legal-name-match";

const FIELDS = ["legal_first_name", "legal_last_name"] as const;

async function live(): Promise<boolean> {
  const { hasSchemaFeature } = await import("@/lib/schema-features.server");
  return (await hasSchemaFeature("0287")) && (await hasSchemaFeature("0290"));
}

/**
 * Seals the member's document name (UTF-8 bytes) into profiles.legal_first_name_sealed /
 * legal_last_name_sealed: XChaCha20-Poly1305 under the profile field key, which exists in Neon
 * only wrapped by ROUT_VAULT_KEK (db/0287). The plaintext columns are set to NULL in the same
 * update. Runs in the member's own RLS context (rout_owner policy). The caller wipes the input
 * buffers; the copies made here are wiped by sealProfileField. False (nothing written) before 0287.
 */
export async function storeSealedLegalName(userId: string, name: { first: Uint8Array; last: Uint8Array }): Promise<boolean> {
  const { hasSchemaFeature } = await import("@/lib/schema-features.server");
  if (!(await hasSchemaFeature("0287"))) return false;
  if (!name.first.length || !name.last.length) return false;
  if (!process.env["ROUT_VAULT_KEK"]) {
    // Not configured: the verification itself must not fail over it; the card then shows no name.
    console.warn("[kyc] legal name not sealed: ROUT_VAULT_KEK missing");
    return false;
  }
  const { withProfileFieldKeys } = await import("@/lib/profile-private/field-keys.server");
  const { sealProfileField } = await import("@/lib/profile-private/field-seal");
  const sealed = await withProfileFieldKeys((ring) => {
    if (!ring) throw new Error("legal_name_seal_failed");
    const v = ring.activeVersion;
    const master = ring.key(v);
    return { first: sealProfileField(master, v, "legal_first_name", userId, name.first), last: sealProfileField(master, v, "legal_last_name", userId, name.last) };
  }, { create: true });
  const { sql } = await import("@/lib/neon");
  const rows = (await sql`update public.profiles
      set legal_first_name = null, legal_last_name = null,
          legal_first_name_sealed = ${Buffer.from(sealed.first)}, legal_last_name_sealed = ${Buffer.from(sealed.last)},
          updated_at = now()
    where id = ${userId}::uuid returning id`) as { id: string }[];
  if (!rows[0]) throw new Error("legal_name_store_no_profile");
  return true;
}

/** Opens a sealed pair in memory and compares it with the account holder; the name never leaves. */
export async function holderMatchesSealed(profileId: string, sealed: { first: unknown; last: unknown }, holder: string): Promise<boolean> {
  if (!(sealed.first instanceof Uint8Array) || !(sealed.last instanceof Uint8Array)) return false;
  const { withProfileFieldKeys } = await import("@/lib/profile-private/field-keys.server");
  const { openProfileRow } = await import("@/lib/profile-private/sealed-profile");
  return withProfileFieldKeys((ring) => {
    if (!ring) return false;
    let opened: Record<string, unknown> | null = openProfileRow(ring, { id: profileId, legal_first_name_sealed: sealed.first, legal_last_name_sealed: sealed.last }, FIELDS);
    try {
      return holderMatchesLegalName(holder, { first: (opened["legal_first_name"] as string | null) ?? null, last: (opened["legal_last_name"] as string | null) ?? null });
    } finally {
      opened = null;
    }
  });
}

/** The caller's own sealed legal name vs. a holder name (personal tip page). False before 0290 or without a sealed name. */
export async function myHolderMatchesSealedName(userId: string, holder: string): Promise<boolean> {
  if (!(await live())) return false;
  const { sql } = await import("@/lib/neon");
  const [row] = (await sql`select first_sealed, last_sealed from public.rout_my_sealed_legal_name()`) as { first_sealed: unknown; last_sealed: unknown }[];
  if (!row) return false;
  return holderMatchesSealed(userId, { first: row.first_sealed, last: row.last_sealed }, holder);
}

/** A workspace owner's sealed legal name vs. a holder name (manager-only definer). */
export async function workspaceOwnerHolderMatches(workspaceId: string, holder: string): Promise<boolean> {
  if (!(await live())) return false;
  const { sql } = await import("@/lib/neon");
  const rows = (await sql`select owner_id, first_sealed, last_sealed from public.rout_ws_support_owner_sealed_name(${workspaceId}::uuid)`) as { owner_id: string; first_sealed: unknown; last_sealed: unknown }[];
  for (const r of rows) if (await holderMatchesSealed(r.owner_id, { first: r.first_sealed, last: r.last_sealed }, holder)) return true;
  return false;
}

/**
 * The sealed legal name for the public blue-mark card (owner directive 2026-11-18), opened in
 * this process only. Callers: readPublicProfile, after the KYC mark and the privacy shield allow
 * names; the minor firewall is applied by the caller. Null before 0287/0290, without a sealed
 * pair, without ROUT_VAULT_KEK or on any failure.
 */
export async function openPublicLegalName(profileId: string): Promise<string | null> {
  try {
    if (!(await live())) return null;
    const { sql } = await import("@/lib/neon");
    const [row] = (await sql`select legal_first_name_sealed as f, legal_last_name_sealed as l
        from public.profiles where id = ${profileId}::uuid limit 1`) as { f: unknown; l: unknown }[];
    if (!(row?.f instanceof Uint8Array) || !(row?.l instanceof Uint8Array)) return null;
    const { withProfileFieldKeys } = await import("@/lib/profile-private/field-keys.server");
    const { openProfileRow } = await import("@/lib/profile-private/sealed-profile");
    return await withProfileFieldKeys((ring) => {
      if (!ring) return null;
      const opened = openProfileRow(ring, { id: profileId, legal_first_name_sealed: row.f, legal_last_name_sealed: row.l }, FIELDS);
      const first = String(opened["legal_first_name"] ?? "").trim();
      const last = String(opened["legal_last_name"] ?? "").trim();
      return `${first} ${last}`.trim() || null;
    });
  } catch (error) {
    console.warn("[legal-name:public:skipped]", error instanceof Error ? error.name : "error");
    return null;
  }
}

/**
 * The caller's own sealed legal name as separate first/last parts, opened in this process only and
 * handed to `use` (owner directive Prioriteit 3: the verified root handle is chosen from variants of
 * the Didit name and re-validated against it). `use` must return derived values (handle variants),
 * never the name; the opened strings are dropped after it returns. Null before 0287, without a
 * sealed pair, without ROUT_VAULT_KEK or on any failure.
 */
export async function withOwnLegalNameParts<T>(
  userId: string,
  use: (name: { first: string; last: string }) => T,
): Promise<T | null> {
  try {
    const { hasSchemaFeature } = await import("@/lib/schema-features.server");
    if (!(await hasSchemaFeature("0287"))) return null;
    const { sql } = await import("@/lib/neon");
    const [row] = (await sql`select legal_first_name_sealed as f, legal_last_name_sealed as l
        from public.profiles where id = ${userId}::uuid limit 1`) as { f: unknown; l: unknown }[];
    if (!(row?.f instanceof Uint8Array) || !(row?.l instanceof Uint8Array)) return null;
    const { withProfileFieldKeys } = await import("@/lib/profile-private/field-keys.server");
    const { openProfileRow } = await import("@/lib/profile-private/sealed-profile");
    return await withProfileFieldKeys((ring) => {
      if (!ring) return null;
      let opened: Record<string, unknown> | null = openProfileRow(ring, { id: userId, legal_first_name_sealed: row.f, legal_last_name_sealed: row.l }, FIELDS);
      try {
        const first = String(opened["legal_first_name"] ?? "").trim();
        const last = String(opened["legal_last_name"] ?? "").trim();
        if (!first || !last) return null;
        return use({ first, last });
      } finally {
        opened = null;
      }
    });
  } catch (error) {
    console.warn("[legal-name:own:skipped]", error instanceof Error ? error.name : "error");
    return null;
  }
}
