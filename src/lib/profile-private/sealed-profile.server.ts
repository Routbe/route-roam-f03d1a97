/**
 * A1 facade for every module that writes or reads a private profile field.
 *
 * Before db/0287 is live these helpers behave exactly like the legacy plaintext columns,
 * so the code can be deployed before the migration (deploy order free). Once it is live:
 * writes carry only ciphertext and blind indexes, reads decrypt in this process, and lookups
 * compare blind indexes. Plaintext never goes back into Neon.
 */
import { hasSchemaFeature } from "@/lib/schema-features.server";
import type { IndexedProfileField, IndexOnlyField, PrivateProfileField } from "./field-seal";
import { withProfileFieldKeys } from "./field-keys.server";
import { bidxColumn, indexCandidates, indexOnlyValue, isIndexed, openProfileRow, sealedColumn, sealProfilePatch, type ProfileFieldValues } from "./sealed-profile";

export { type ProfileFieldValues } from "./sealed-profile";

/** True once the sealed columns exist. */
export function profileSealingLive(): Promise<boolean> {
  return hasSchemaFeature("0287");
}

/** Columns to merge into an update/insert of public.profiles for these private values. */
export async function profileFieldPatch(profileId: string, values: ProfileFieldValues): Promise<Record<string, unknown>> {
  if (!(await profileSealingLive())) return { ...values };
  return withProfileFieldKeys((ring) => sealProfilePatch(ring!, profileId, values), { create: true });
}

/** Columns that store an index-only secret (the forwarding token): its blind index, plaintext NULL. */
export async function indexOnlyPatch(field: IndexOnlyField, value: string | null): Promise<Record<string, unknown>> {
  if (!(await profileSealingLive())) return { [field]: value };
  return withProfileFieldKeys((ring) => ({ [field]: null, [bidxColumn(field)]: indexOnlyValue(ring!, field, value) }), { create: true });
}

/** Extra select-list items for these fields (", f_sealed, ..."), empty before 0287. Constant text, never input. */
export async function sealedSelectList(fields: readonly PrivateProfileField[], alias = ""): Promise<string> {
  if (!fields.length || !(await profileSealingLive())) return "";
  const p = alias ? `${alias}.` : "";
  return fields.map((f) => `, ${p}${sealedColumn(f)}`).join("");
}

/** Decrypts the listed fields of every row in place of their plaintext columns. */
export async function openProfileRows<T extends Record<string, unknown>>(rows: T[], fields: readonly PrivateProfileField[], idKey = "id"): Promise<T[]> {
  if (!rows.length || !fields.length || !(await profileSealingLive())) return rows;
  const anySealed = rows.some((r) => fields.some((f) => r[sealedColumn(f)] instanceof Uint8Array));
  if (!anySealed) return rows.map((r) => openProfileRow(null, r, fields, idKey));
  return withProfileFieldKeys((ring) => rows.map((r) => openProfileRow(ring, r, fields, idKey)));
}

/** One row (or null). */
export async function openProfileRowOne<T extends Record<string, unknown>>(row: T | null | undefined, fields: readonly PrivateProfileField[], idKey = "id"): Promise<T | null> {
  if (!row) return null;
  return (await openProfileRows([row], fields, idKey))[0] ?? null;
}

/**
 * Blind indexes to match `value` against, one per key version; null before 0287 (callers then
 * compare the legacy column) and [] when no key exists yet (nothing can be sealed, nothing matches).
 */
export async function profileLookupIndexes(field: IndexedProfileField | IndexOnlyField, value: string): Promise<Uint8Array[] | null> {
  if (!(await profileSealingLive())) return null;
  return withProfileFieldKeys((ring) => (ring ? indexCandidates(ring, field, value) : []));
}

export { bidxColumn, isIndexed, sealedColumn };

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/**
 * Lookup indexes as hex strings, to pass as text[] and decode in SQL:
 *   where f_bidx = any(array(select pg_catalog.decode(h, 'hex') from unnest($1::text[]) h))
 * null before 0287 (compare the legacy column instead).
 */
export async function profileLookupHex(field: IndexedProfileField | IndexOnlyField, value: string): Promise<string[] | null> {
  const idx = await profileLookupIndexes(field, value);
  return idx ? idx.map(toHex) : null;
}

const COLUMN_NAME = /^[a-z][a-z_]{1,40}$/;

/**
 * Writes private fields of one profile in their own UPDATE (sealed once 0287 is live, plaintext
 * before). Column names come only from the fixed field list; values are always parameters.
 */
export async function writeProfilePrivateFields(profileId: string, values: ProfileFieldValues): Promise<void> {
  const patch = await profileFieldPatch(profileId, values);
  const cols = Object.keys(patch);
  if (!cols.length) return;
  if (!cols.every((c) => COLUMN_NAME.test(c))) throw new Error("profile_field_column_invalid");
  const { sql } = await import("@/lib/neon");
  const text = `update public.profiles set ${cols.map((c, i) => `${c} = $${i + 2}`).join(", ")}, updated_at = now() where id = $1`;
  await sql.query(text, [profileId, ...cols.map((c) => patch[c] ?? null)]);
}

/**
 * Private fields of several profiles, opened server-side. Only for callers that already
 * authorised the read (admin screens); reads legacy plaintext before 0287.
 */
export async function readProfileFieldsByIds<F extends PrivateProfileField>(
  ids: readonly string[],
  fields: readonly F[],
): Promise<Record<string, Partial<Record<F, string | null>>>> {
  if (!ids.length || !fields.length) return {};
  const { dbAdmin } = await import("@/lib/db/admin.server");
  const live = await profileSealingLive();
  const cols = ["id", ...(live ? fields.map((f) => sealedColumn(f)) : fields)].join(", ");
  const { data, error } = await dbAdmin.from("profiles").select(cols).in("id", [...ids]);
  if (error) throw new Error(error.message);
  const opened = await openProfileRows((data ?? []) as unknown as Array<Record<string, unknown> & { id: string }>, fields);
  const out: Record<string, Partial<Record<F, string | null>>> = {};
  for (const row of opened) {
    const r = row as Record<string, unknown>;
    out[String(r["id"])] = Object.fromEntries(fields.map((f) => [f, (r[f] as string | null | undefined) ?? null])) as Partial<Record<F, string | null>>;
  }
  return out;
}
