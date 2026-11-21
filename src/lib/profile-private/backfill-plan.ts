/**
 * A1 backfill planner (pure; run by scripts/a1-backfill.ts after the owner's "GO A1").
 * For each legacy row it builds one UPDATE that writes the sealed value and blind index and sets
 * the plaintext column to NULL, guarded by `plaintext is not distinct from <value read>` so a
 * concurrent app write is never overwritten (that row is simply picked up by the next batch).
 * Bytes travel as hex text and are decoded in SQL, so no driver-specific bytea handling matters.
 */
import type { FieldKeyring } from "./field-keys";
import type { PrivateProfileField } from "./field-seal";
import { sealedColumn, sealProfilePatch } from "./sealed-profile";

/**
 * Fields whose every reader and writer already uses the sealed columns. Only these are backfilled;
 * a field is added here in the same change that moves its last plaintext reader.
 */
export const BACKFILL_FIELDS = ["business_vat", "stripe_account_id", "payment_method", "moderation_reason", "moderated_by"] as const satisfies readonly PrivateProfileField[];
export type BackfillField = (typeof BACKFILL_FIELDS)[number];

export type BackfillStatement = { query: string; params: unknown[] };
const IDENT = /^[a-z][a-z_]{1,40}$/;
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** Selects up to `limit` rows that still hold plaintext in a backfill field and nothing sealed for it. */
export function backfillSelect(limit: number): BackfillStatement {
  const where = BACKFILL_FIELDS.map((f) => `(${f} is not null and ${sealedColumn(f)} is null)`).join(" or ");
  return { query: `select id, ${BACKFILL_FIELDS.join(", ")} from public.profiles where ${where} order by id limit $1`, params: [limit] };
}

export function backfillStatements(ring: FieldKeyring, rows: ReadonlyArray<Record<string, unknown>>): BackfillStatement[] {
  const out: BackfillStatement[] = [];
  for (const row of rows) {
    const id = String(row["id"]);
    for (const f of BACKFILL_FIELDS) {
      const raw = row[f];
      if (raw === null || raw === undefined) continue;
      const value = String(raw);
      const patch = sealProfilePatch(ring, id, { [f]: value });
      const params: unknown[] = [id, value];
      const sets: string[] = [`${f} = null`];
      for (const [col, v] of Object.entries(patch)) {
        if (col === f) continue;
        if (!IDENT.test(col)) throw new Error("backfill_column_invalid");
        params.push(v instanceof Uint8Array ? hex(v) : null);
        sets.push(`${col} = pg_catalog.decode($${params.length}, 'hex')`);
      }
      // ::text on both sides: moderated_by is a uuid, the rest are text.
      out.push({ query: `update public.profiles set ${sets.join(", ")} where id = $1::uuid and ${f}::text is not distinct from $2`, params });
    }
  }
  return out;
}
