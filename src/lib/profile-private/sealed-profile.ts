/**
 * A1 column mapping: plaintext profile values <-> the sealed columns of db/0287.
 *
 * For every private field `f` the database holds `f_sealed` (RPF1 ciphertext, field-seal.ts) and,
 * for indexed fields, `f_bidx` (HMAC-BLAKE3 blind index). A write always sets the plaintext column
 * to NULL, so no new plaintext ever reaches Neon; a read prefers the sealed value and only falls
 * back to the legacy plaintext column for rows the backfill has not reached yet.
 * Pure: the key ring is supplied by the caller (field-keys.server.ts on the server).
 */
import {
  blindIndex,
  FieldSealError,
  INDEX_ONLY_FIELDS,
  INDEXED_PROFILE_FIELDS,
  openProfileField,
  PRIVATE_PROFILE_FIELDS,
  sealedFieldVersion,
  sealProfileField,
  type IndexedProfileField,
  type IndexOnlyField,
  type PrivateProfileField,
} from "./field-seal";
import type { FieldKeyring } from "./field-keys";

export type ProfileFieldValues = Partial<Record<PrivateProfileField, string | null>>;
export type SealedPatch = Record<string, Uint8Array | null>;

const INDEXED: readonly string[] = INDEXED_PROFILE_FIELDS;
export const sealedColumn = (f: PrivateProfileField) => `${f}_sealed`;
export const bidxColumn = (f: IndexedProfileField | IndexOnlyField) => `${f}_bidx`;
export const isIndexed = (f: PrivateProfileField): f is IndexedProfileField => INDEXED.includes(f);

/** Every column 0287 adds, in a fixed order (used for select lists and the migration test). */
export const SEALED_COLUMNS: readonly string[] = [
  ...PRIVATE_PROFILE_FIELDS.map(sealedColumn),
  ...INDEXED_PROFILE_FIELDS.map(bidxColumn),
  ...INDEX_ONLY_FIELDS.map(bidxColumn),
];

function assertField(f: string): asserts f is PrivateProfileField {
  if (!(PRIVATE_PROFILE_FIELDS as readonly string[]).includes(f)) throw new FieldSealError();
}

/** The update payload for `values`: plaintext NULL, sealed value, blind index (all NULL for an empty value). */
export function sealProfilePatch(ring: FieldKeyring, profileId: string, values: ProfileFieldValues): SealedPatch {
  const out: Record<string, Uint8Array | null> = {};
  const version = ring.activeVersion;
  const master = ring.key(version);
  for (const [f, raw] of Object.entries(values)) {
    assertField(f);
    const value = raw === undefined || raw === null || raw === "" ? null : raw;
    out[f] = null;
    out[sealedColumn(f)] = value === null ? null : sealProfileField(master, version, f, profileId, value);
    if (isIndexed(f)) out[bidxColumn(f)] = value === null ? null : blindIndex(master, version, f, value);
  }
  return out as SealedPatch & Record<string, null>;
}

/** Blind index of an index-only secret (forwarding token) under the active version, for storage. */
export function indexOnlyValue(ring: FieldKeyring, field: IndexOnlyField, value: string | null): Uint8Array | null {
  if (value === null || value === "") return null;
  return blindIndex(ring.key(ring.activeVersion), ring.activeVersion, field, value);
}

const asBytes = (v: unknown): Uint8Array | null => (v instanceof Uint8Array && v.length > 0 ? v : null);

/** One field's plaintext: the sealed value when present (tampering throws), else the legacy column. */
export function openProfileValue(ring: FieldKeyring | null, profileId: string, field: PrivateProfileField, sealed: unknown, legacy: unknown): string | null {
  const blob = asBytes(sealed);
  if (blob) {
    if (!ring) throw new FieldSealError();
    return openProfileField(ring.key(sealedFieldVersion(blob)), field, profileId, blob);
  }
  return typeof legacy === "string" ? legacy : legacy === null || legacy === undefined ? null : String(legacy);
}

/**
 * Replaces each listed field of a row with its plaintext and drops the sealed/bidx columns, so the
 * caller sees exactly the shape it had before 0287.
 */
export function openProfileRow<T extends Record<string, unknown>>(ring: FieldKeyring | null, row: T, fields: readonly PrivateProfileField[], idKey = "id"): T {
  const id = String(row[idKey] ?? "");
  const out: Record<string, unknown> = { ...row };
  for (const f of fields) {
    out[f] = openProfileValue(ring, id, f, row[sealedColumn(f)], row[f]);
    delete out[sealedColumn(f)];
    if (isIndexed(f)) delete out[bidxColumn(f)];
  }
  return out as T;
}

/** The blind index of `value` under every key version present (a lookup matches any of them). */
export function indexCandidates(ring: FieldKeyring, field: IndexedProfileField | IndexOnlyField, value: string): Uint8Array[] {
  return ring.versions.map((v) => blindIndex(ring.key(v), v, field, value));
}

const HEX_BYTEA = /^\\x([0-9a-f]{2})*$/i;

/**
 * A profile row that went through to_jsonb() (export definer) carries bytea as "\x…" text.
 * Turns the sealed columns back into bytes so openProfileRow can use them; other keys are kept.
 */
export function sealedBytesFromJson<T extends Record<string, unknown>>(row: T): T {
  const out: Record<string, unknown> = { ...row };
  for (const c of SEALED_COLUMNS) {
    const v = out[c];
    if (typeof v === "string" && HEX_BYTEA.test(v)) {
      const hex = v.slice(2);
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
      out[c] = bytes;
    }
  }
  return out as T;
}

/** Drops every ciphertext and blind-index column, e.g. before showing an export to its owner. */
export function withoutSealedColumns<T extends Record<string, unknown>>(row: T): T {
  const out: Record<string, unknown> = { ...row };
  for (const c of SEALED_COLUMNS) delete out[c];
  return out as T;
}
