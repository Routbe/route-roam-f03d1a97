/**
 * A1 — application-level AEAD for private profile fields, plus blind indexes.
 *
 *   Seal   XChaCha20-Poly1305, one key per
 *          (column, key version) derived by HKDF-SHA-512 from the field master key, a fresh
 *          random 24-byte nonce per write. AAD binds magic, version, column and profile id,
 *          so a ciphertext copied to another member or another column never opens.
 *   Index  HMAC-BLAKE3 under a separate per-column index key (HKDF, other label), over the
 *          normalized value. Equality search without plaintext; a different column or key
 *          version gives an unrelated hash, so indexes never join across columns.
 *
 * Layout: "RPF1" | ver u8 | nonce 24 | ciphertext+tag (29 + 64k + 16 bytes, k >= 1). Plaintext is padded to 64-byte
 * buckets so the length of a VAT number or reason only leaks its bucket.
 * Every failure throws the same FieldSealError (no oracle). Derived keys are zeroed in finally.
 * Pure and browser-safe; key material is supplied by the caller (server: env, read per call).
 */
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";

/**
 * Profile columns stored only as RPF1 ciphertext once db/0287 is live. Free text and identifiers
 * the database never computes on. Flags and foreign keys the database itself enforces
 * (is_shadowbanned, referred_by) are not sealed but withheld behind definers instead: an AEAD'd
 * boolean either leaks through a deterministic index or stops the SQL that enforces it.
 */
export const PRIVATE_PROFILE_FIELDS = [
  "business_vat",
  "stripe_account_id",
  "payment_method",
  "moderation_reason",
  "moderated_by",
  "email",
  "forwarding_email",
  "legal_first_name",
  "legal_last_name",
  "last_city",
  "last_country",
] as const;
export type PrivateProfileField = (typeof PRIVATE_PROFILE_FIELDS)[number];

/** Columns that also carry a blind index for equality lookups (and how each value is canonicalised). */
export const INDEXED_PROFILE_FIELDS = ["business_vat", "stripe_account_id", "email", "forwarding_email"] as const;
export type IndexedProfileField = (typeof INDEXED_PROFILE_FIELDS)[number];
/** Index-only secrets: never stored in any readable form, only their blind index. */
export const INDEX_ONLY_FIELDS = ["forwarding_email_token"] as const;
export type IndexOnlyField = (typeof INDEX_ONLY_FIELDS)[number];
type BlindField = IndexedProfileField | IndexOnlyField;
const BLIND_FIELDS: readonly string[] = [...INDEXED_PROFILE_FIELDS, ...INDEX_ONLY_FIELDS];

const MAGIC = new Uint8Array([0x52, 0x50, 0x46, 0x31]); // "RPF1"
const NONCE = 24;
const HEAD = MAGIC.length + 1 + NONCE;
const BUCKET = 64;
const MAX_PLAINTEXT = 4096;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

export class FieldSealError extends Error {
  constructor() {
    super("profile_field_invalid");
    this.name = "FieldSealError";
  }
}

function assertInputs(master: Uint8Array, version: number, field: string, profileId: string) {
  if (!(master instanceof Uint8Array) || master.length < 32) throw new FieldSealError();
  if (!Number.isInteger(version) || version < 1 || version > 255) throw new FieldSealError();
  if (!(PRIVATE_PROFILE_FIELDS as readonly string[]).includes(field)) throw new FieldSealError();
  if (!UUID.test(profileId)) throw new FieldSealError();
}

function derive(master: Uint8Array, label: string, field: string, version: number): Uint8Array {
  return hkdf(sha512, master, enc.encode("rout.profile.v1"), enc.encode(`${label}|${field}|v${version}`), 32);
}

function aad(version: number, field: string, profileId: string): Uint8Array {
  return enc.encode(`rout.profile.private.v1|v${version}|${field}|${profileId}`);
}

function pad(p: Uint8Array): Uint8Array {
  const total = Math.ceil((p.length + 2) / BUCKET) * BUCKET;
  const out = new Uint8Array(total);
  out[0] = p.length >> 8;
  out[1] = p.length & 0xff;
  out.set(p, 2);
  return out;
}

function unpad(b: Uint8Array): Uint8Array {
  if (b.length < 2 || b.length % BUCKET !== 0) throw new FieldSealError();
  const n = (b[0]! << 8) | b[1]!;
  if (n + 2 > b.length) throw new FieldSealError();
  for (let i = n + 2; i < b.length; i++) if (b[i] !== 0) throw new FieldSealError();
  return b.slice(2, n + 2);
}

/** Encrypts one field value for one profile. */
export function sealProfileField(master: Uint8Array, version: number, field: PrivateProfileField, profileId: string, value: string | Uint8Array): Uint8Array {
  assertInputs(master, version, field, profileId);
  // Bytes are copied so the copy can be wiped here; the caller wipes its own buffer.
  const plain = typeof value === "string" ? enc.encode(value) : value.slice();
  if (plain.length > MAX_PLAINTEXT) throw new FieldSealError();
  const key = derive(master, "aead", field, version);
  const padded = pad(plain);
  try {
    const nonce = randomBytes(NONCE);
    const ct = xchacha20poly1305(key, nonce, aad(version, field, profileId)).encrypt(padded);
    const out = new Uint8Array(HEAD + ct.length);
    out.set(MAGIC, 0);
    out[4] = version;
    out.set(nonce, 5);
    out.set(ct, HEAD);
    return out;
  } finally {
    key.fill(0);
    padded.fill(0);
    plain.fill(0);
  }
}

/** Key version a sealed value was written under (for rotation), or throws. */
export function sealedFieldVersion(blob: Uint8Array): number {
  if (!(blob instanceof Uint8Array) || blob.length < HEAD + 16 + BUCKET) throw new FieldSealError();
  for (let i = 0; i < 4; i++) if (blob[i] !== MAGIC[i]) throw new FieldSealError();
  return blob[4]!;
}

/** Decrypts one field; any tampering, wrong field, wrong profile or wrong key throws. */
export function openProfileField(master: Uint8Array, field: PrivateProfileField, profileId: string, blob: Uint8Array): string {
  let version: number;
  try {
    version = sealedFieldVersion(blob);
    assertInputs(master, version, field, profileId);
  } catch {
    throw new FieldSealError();
  }
  const key = derive(master, "aead", field, version);
  let padded: Uint8Array | null = null;
  try {
    padded = xchacha20poly1305(key, blob.subarray(5, HEAD), aad(version, field, profileId)).decrypt(blob.subarray(HEAD));
    const plain = unpad(padded);
    try {
      return dec.decode(plain);
    } finally {
      plain.fill(0);
    }
  } catch {
    throw new FieldSealError();
  } finally {
    key.fill(0);
    padded?.fill(0);
  }
}

/**
 * Canonical form before indexing, per column, so equivalent spellings meet and distinct values never do:
 *   business_vat        NFKC, upper case, only A-Z and 0-9 ("BE 0123.456.789" = "be0123456789")
 *   email, forwarding   NFKC, trimmed, lower case (addresses are matched case-insensitively)
 *   stripe_account_id   trimmed only: Stripe ids are case-sensitive
 *   forwarding token    exact: an opaque random token
 */
export function normalizeForIndex(field: BlindField, value: string): string {
  switch (field) {
    case "business_vat":
      return value.normalize("NFKC").toUpperCase().replace(/[^A-Z0-9]/g, "");
    case "email":
    case "forwarding_email":
      return value.normalize("NFKC").trim().toLowerCase();
    case "stripe_account_id":
      return value.trim();
    case "forwarding_email_token":
      return value;
  }
}

/** HMAC-BLAKE3 blind index (32 bytes) of a normalized value for one column and key version. */
export function blindIndex(master: Uint8Array, version: number, field: BlindField, value: string): Uint8Array {
  if (!(master instanceof Uint8Array) || master.length < 32) throw new FieldSealError();
  if (!Number.isInteger(version) || version < 1 || version > 255) throw new FieldSealError();
  if (!BLIND_FIELDS.includes(field)) throw new FieldSealError();
  if (typeof value !== "string") throw new FieldSealError();
  const key = derive(master, "bidx", field, version);
  const msg = enc.encode(normalizeForIndex(field, value));
  try {
    return hmac(blake3, key, msg);
  } finally {
    key.fill(0);
    msg.fill(0);
  }
}
