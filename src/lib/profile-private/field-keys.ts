/**
 * A1 key ring for sealed profile fields.
 *
 * Each key version is a random 32-byte field master key (the input to field-seal.ts). It is
 * stored in vault_enclave.profile_field_keys (db/0287) ONLY wrapped with AES-256-GCM
 * under a key derived from ROUT_VAULT_KEK, which lives in the server environment and never in
 * the database. A database dump alone opens no field and the environment alone holds no data.
 *
 *   wrap = "RFK1" || kekId(16) || nonce(12) || AES-256-GCM(key 32) + tag(16)   = 80 bytes
 *   AAD  = "rout.profile.field-key.v1" || kekId || version(u8) || kid(16)
 *
 * The wrapping key and the KEK id come from HKDF-SHA-256 under labels of their own, so this
 * wrap is domain-separated from the server-vault seed wrap (server-kek.ts) although both use
 * the same environment secret. A wrap that does not authenticate (forged row, other KEK,
 * swapped version or kid) fails closed: the whole ring refuses to open. Every failure is the
 * same FieldKeyError. Callers dispose the ring; disposal zero-fills every unwrapped key.
 */
import { gcm } from "@noble/ciphers/aes.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";

const KEK_SECRET_RE = /^[A-Za-z0-9]{64,512}$/;
const MAGIC = Uint8Array.of(0x52, 0x46, 0x4b, 0x31); // "RFK1"
const KEK_ID_LEN = 16;
const KID_LEN = 16;
const NONCE_LEN = 12;
const KEY_LEN = 32;
const TAG_LEN = 16;
export const WRAPPED_FIELD_KEY_BYTES = MAGIC.length + KEK_ID_LEN + NONCE_LEN + KEY_LEN + TAG_LEN; // 80
export const MAX_FIELD_KEY_VERSION = 255;

const enc = new TextEncoder();
const SALT = enc.encode("rout.profile.field-kek.v1");
const AAD_LABEL = enc.encode("rout.profile.field-key.v1");

export class FieldKeyError extends Error {
  constructor() {
    super("profile_field_key_invalid");
    this.name = "FieldKeyError";
  }
}

export type FieldKek = {
  readonly kekId: Uint8Array;
  wrap(version: number, kid: Uint8Array, key: Uint8Array): Uint8Array;
  unwrap(version: number, kid: Uint8Array, wrapped: Uint8Array): Uint8Array;
  dispose(): void;
};

/** A stored, still wrapped key version as the database returns it. */
export type StoredFieldKey = { version: number; kid: Uint8Array; wrapped: Uint8Array; kekId: Uint8Array; active: boolean };

export type FieldKeyring = {
  /** Version new values are sealed and indexed under. */
  readonly activeVersion: number;
  /** Every version present, newest first (lookups compute one index per version). */
  readonly versions: readonly number[];
  /** The unwrapped master key of one version; throws for an unknown version or after dispose. */
  key(version: number): Uint8Array;
  dispose(): void;
};

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return d === 0;
}

function validVersion(version: number): boolean {
  return Number.isInteger(version) && version >= 1 && version <= MAX_FIELD_KEY_VERSION;
}

function aad(kekId: Uint8Array, version: number, kid: Uint8Array): Uint8Array {
  const out = new Uint8Array(AAD_LABEL.length + KEK_ID_LEN + 1 + KID_LEN);
  out.set(AAD_LABEL);
  out.set(kekId, AAD_LABEL.length);
  out[AAD_LABEL.length + KEK_ID_LEN] = version;
  out.set(kid, AAD_LABEL.length + KEK_ID_LEN + 1);
  return out;
}

/** Derives the field-key wrapping KEK from the environment secret (same format as ROUT_VAULT_KEK). */
export function deriveFieldKek(secret: string): FieldKek {
  if (typeof secret !== "string" || !KEK_SECRET_RE.test(secret)) throw new FieldKeyError();
  const ikm = enc.encode(secret);
  const key = hkdf(sha256, ikm, SALT, enc.encode("aes-256-gcm.profile-field-key-wrap"), 32);
  const kekId = hkdf(sha256, ikm, SALT, enc.encode("kek-id"), KEK_ID_LEN);
  ikm.fill(0);
  let disposed = false;
  const live = () => {
    if (disposed) throw new FieldKeyError();
  };
  return {
    kekId,
    wrap(version, kid, fieldKey) {
      live();
      if (!validVersion(version) || kid.length !== KID_LEN || fieldKey.length !== KEY_LEN) throw new FieldKeyError();
      const nonce = randomBytes(NONCE_LEN);
      const body = gcm(key, nonce, aad(kekId, version, kid)).encrypt(fieldKey);
      const out = new Uint8Array(WRAPPED_FIELD_KEY_BYTES);
      out.set(MAGIC, 0);
      out.set(kekId, 4);
      out.set(nonce, 4 + KEK_ID_LEN);
      out.set(body, 4 + KEK_ID_LEN + NONCE_LEN);
      body.fill(0);
      return out;
    },
    unwrap(version, kid, wrapped) {
      live();
      try {
        if (!validVersion(version) || kid.length !== KID_LEN || wrapped.length !== WRAPPED_FIELD_KEY_BYTES) throw new FieldKeyError();
        if (!equal(wrapped.subarray(0, 4), MAGIC) || !equal(wrapped.subarray(4, 4 + KEK_ID_LEN), kekId)) throw new FieldKeyError();
        const nonce = wrapped.subarray(4 + KEK_ID_LEN, 4 + KEK_ID_LEN + NONCE_LEN);
        const view = gcm(key, nonce, aad(kekId, version, kid)).decrypt(wrapped.subarray(4 + KEK_ID_LEN + NONCE_LEN));
        const out = view.slice();
        view.fill(0);
        return out;
      } catch {
        throw new FieldKeyError();
      }
    },
    dispose() {
      disposed = true;
      key.fill(0);
    },
  };
}

/** A fresh key version, wrapped for storage. The caller wipes `key` once it no longer needs it. */
export function generateFieldKey(kek: FieldKek, version: number): { stored: StoredFieldKey; key: Uint8Array } {
  if (!validVersion(version)) throw new FieldKeyError();
  const key = randomBytes(KEY_LEN);
  const kid = randomBytes(KID_LEN);
  return { key, stored: { version, kid, wrapped: kek.wrap(version, kid, key), kekId: kek.kekId.slice(), active: true } };
}

/**
 * Opens every stored version. Fails closed when any wrap does not authenticate, when no version
 * or more than one version is active, or when the active version is not the newest one.
 */
export function openFieldKeyring(kek: FieldKek, stored: readonly StoredFieldKey[]): FieldKeyring {
  const keys = new Map<number, Uint8Array>();
  const wipe = () => {
    for (const k of keys.values()) k.fill(0);
    keys.clear();
  };
  try {
    const active = stored.filter((s) => s.active);
    if (stored.length === 0 || active.length !== 1) throw new FieldKeyError();
    for (const s of stored) {
      if (!validVersion(s.version) || keys.has(s.version) || !equal(s.kekId, kek.kekId)) throw new FieldKeyError();
      keys.set(s.version, kek.unwrap(s.version, s.kid, s.wrapped));
    }
    const versions = [...keys.keys()].sort((a, b) => b - a);
    const activeVersion = active[0]!.version;
    if (activeVersion !== versions[0]) throw new FieldKeyError();
    let disposed = false;
    return {
      activeVersion,
      versions,
      key(version) {
        const k = keys.get(version);
        if (disposed || !k) throw new FieldKeyError();
        return k;
      },
      dispose() {
        disposed = true;
        wipe();
      },
    };
  } catch {
    wipe();
    throw new FieldKeyError();
  }
}
