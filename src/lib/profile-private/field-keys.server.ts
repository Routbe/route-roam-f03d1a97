/**
 * Server side of the A1 key ring: reads the wrapped key versions through the db/0287
 * definers, unwraps them under ROUT_VAULT_KEK (read per call, never at module scope) and wipes
 * every key when the callback returns. The first version is created on first use; later versions
 * (rotation) are an owner operation (scripts/a1-field-keys.ts), never done by the app role.
 */
import { sql } from "@/lib/neon";
import { deriveFieldKek, generateFieldKey, openFieldKeyring, type FieldKeyring, type StoredFieldKey } from "./field-keys";

export class FieldKekMissingError extends Error {
  constructor() {
    super("profile_field_kek_missing");
    this.name = "FieldKekMissingError";
  }
}

type KeyRow = { version: number; kid: Uint8Array; wrapped_key: Uint8Array; kek_id: Uint8Array; active: boolean };

const toStored = (r: KeyRow): StoredFieldKey => ({
  version: Number(r.version),
  kid: new Uint8Array(r.kid),
  wrapped: new Uint8Array(r.wrapped_key),
  kekId: new Uint8Array(r.kek_id),
  active: r.active === true,
});

async function readStored(): Promise<StoredFieldKey[]> {
  const rows = (await sql`select version, kid, wrapped_key, kek_id, active from public.rout_profile_field_keys()`) as KeyRow[];
  return rows.map(toStored);
}

/**
 * Runs `use` with the opened key ring. With `create`, a database without any key gets version 1
 * (registered through the definer, which only ever accepts a first key); without it, `use` gets
 * null so readers of legacy rows keep working before the first sealed write.
 */
export async function withProfileFieldKeys<T>(use: (ring: FieldKeyring | null) => T | Promise<T>, opts: { create?: boolean } = {}): Promise<T> {
  const secret = process.env["ROUT_VAULT_KEK"];
  if (!secret) throw new FieldKekMissingError();
  const kek = deriveFieldKek(secret);
  let ring: FieldKeyring | null = null;
  try {
    let stored = await readStored();
    if (stored.length === 0 && opts.create) {
      const fresh = generateFieldKey(kek, 1);
      fresh.key.fill(0);
      const s = fresh.stored;
      await sql`select public.rout_profile_field_key_register(${s.kid}, ${s.wrapped}, ${s.kekId})`;
      stored = await readStored();
    }
    if (stored.length === 0) return await use(null);
    ring = openFieldKeyring(kek, stored);
    return await use(ring);
  } finally {
    ring?.dispose();
    kek.dispose();
  }
}
