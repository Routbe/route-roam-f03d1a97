/**
 * A1 backfill: seals legacy plaintext in BACKFILL_FIELDS and sets the plaintext column to NULL.
 * Only after the owner's "GO A1" and once db/0287 is applied.
 *   bun scripts/a1-backfill.ts            dry run: counts rows still holding plaintext, writes nothing
 *   bun scripts/a1-backfill.ts --apply    seals in batches of 200, one transaction per batch
 * Needs ROUT_VAULT_KEK and MIGRATION_URL (owner) or DATABASE_URL. Never registers a key: the first
 * key version comes from the app (rout_profile_field_key_register) or is refused here.
 */
import { closeDirect, sqlRequest } from "./db-direct";
import { deriveFieldKek, openFieldKeyring, type StoredFieldKey } from "../src/lib/profile-private/field-keys";
import { backfillSelect, backfillStatements } from "../src/lib/profile-private/backfill-plan";

const apply = process.argv.includes("--apply");
const BATCH = 200;
const bytes = (v: unknown) => (v instanceof Uint8Array ? v : new Uint8Array(Buffer.from(String(v).replace(/^\\x/, ""), "hex")));

async function main() {
  const marker = await sqlRequest({ query: "select to_regclass('vault_enclave.profile_field_keys') is not null as ok" });
  if (marker.rows[0]?.["ok"] !== true) throw new Error("0287 is not applied: nothing to backfill");
  const pending = async () => Number((await sqlRequest(backfillSelect(1_000_000))).rows.length);
  if (!apply) {
    console.log(`[a1-backfill] dry run: ${await pending()} profile rows still hold plaintext in a sealed field`);
    return;
  }
  const secret = process.env["ROUT_VAULT_KEK"];
  if (!secret) throw new Error("ROUT_VAULT_KEK missing");
  const keys = (await sqlRequest({ query: "select version, kid, wrapped_key, kek_id, active from public.rout_profile_field_keys()" })).rows;
  if (!keys.length) throw new Error("no field key registered yet: let the app register version 1 first");
  const stored: StoredFieldKey[] = keys.map((k) => ({ version: Number(k["version"]), kid: bytes(k["kid"]), wrapped: bytes(k["wrapped_key"]), kekId: bytes(k["kek_id"]), active: k["active"] === true }));
  const kek = deriveFieldKek(secret);
  const ring = openFieldKeyring(kek, stored);
  try {
    let total = 0;
    for (;;) {
      const rows = (await sqlRequest(backfillSelect(BATCH))).rows;
      if (!rows.length) break;
      const queries = backfillStatements(ring, rows);
      const { results } = await sqlRequest({ queries });
      const changed = results.reduce((n, r) => n + (r.rowCount ?? 0), 0);
      total += changed;
      console.log(`[a1-backfill] batch: ${rows.length} rows, ${changed} fields sealed (total ${total})`);
      if (changed === 0) throw new Error("no progress in a batch (concurrent writes?): stop and re-run");
    }
    console.log(`[a1-backfill] done: ${total} fields sealed, ${await pending()} rows remaining`);
  } finally {
    ring.dispose();
    kek.dispose();
  }
}

main().then(closeDirect, async (e) => { console.error("[a1-backfill]", e instanceof Error ? e.message : e); await closeDirect(); process.exit(1); });
