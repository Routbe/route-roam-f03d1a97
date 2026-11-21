// @vitest-environment node
/**
 * Combined rollout of db/0287 (A1 field-level AEAD) and db/0288 (nullifier registry), both live on
 * Neon since 2026-11-17, on an offline replay of db/ up to 0286, recorded in schema_migrations
 * exactly as Neon had it before the GO.
 * Each file goes through the same one-transaction gateway batch as scripts/migration-rollout.ts
 * (ASCII-JSON transport, in-transaction SHA-256 check, predecessor check, definer guard).
 * The checksums are pinned to db-pending/ROLLOUT-0287-0288.md, the notes the owner gives the GO on:
 * a single changed byte in either file fails this test. Never touches Neon.
 */
import { PGlite } from "@electric-sql/pglite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { checksumOf, listMigrationFiles, planMigrations } from "../../scripts/migration-plan";
import { asciiJson, rolloutBatch, type RolloutQuery } from "../../scripts/migration-rollout";
import { guardedMigration, migrationDefinerGuardSql } from "../../scripts/security-definer-policy";

const ROOT = join(__dirname, "..", "..");
const DB = join(ROOT, "db");
const PENDING = join(ROOT, "db-pending");
const F0286 = "0286_fk_indexes_trigger_rights.sql";
const F0287 = "0287_profile_field_encryption.sql";
const F0288 = "0288_universal_identity_nullifiers.sql";
const body = (f: string) => readFileSync(join(f.endsWith("_rollback.sql") ? PENDING : DB, f), "utf8");
const NOTES = readFileSync(join(PENDING, "ROLLOUT-0287-0288.md"), "utf8");

/** sha256 values the notes name for a file (every occurrence must agree). */
const pinned = (file: string) => {
  const re = new RegExp(`${file.replace(/\./g, "\\.")}[^\\n]*?\`([0-9a-f]{64})\``, "g");
  return [...NOTES.matchAll(re)].map((m) => m[1]);
};

describe("combined rollout 0287 -> 0288 (offline)", () => {
  let db: PGlite;
  const run = async (queries: RolloutQuery[]) => {
    // Exactly what travels to the gateway: ASCII-only JSON, parsed back.
    const { queries: sent } = JSON.parse(asciiJson({ queries })) as { queries: RolloutQuery[] };
    await db.exec("begin");
    try {
      const out: Record<string, unknown>[][] = [];
      for (const q of sent) out.push((await db.query<Record<string, unknown>>(q.query, q.params)).rows);
      await db.exec("commit");
      return out;
    } catch (e) {
      await db.exec("rollback");
      throw e;
    }
  };

  beforeAll(async () => {
    const { btree_gist } = await import("@electric-sql/pglite/contrib/btree_gist");
    const { pgcrypto } = await import("@electric-sql/pglite/contrib/pgcrypto");
    db = await PGlite.create({ extensions: { pgcrypto, btree_gist } });
    const files = listMigrationFiles(DB).filter((f) => f < "0287");
    for (const step of planMigrations(files, new Set())) {
      if (step.action !== "run") continue;
      const guard = guardedMigration(step.file) ? `;\n${migrationDefinerGuardSql(step.file)}` : "";
      await db.exec(`begin;\n${readFileSync(join(DB, step.file), "utf8")}\n${guard};commit;`);
    }
    await db.exec("create table if not exists public.schema_migrations (filename text primary key, checksum text not null, applied_at timestamptz not null default now())");
    for (const f of files) await db.query("insert into public.schema_migrations (filename, checksum) values ($1, $2) on conflict do nothing", [f, checksumOf(readFileSync(join(DB, f), "utf8"))]);
  }, 600_000);
  afterAll(async () => db?.close());

  let fksBefore: string[] = [];
  const unindexedFks = async () =>
    (await db.query<{ fk: string }>(`
      select c.conrelid::regclass::text || '.' || c.conname as fk from pg_constraint c
       where c.contype = 'f' and c.connamespace in ('public'::regnamespace, 'vault_enclave'::regnamespace)
         and not exists (select 1 from pg_index i where i.indrelid = c.conrelid
               and (i.indkey::int2[])[0:cardinality(c.conkey) - 1] @> c.conkey
               and c.conkey @> (i.indkey::int2[])[0:cardinality(c.conkey) - 1])
       order by 1`)).rows.map((r) => r.fk);

  it("the notes pin the exact SHA-256 of both files and their rollbacks", () => {
    for (const f of [F0287, F0288, "0287_profile_field_encryption_rollback.sql", "0288_universal_identity_nullifiers_rollback.sql"]) {
      const sums = pinned(f);
      expect(sums.length, f).toBeGreaterThan(0);
      for (const s of sums) expect(s, f).toBe(checksumOf(body(f)));
    }
    expect(NOTES).toContain(`\`${checksumOf(readFileSync(join(DB, F0286), "utf8"))}\``);
  });

  it("0287 and 0288 are the two files right after 0286 in db/", async () => {
    fksBefore = await unindexedFks();
    const all = listMigrationFiles(DB);
    expect(all.slice(all.indexOf(F0286), all.indexOf(F0286) + 3)).toEqual([F0286, F0287, F0288]);
  });

  it("refuses 0288 before 0287 and a single changed byte, without running anything", async () => {
    await expect(run(rolloutBatch(F0288, F0287, body(F0288)))).rejects.toThrow(/predecessor/);
    const tampered = rolloutBatch(F0287, F0286, body(F0287));
    tampered[1] = { ...tampered[1]!, params: [F0287, F0286, `${body(F0287)} `, checksumOf(body(F0287))] };
    await expect(run(tampered)).rejects.toThrow(/does not match checksum/);
    const [r] = (await db.query<{ n: number }>("select count(*)::int as n from public.schema_migrations where filename in ($1, $2)", [F0287, F0288])).rows;
    expect(r!.n).toBe(0);
    const [t] = (await db.query<{ a: string | null; b: string | null }>("select to_regclass('vault_enclave.profile_field_keys')::text as a, to_regclass('public.verified_identity_nullifiers')::text as b")).rows;
    expect(t).toEqual({ a: null, b: null });
  });

  it("applies 0287 then 0288, each in one transaction, recording exactly the file checksum", async () => {
    const a = await run(rolloutBatch(F0287, F0286, body(F0287)));
    expect(a.at(-2)).toEqual([{ filename: F0287, checksum: checksumOf(body(F0287)) }]);
    const b = await run(rolloutBatch(F0288, F0287, body(F0288)));
    expect(b.at(-2)).toEqual([{ filename: F0288, checksum: checksumOf(body(F0288)) }]);
    await expect(run(rolloutBatch(F0287, F0286, body(F0287)))).rejects.toThrow(/already applied/);
  });

  it("leaves every SECURITY DEFINER on pg_catalog, pg_temp and add no unindexed foreign key", async () => {
    const bad = await db.query<{ f: string }>(`
      select p.oid::regprocedure::text as f from pg_proc p
       where p.prosecdef and p.pronamespace in ('public'::regnamespace, 'vault_enclave'::regnamespace)
         and not (coalesce(p.proconfig, '{}') @> array['search_path=pg_catalog, pg_temp'])`);
    expect(bad.rows.map((r) => r.f)).toEqual([]);
    const after = await unindexedFks();
    // public: none at all (0286). vault_enclave: 0287/0288 add none; the older ones are listed in the notes.
    expect(after.filter((f) => f.startsWith("public."))).toEqual([]);
    expect(after).toEqual(fksBefore);
  });

  it("both markers the app detects exist afterwards", async () => {
    const [r] = (await db.query<{ a: boolean; b: boolean }>(`select
      to_regprocedure('public.rout_profile_field_keys()') is not null as a,
      to_regprocedure('public.rout_kyc_attest(text,text[],text[],boolean,boolean,text)') is not null as b`)).rows;
    expect(r).toEqual({ a: true, b: true });
  });

  it("rolls back in reverse order (0288, then 0287) while empty", async () => {
    await db.exec(`begin;\n${body("0288_universal_identity_nullifiers_rollback.sql")}\n;commit;`);
    await db.exec(`begin;\n${body("0287_profile_field_encryption_rollback.sql")}\n;commit;`);
    const [t] = (await db.query<{ a: string | null; b: string | null }>("select to_regclass('vault_enclave.profile_field_keys')::text as a, to_regclass('public.verified_identity_nullifiers')::text as b")).rows;
    expect(t).toEqual({ a: null, b: null });
  });
});
