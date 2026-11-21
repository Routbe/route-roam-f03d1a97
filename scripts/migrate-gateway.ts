/**
 * Applies pending db/NN_*.sql files through the Lovable Neon connector gateway
 * (MIGRATION_URL, else DATABASE_URL; direct TLS), tracked in public.schema_migrations.
 * Each file is sent as one batch statement => one transaction. From 0255 on the
 * file is linted and the batch ends with the SECURITY DEFINER guard, so a
 * function without search_path = pg_catalog rolls the whole file back.
 *
 *   bun scripts/migrate-gateway.ts            apply pending
 *   bun scripts/migrate-gateway.ts --dry-run  list pending
 */
import { closeDirect, sqlRequest } from "./db-direct";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { checksumDrift, checksumOf, listMigrationFiles, planMigrations, splitSql } from "./migration-plan";
import { migrationDefinerGuardSql, migrationDefinerViolations, guardedMigration } from "./security-definer-policy";

const q = (body: any): Promise<any> => sqlRequest(body);

const dryRun = process.argv.includes("--dry-run");
// --only=a.sql,b.sql applies just those files (e.g. to hold back a migration waiting on a deploy).
const only = process.argv.find((a) => a.startsWith("--only="))?.slice(7).split(",").filter(Boolean);
const dir = join(import.meta.dir, "..", "db");
const files = listMigrationFiles(dir);
await q({
  query: "create table if not exists public.schema_migrations (filename text primary key, checksum text not null, applied_at timestamptz not null default now())",
  params: [],
});
const applied = (await q({ query: "select filename, checksum from public.schema_migrations", params: [] })).rows as {
  filename: string;
  checksum: string;
}[];
const done = new Set(applied.map((r) => r.filename));
const current = new Map(files.map((f) => [f, checksumOf(readFileSync(join(dir, f), "utf8"))]));
for (const file of checksumDrift(applied, current)) console.warn(`! ${file} is gewijzigd na toepassen (niet opnieuw gedraaid).`);

const record = (file: string) => ({
  query: "insert into public.schema_migrations (filename, checksum) values ($1, $2)",
  params: [file, current.get(file)!],
});
for (const step of planMigrations(files, done)) {
  const { file } = step;
  if (only && !only.includes(file)) continue;
  if (dryRun) {
    console.log(`… ${step.action === "run" ? "pending" : "record "} ${file}`);
    continue;
  }
  try {
    if (step.action === "record") {
      await q({ queries: [record(file)] });
      console.log(`= ${file} (recorded, covered by baseline)`);
      continue;
    }
    const body = readFileSync(join(dir, file), "utf8");
    const guarded = guardedMigration(file);
    const lint = guarded ? migrationDefinerViolations(file, body) : [];
    if (lint.length > 0) throw new Error(lint.join("; "));
    const guard = guarded ? [{ query: migrationDefinerGuardSql(file), params: [] }] : [];
    await q({ queries: [...splitSql(body).map((query) => ({ query, params: [] })), ...guard, record(file)] });
    console.log(`✓ ${file}`);
  } catch (e) {
    console.error(`✗ ${file}: ${e instanceof Error ? e.message : e}`);
    process.exitCode = 1;
    break;
  }
}
await closeDirect();
