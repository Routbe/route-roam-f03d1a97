/**
 * Checks every row of public.schema_migrations against db/ and the
 * acknowledged list (scripts/migration-history-allowlist.ts). Read-only.
 *
 *   bun scripts/migration-history-check.ts                     live (MIGRATION_URL, else DATABASE_URL)
 *   bun scripts/migration-history-check.ts --applied=rows.json  offline, rows exported as [{filename, checksum}]
 *
 * Exit 1 when any row is unexplained. Pending files (not applied yet) are listed, not failed.
 * Use the owner login in MIGRATION_URL: rout_app has no rights on schema_migrations.
 */
import { closeDirect, sqlRequest } from "./db-direct";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ACKNOWLEDGED_HISTORY } from "./migration-history-allowlist";
import { checksumOf, historyFindings, listMigrationFiles, pendingFiles, type AppliedMigration } from "./migration-plan";

const QUERY = "select filename, checksum from public.schema_migrations order by filename";

async function readApplied(): Promise<AppliedMigration[]> {
  const fromFile = process.argv.find((a) => a.startsWith("--applied="))?.slice(10);
  if (fromFile) return JSON.parse(readFileSync(fromFile, "utf8")) as AppliedMigration[];
  try {
    return (await sqlRequest({ query: QUERY })).rows as AppliedMigration[];
  } finally {
    await closeDirect();
  }
}

const dir = join(import.meta.dir, "..", "db");
const files = listMigrationFiles(dir);
const current = new Map(files.map((f) => [f, checksumOf(readFileSync(join(dir, f), "utf8"))]));
const applied = await readApplied();
const findings = historyFindings(applied, current, ACKNOWLEDGED_HISTORY);
const acknowledged = applied.filter((r) => ACKNOWLEDGED_HISTORY.some((a) => a.filename === r.filename && a.neonChecksum === r.checksum));

console.log(`${applied.length} toegepaste migraties, ${files.length} bestanden in db/`);
for (const r of acknowledged) console.log(`= erkend: ${r.filename}`);
for (const f of pendingFiles(applied, files)) console.log(`… nog niet toegepast: ${f}`);
for (const f of findings) console.error(`✗ ${f.problem}: ${f.filename} (Neon ${f.recorded}${f.file ? `, bestand ${f.file}` : ""})`);
console.log(`${findings.length} afwijkingen`);
if (findings.length > 0) process.exitCode = 1;
