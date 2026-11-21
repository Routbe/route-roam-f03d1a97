/**
 * Schema snapshot, drift check, baseline and row types — all from the live catalog.
 *
 *   bun scripts/schema-snapshot.ts             write db/schema.snapshot.json + src/lib/db-types.gen.ts
 *   bun scripts/schema-snapshot.ts --check     exit 1 when the live database differs from the snapshot
 *   bun scripts/schema-snapshot.ts --types     regenerate src/lib/db-types.gen.ts from the committed snapshot
 *   bun scripts/schema-snapshot.ts --baseline  write db/0000_baseline.sql (once; it is immutable afterwards)
 *
 * Connection: MIGRATION_URL, else DATABASE_URL (direct, TLS). Read-only: only catalog queries.
 */
import { closeDirect, sqlRequest } from "./db-direct";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { BASELINE_COVERS, BASELINE_FILE } from "./migration-plan";
import { catalogJson, diffCatalogs, readCatalog, renderBaseline, renderDbTypes, type Catalog, type Exec } from "./schema-catalog";

const root = join(import.meta.dir, "..");
const SNAPSHOT = join(root, "db", "schema.snapshot.json");
const TYPES = join(root, "src", "lib", "db-types.gen.ts");

async function executor(): Promise<{ exec: Exec; close: () => Promise<void> }> {
  return { exec: async (query) => (await sqlRequest({ query })).rows, close: closeDirect };
}

const args = new Set(process.argv.slice(2));

if (args.has("--types")) {
  const catalog = JSON.parse(readFileSync(SNAPSHOT, "utf8")) as Catalog;
  writeFileSync(TYPES, renderDbTypes(catalog));
  console.log(`✓ ${TYPES}`);
  process.exit(0);
}

const { exec, close } = await executor();
try {
  const live = await readCatalog(exec);
  if (args.has("--check")) {
    const committed = JSON.parse(readFileSync(SNAPSHOT, "utf8")) as Catalog;
    const diff = diffCatalogs(committed, live);
    if (diff.length) {
      console.error(`Schema drift (${diff.length}) — live database vs db/schema.snapshot.json:`);
      for (const line of diff) console.error(`  ${line}`);
      process.exitCode = 1;
    } else console.log("✓ live database matches db/schema.snapshot.json");
  } else if (args.has("--baseline")) {
    const target = join(root, "db", BASELINE_FILE);
    if (existsSync(target) && !args.has("--force")) throw new Error(`${BASELINE_FILE} bestaat al en is onveranderlijk.`);
    const seedSql = readFileSync(join(root, "db", "baseline-seed.sql"), "utf8");
    writeFileSync(target, renderBaseline(live, { covers: BASELINE_COVERS, seedSql, generatedAt: new Date().toISOString().slice(0, 10) }));
    console.log(`✓ ${target}`);
  } else {
    writeFileSync(SNAPSHOT, catalogJson(live));
    writeFileSync(TYPES, renderDbTypes(live));
    console.log(`✓ ${SNAPSHOT} (${live.tables.length} tables)\n✓ ${TYPES}`);
  }
} finally {
  await close();
}
