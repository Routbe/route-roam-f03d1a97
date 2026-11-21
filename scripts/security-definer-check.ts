/**
 * Live check: every SECURITY DEFINER function outside extensions runs with
 * search_path = pg_catalog, except the shrinking list in
 * scripts/security-definer-legacy.ts. Read-only.
 *
 *   bun scripts/security-definer-check.ts                    live (MIGRATION_URL, else DATABASE_URL)
 *   bun scripts/security-definer-check.ts --rows=rows.json   offline, rows exported as [{schema, name, args, config}]
 *
 * Exit 1 on an unpinned function that is not listed, or on a listed function
 * that is already pinned or gone (remove it from the list).
 */
import { closeDirect, sqlRequest } from "./db-direct";
import { readFileSync } from "node:fs";
import { LEGACY_DEFINER_SEARCH_PATH } from "./security-definer-legacy";
import { definerFindings, definerKey, searchPathFromConfig } from "./security-definer-policy";

type Row = { schema: string; name: string; args: string; config: string[] | null };

const QUERY = `select n.nspname as schema, p.proname as name, pg_catalog.pg_get_function_identity_arguments(p.oid) as args, p.proconfig as config
  from pg_catalog.pg_proc p join pg_catalog.pg_namespace n on n.oid = p.pronamespace
 where p.prosecdef and n.nspname not in ('pg_catalog', 'information_schema')
   and not exists (select 1 from pg_catalog.pg_depend d where d.classid = 'pg_catalog.pg_proc'::regclass and d.objid = p.oid and d.deptype = 'e')
 order by 1, 2, 3`;

async function readRows(): Promise<Row[]> {
  const fromFile = process.argv.find((a) => a.startsWith("--rows="))?.slice(7);
  if (fromFile) return JSON.parse(readFileSync(fromFile, "utf8")) as Row[];
  try {
    return (await sqlRequest({ query: QUERY })).rows as Row[];
  } finally {
    await closeDirect();
  }
}

const rows = await readRows();
const fns = rows.map((r) => ({ key: definerKey(r.schema, r.name, r.args), searchPath: searchPathFromConfig(r.config) }));
const findings = definerFindings(fns, LEGACY_DEFINER_SEARCH_PATH);
const pinned = fns.length - LEGACY_DEFINER_SEARCH_PATH.length;
console.log(`${fns.length} SECURITY DEFINER-functies, ${LEGACY_DEFINER_SEARCH_PATH.length} nog op de overgangslijst, ${pinned} vastgezet op pg_catalog`);
for (const f of findings) {
  if (f.problem === "not_pinned") console.error(`✗ niet vastgezet: ${f.key} (search_path ${f.searchPath?.join(", ") ?? "ontbreekt"})`);
  else console.error(`✗ verouderde regel op de overgangslijst (al vastgezet of verdwenen): ${f.key}`);
}
console.log(`${findings.length} afwijkingen`);
if (findings.length > 0) process.exitCode = 1;
