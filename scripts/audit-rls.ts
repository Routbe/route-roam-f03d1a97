/**
 * Zero-trust audit: lists every public table with user_id / owner_id / workspace_id / host_user_id
 * and fails (exit 1) when one has row level security switched off. Also reports which DB roles
 * bypass RLS, because for those roles scope is enforced server-side only.
 *
 *   MIGRATION_URL=... bun scripts/audit-rls.ts
 */
import { closeDirect, sqlRequest } from "./db-direct";
import { writeFileSync } from "node:fs";
import { RLS_AUDIT_QUERY, auditFailures, type AuditTable } from "./rls-audit-query";
const data = await sqlRequest({ queries: [
  { query: RLS_AUDIT_QUERY, params: [] },
  { query: "select rolname, rolbypassrls from pg_roles where rolname in ('rout_app','neondb_owner')", params: [] },
] }, { readOnly: true }) as any;
await closeDirect();
const tables = data.results[0].rows as AuditTable[];
const roles = data.results[1].rows.filter((r: { rolbypassrls: boolean }) => r.rolbypassrls).map((r: { rolname: string }) => r.rolname);
const failures = auditFailures(tables, roles.filter((role: string) => role === "rout_app"));
writeFileSync("/tmp/rls-audit.json", JSON.stringify({ tables, roles, failures }, null, 2));
console.log(`${tables.length} scoped tables; ${failures.disabled.length} RLS disabled; ${failures.missingPolicies.length} without policies.`);
console.log(`Application bypass roles: ${failures.bypassRoles.join(", ") || "none"}. Policy expressions saved for review; active-scope correctness is NOT automatically certified.`);
process.exitCode = failures.disabled.length || failures.missingPolicies.length || failures.bypassRoles.length ? 1 : 0;
