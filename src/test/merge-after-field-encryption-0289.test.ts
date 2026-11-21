// @vitest-environment node
/**
 * db/0289 (live on Neon since 2026-11-17) on an offline replay of db/ up to 0288. Never touches Neon.
 * Proves: with 0287 in place the merge executor cannot run 0287's shape check (so every merge
 * fails); 0289 grants exactly that function and adds the nullifier merge guard right after the
 * verified_identities guard; it is idempotent; the rollback removes both again.
 */
import { PGlite } from "@electric-sql/pglite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { applyReleased, replayDb, ROOT } from "../../scripts/formal-rls/replay";

const FILE = "0289_merge_after_field_encryption.sql";
let db: PGlite;
const canRun = async () =>
  (await db.query<{ ok: boolean }>("select has_function_privilege('rout_merge_executor', 'public.rout_rpf1_shape_ok(bytea)', 'EXECUTE') as ok")).rows[0]!.ok;
const def = async () =>
  (await db.query<{ d: string }>("select pg_get_functiondef('public.execute_account_merge(text,text,text,text)'::regprocedure) as d")).rows[0]!.d;

beforeAll(async () => { db = await replayDb((f) => f < "0289"); }, 600_000);
afterAll(async () => { await db?.close(); });

describe("0289 account merge after field encryption", () => {
  it("before 0289 the merge executor cannot pass 0287's shape check", async () => {
    expect(await canRun()).toBe(false);
    expect(await def()).not.toContain("merge_blocked:verified_identity_nullifiers");
  });

  it("grants the shape check and guards nullifier rows right after verified_identities", async () => {
    await applyReleased(db, FILE);
    expect(await canRun()).toBe(true);
    const d = await def();
    const at = d.indexOf("'merge_blocked:verified_identities'");
    const guard = d.indexOf("'merge_blocked:verified_identity_nullifiers'");
    expect(at).toBeGreaterThan(0);
    expect(guard).toBeGreaterThan(at);
    expect(d).toContain('select 1 from public."verified_identity_nullifiers" where "user_id" = v_secondary');
    // The temporary membership of the migrating role is revoked again.
    const m = await db.query("select 1 from pg_auth_members where roleid = 'rout_merge_executor'::regrole and member = (select oid from pg_roles where rolname = current_user)");
    expect(m.rows).toEqual([]);
  });

  it("is idempotent", async () => {
    const before = await def();
    await applyReleased(db, FILE);
    expect(await def()).toBe(before);
  });

  it("rolls back to the 0288 state", async () => {
    const body = readFileSync(join(ROOT, "db-pending", "0289_merge_after_field_encryption_rollback.sql"), "utf8");
    await db.exec(`begin;\n${body}\n;commit;`);
    expect(await canRun()).toBe(false);
    expect(await def()).not.toContain("merge_blocked:verified_identity_nullifiers");
  });
});
