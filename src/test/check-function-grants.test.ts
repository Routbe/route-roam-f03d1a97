// @vitest-environment node
/**
 * Every role that may write a table must be able to execute every function a CHECK constraint on
 * that table calls. db/ up to 0288 has exactly one such gap: 0287's RPF1 shape
 * check for the account-merge executor; db/0289 closes it. Nothing touches Neon.
 */
import { afterAll, beforeAll, expect, it } from "vitest";
import type { PGlite } from "@electric-sql/pglite";
import { applyReleased, replayDb } from "../../scripts/formal-rls/replay";
import { AUDIT_ROLES, CHECK_GRANT_AUDIT_SQL } from "../../scripts/formal-rls/policy-grant-audit";

let db: PGlite;
const gaps = async () =>
  (await db.query<{ role: string; fn: string }>(CHECK_GRANT_AUDIT_SQL, [AUDIT_ROLES as unknown as string[]])).rows.map((g) => `${g.role}:${g.fn}`);
beforeAll(async () => { db = await replayDb((f) => f < "0289"); }, 300_000);
afterAll(async () => { await db?.close(); });

it("db/ up to 0288 leaves the merge executor unable to run 0287's shape check", async () => {
  expect([...new Set(await gaps())]).toEqual(["rout_merge_executor:rout_rpf1_shape_ok(bytea)"]);
});
it("after 0289 no audited role misses EXECUTE on a CHECK helper", async () => {
  await applyReleased(db, "0289_merge_after_field_encryption.sql");
  expect(await gaps()).toEqual([]);
}, 120_000);
