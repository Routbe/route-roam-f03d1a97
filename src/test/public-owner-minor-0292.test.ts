// @vitest-environment node
/**
 * db/0292 (under-18 check for the public blue-mark card) on an offline replay of db/.
 * Never touches Neon. Proves: under 18 by self-declared or KYC age floor = true, adults and
 * unknown age = false, only rout_app may execute it, search_path is pinned, rollback removes it.
 */
import type { PGlite } from "@electric-sql/pglite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { applyPending, applyReleased, replayDb } from "../../scripts/formal-rls/replay";

const SEVENTEEN = "00000000-0000-4000-8000-000000002921";
const ADULT = "00000000-0000-4000-8000-000000002922";
const NOAGE = "00000000-0000-4000-8000-000000002923";
const AGED = "00000000-0000-4000-8000-000000002924";

let db: PGlite;
beforeAll(async () => {
  db = await replayDb((f) => f < "0292");
  await db.exec(`
    insert into public.users (id, email, age_floor, age_floor_at) values
      ('${SEVENTEEN}', 'seventeen@example.test', 17, current_date),
      ('${ADULT}', 'adult@example.test', 20, current_date),
      ('${AGED}', 'aged@example.test', 17, current_date - interval '1 year 1 day');
    insert into public.users (id, email) values ('${NOAGE}', 'noage@example.test');
  `);
  await applyReleased(db, "0292_public_owner_minor.sql");
}, 600_000);
afterAll(async () => { await db?.close(); });

async function minor(id: string): Promise<unknown> {
  await db.exec("begin; set local role rout_app;");
  try {
    return (await db.query<{ m: unknown }>("select public.rout_public_owner_is_minor($1) as m", [id])).rows[0]?.m;
  } finally {
    await db.exec("rollback;");
  }
}

describe("0292 rout_public_owner_is_minor", () => {
  it("a 17-year-old is a minor, an adult is not", async () => {
    expect(await minor(SEVENTEEN)).toBe(true);
    expect(await minor(ADULT)).toBe(false);
  });

  it("the age floor ages with the calendar", async () => {
    expect(await minor(AGED)).toBe(false);
  });

  it("unknown age is not treated as a minor", async () => {
    expect(await minor(NOAGE)).toBe(false);
    expect(await minor("00000000-0000-4000-8000-00000000ffff")).toBe(false);
  });

  it("is a pinned definer that only rout_app may execute", async () => {
    const r = (await db.query<{ cfg: string[]; pub: boolean; app: boolean; def: boolean }>(`
      select p.proconfig as cfg, p.prosecdef as def,
             has_function_privilege('public', p.oid, 'execute') as pub,
             has_function_privilege('rout_app', p.oid, 'execute') as app
        from pg_proc p where p.oid = 'public.rout_public_owner_is_minor(uuid)'::regprocedure`)).rows[0]!;
    expect(r.def).toBe(true);
    expect(r.cfg).toContain("search_path=pg_catalog, pg_temp");
    expect(r.pub).toBe(false);
    expect(r.app).toBe(true);
  });

  it("the rollback removes it", async () => {
    await applyPending(db, "0292_public_owner_minor_rollback.sql");
    const r = (await db.query<{ ok: boolean }>("select to_regprocedure('public.rout_public_owner_is_minor(uuid)') is null as ok")).rows[0]!;
    expect(r.ok).toBe(true);
  });
});
