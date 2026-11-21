// @vitest-environment node
/**
 * db/0291 (zero raw date of birth) on an offline replay of db/ up to 0290, applied with the
 * definer guard in the same transaction. Never touches Neon. Proves:
 *   - existing birth dates become a whole-year age floor and are erased; the column stays empty;
 *   - minor and Q&A protections read the floor and age with the calendar (fail closed);
 *   - sign-up records only the floor (the legacy date form converts and never stores the date);
 *   - the age sheet sets the caller's own floor once, and a minor needs a distinct parent address;
 *   - every definer pins search_path and PUBLIC executes none of them;
 *   - the rollback refuses while floors exist and restores 0290 when empty.
 */
import type { PGlite } from "@electric-sql/pglite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { applyReleased, replayDb, ROOT } from "../../scripts/formal-rls/replay";

const MINOR = "00000000-0000-4000-8000-000000002911";
const ADULT = "00000000-0000-4000-8000-000000002912";
const SHEET = "00000000-0000-4000-8000-000000002913";
const NOAGE = "00000000-0000-4000-8000-000000002914";
const HASH = "a".repeat(64);

let db: PGlite;
beforeAll(async () => {
  db = await replayDb((f) => f < "0291");
  await db.exec(`
    insert into public.users (id, email, date_of_birth) values
      ('${MINOR}', 'minor@example.test', current_date - interval '15 years' + interval '10 days'),
      ('${ADULT}', 'adult@example.test', date '1990-05-05');
    insert into public.users (id, email) values ('${SHEET}', 'sheet@example.test'), ('${NOAGE}', 'noage@example.test');
  `);
  await applyReleased(db, "0291_age_floor_zero_dob.sql");
}, 600_000);
afterAll(async () => { await db?.close(); });

async function as<T>(userId: string | null, query: string, params: unknown[] = []): Promise<T[]> {
  await db.exec("begin; set local role rout_app;");
  try {
    if (userId) await db.query("select set_config('rout.current_user_id', $1, true)", [userId]);
    const rows = (await db.query<T>(query, params)).rows;
    await db.exec("commit;");
    return rows;
  } catch (e) {
    await db.exec("rollback;");
    throw e;
  }
}
const one = async <T>(userId: string | null, q: string, p: unknown[] = []) => (await as<T>(userId, q, p))[0]!;
type U = { dob: string | null; floor: number | null; minor: boolean; qa: string };
const user = async (id: string) =>
  (await db.query<U>("select date_of_birth::text as dob, age_floor as floor, is_minor as minor, qa_permission_level::text as qa from public.users where id = $1", [id])).rows[0]!;

describe("conversion", () => {
  it("turns every stored birth date into a floor and erases it", async () => {
    expect(await user(MINOR)).toEqual({ dob: null, floor: 14, minor: true, qa: "verified_only" });
    expect(await user(ADULT)).toEqual({ dob: null, floor: 21, minor: false, qa: "public_unrestricted" });
    const [{ n }] = (await db.query<{ n: number }>("select count(*)::int as n from public.users where date_of_birth is not null")).rows as [{ n: number }];
    expect(n).toBe(0);
  });

  it("refuses any new birth date", async () => {
    await expect(db.query(`update public.users set date_of_birth = date '2000-01-01' where id = '${ADULT}'`)).rejects.toThrow(/users_no_birth_date/);
  });
});

describe("protections", () => {
  it("rout_user_is_minor ages with the calendar", async () => {
    expect((await one<{ m: boolean }>(null, `select public.rout_user_is_minor('${MINOR}') as m`)).m).toBe(true);
    expect((await one<{ m: boolean }>(null, `select public.rout_user_is_minor('${ADULT}') as m`)).m).toBe(false);
    await db.exec(`update public.users set age_floor_at = current_date - interval '2 years' where id = '${MINOR}'`);
    expect((await one<{ m: boolean }>(null, `select public.rout_user_is_minor('${MINOR}') as m`)).m).toBe(false);
    await db.exec(`update public.users set age_floor_at = current_date where id = '${MINOR}'`);
  });
});

describe("sign-up", () => {
  it("records only the floor and opens a consent link for a minor, once", async () => {
    await db.exec("insert into public.users (email) values ('fresh@example.test'), ('legacy@example.test')");
    const q = "select public.rout_record_signup_age_floor($1, $2::smallint, $3, $4) as id";
    const first = await one<{ id: string | null }>(null, q, ["fresh@example.test", 13, "parent@example.test", HASH]);
    expect(first.id).toBeTruthy();
    expect(await user(first.id!)).toMatchObject({ dob: null, floor: 13, minor: true, qa: "verified_only" });
    const [{ n }] = (await db.query<{ n: number }>(`select count(*)::int as n from public.parent_authorizations where user_id = '${first.id}'`)).rows as [{ n: number }];
    expect(n).toBe(1);
    expect((await one<{ id: string | null }>(null, q, ["fresh@example.test", 30, null, null])).id).toBeNull();
    expect((await one<{ id: string | null }>(null, q, ["fresh@example.test", 22, null, null])).id).toBeNull();
  });

  it("the legacy date form converts and never stores the date", async () => {
    const r = await one<{ id: string | null }>(null, "select public.rout_record_signup_age($1, $2::date, null, null) as id", ["legacy@example.test", "1980-01-01"]);
    expect(await user(r.id!)).toMatchObject({ dob: null, floor: 21, minor: false });
  });
});

describe("age sheet", () => {
  const rec = "select public.rout_record_my_age_floor($1::smallint, $2, $3) as r";
  it("needs a member, a valid floor and a distinct parent for a minor", async () => {
    expect((await one<{ r: string }>(null, rec, [20, null, null])).r).toBe("no_member");
    expect((await one<{ r: string }>(SHEET, rec, [22, null, null])).r).toBe("invalid_input");
    expect((await one<{ r: string }>(SHEET, rec, [14, null, null])).r).toBe("parent_required");
    expect((await one<{ r: string }>(SHEET, rec, [14, "Sheet@Example.test", HASH])).r).toBe("parent_email_same");
    expect((await user(SHEET)).floor).toBeNull();
  });

  it("sets the caller's own floor once", async () => {
    expect((await one<{ r: string }>(SHEET, rec, [18, null, null])).r).toBe("ok");
    expect((await one<{ r: string }>(SHEET, rec, [21, null, null])).r).toBe("already_set");
    expect(await user(SHEET)).toMatchObject({ dob: null, floor: 18, minor: false, qa: "public_unrestricted" });
    expect(await user(NOAGE)).toMatchObject({ floor: null });
  });

  it("rout_my_age_floor answers only for the caller", async () => {
    expect((await one<{ a: number | null }>(SHEET, "select public.rout_my_age_floor() as a")).a).toBe(18);
    expect((await one<{ a: number | null }>(NOAGE, "select public.rout_my_age_floor() as a")).a).toBeNull();
    expect((await one<{ a: number | null }>(null, "select public.rout_my_age_floor() as a")).a).toBeNull();
  });
});

describe("definers", () => {
  it("pin search_path, are not executable by PUBLIC, and rout_app reaches the app-facing ones", async () => {
    const rows = (await db.query<{ f: string; cfg: string[]; pub: boolean; app: boolean }>(`
      select p.oid::regprocedure::text as f, p.proconfig as cfg,
             has_function_privilege('public', p.oid, 'EXECUTE') as pub, has_function_privilege('rout_app', p.oid, 'EXECUTE') as app
        from pg_proc p where p.pronamespace = 'public'::regnamespace
         and p.proname in ('rout_record_signup_age_floor', 'rout_record_my_age_floor', 'rout_my_age_floor',
           'rout_record_signup_age', 'rout_user_is_minor', 'rout_profile_qa_level')`)).rows;
    expect(rows.length).toBe(6);
    for (const r of rows) {
      expect(r.cfg, r.f).toEqual(["search_path=pg_catalog, pg_temp"]);
      expect(r.pub, r.f).toBe(false);
    }
    for (const f of ["rout_record_signup_age_floor", "rout_record_my_age_floor", "rout_my_age_floor"]) {
      expect(rows.find((r) => r.f.startsWith(`public.${f}(`) || r.f.startsWith(`${f}(`))?.app, f).toBe(true);
    }
  });
});

describe("rollback", () => {
  it("refuses while floors exist, restores 0290 when empty", async () => {
    const body = readFileSync(join(ROOT, "db-pending", "0291_age_floor_zero_dob_rollback.sql"), "utf8");
    await expect(db.exec(`begin;\n${body}\ncommit;`)).rejects.toThrow(/rollback_0291_refused/);
    await db.exec("rollback;");
    await db.exec("update public.users set age_floor = null, age_floor_at = null;");
    await db.exec(`begin;\n${body}\ncommit;`);
    const [r] = (await db.query<{ col: number; mine: string | null }>(`
      select (select count(*)::int from information_schema.columns where table_name = 'users' and column_name = 'age_floor') as col,
             to_regprocedure('public.rout_my_age_floor()')::text as mine`)).rows;
    expect(r).toEqual({ col: 0, mine: null });
    await db.exec(`update public.users set date_of_birth = date '2012-01-01' where id = '${NOAGE}'`);
    const [{ m }] = (await db.query<{ m: boolean }>(`select is_minor as m from public.users where id = '${NOAGE}'`)).rows as [{ m: boolean }];
    expect(m).toBe(true);
  });
});
