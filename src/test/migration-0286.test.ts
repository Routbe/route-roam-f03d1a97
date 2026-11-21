// @vitest-environment node
/**
 * db/0286 on an offline replay of db/: every foreign key in public has an index on its key
 * columns, the four trigger-only SECURITY DEFINER functions carry no EXECUTE for PUBLIC or
 * rout_app, and a trigger whose function rout_app may not execute still fires for rout_app.
 * Neon is not touched.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { PGlite } from "@electric-sql/pglite";
import { replayDb } from "../../scripts/formal-rls/replay";

const TRIGGER_DEFINERS = [
  "public.enforce_short_link_limits()",
  "public.grant_early_verified_promo()",
  "public.handle_new_user()",
  "public.rout_shadow_mute_trust()",
];

let db: PGlite;
beforeAll(async () => {
  db = await replayDb();
}, 300_000);
afterAll(async () => { await db?.close(); });

describe("db/0286 foreign-key indexes and trigger rights", () => {
  it("leaves no foreign key in public without an index on its key columns", async () => {
    const r = await db.query<{ fk: string }>(`
      select c.conrelid::regclass::text || '.' || c.conname as fk
        from pg_constraint c
       where c.contype = 'f' and c.connamespace = 'public'::regnamespace
         and not exists (select 1 from pg_index i where i.indrelid = c.conrelid
               and (i.indkey::int2[])[0:cardinality(c.conkey) - 1] @> c.conkey
               and c.conkey @> (i.indkey::int2[])[0:cardinality(c.conkey) - 1])`);
    expect(r.rows.map((x) => x.fk)).toEqual([]);
  });

  it("indexes the composite key of user_encrypted_audit_logs in key order", async () => {
    const r = await db.query<{ def: string }>(
      `select pg_get_indexdef('public.user_encrypted_audit_logs_user_id_key_id_fkx'::regclass) as def`);
    expect(r.rows[0]!.def).toMatch(/\(user_id, key_id\)$/);
  });

  it("gives neither PUBLIC nor rout_app EXECUTE on the trigger-only definers", async () => {
    for (const fn of TRIGGER_DEFINERS) {
      const r = await db.query<{ app: boolean; anyone: boolean; definer: boolean }>(
        `select has_function_privilege('rout_app', $1::regprocedure, 'execute') as app,
                has_function_privilege('public', $1::regprocedure, 'execute') as anyone,
                (select prosecdef from pg_proc where oid = $1::regprocedure) as definer`, [fn]);
      expect(r.rows[0], fn).toEqual({ app: false, anyone: false, definer: true });
    }
  });

  it("keeps three of those triggers attached and enabled; rout_shadow_mute_trust has had none since 0183", async () => {
    const r = await db.query<{ fn: string }>(
      `select distinct t.tgfoid::regprocedure::text as fn from pg_trigger t
        where not t.tgisinternal and t.tgenabled <> 'D' and t.tgfoid = any($1::regprocedure[]) order by 1`,
      [TRIGGER_DEFINERS]);
    expect(r.rows.map((x) => `public.${x.fn.replace(/^public\./, "")}`).sort()).toEqual(
      TRIGGER_DEFINERS.filter((f) => f !== "public.rout_shadow_mute_trust()"));
  });

  it("fires a trigger for rout_app even though rout_app may not execute its function", async () => {
    await db.exec(`
      create table public.t0286 (id int primary key, fired boolean not null default false);
      create function public.t0286_mark() returns trigger language plpgsql security definer
        set search_path = pg_catalog, pg_temp as $$ begin new.fired := true; return new; end $$;
      revoke all on function public.t0286_mark() from public, rout_app;
      create trigger t0286_mark before insert on public.t0286 for each row execute function public.t0286_mark();
      grant insert, select on public.t0286 to rout_app;
    `);
    try {
      expect((await db.query<{ ok: boolean }>(
        `select has_function_privilege('rout_app', 'public.t0286_mark()', 'execute') as ok`)).rows[0]!.ok).toBe(false);
      await db.exec("begin; set local role rout_app; insert into public.t0286 (id) values (1); commit;");
      expect((await db.query<{ fired: boolean }>("select fired from public.t0286 where id = 1")).rows[0]!.fired).toBe(true);
      await db.exec("begin; set local role rout_app;");
      await expect(db.query("select public.t0286_mark()")).rejects.toThrow();
      await db.exec("rollback;");
    } finally {
      await db.exec("drop table public.t0286; drop function public.t0286_mark();");
    }
  });
});
