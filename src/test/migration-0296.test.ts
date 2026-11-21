// @vitest-environment node
/**
 * db/0296 on an offline replay of db/: rout_app still cannot read or delete relay deliveries or
 * identity-link history directly, but the account purge clears both through
 * rout_identity_records_purge in its own transaction, only when the deletion is due. Neon is not touched.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { PGlite } from "@electric-sql/pglite";
import { replayDb } from "../../scripts/formal-rls/replay";

let db: PGlite;
const U = "11111111-1111-4111-8111-111111111111";
const V = "22222222-2222-4222-8222-222222222222";

beforeAll(async () => {
  db = await replayDb();
  await db.exec("set session_replication_role = replica;");
  for (const id of [U, V]) {
    await db.query("insert into public.oauth_email_deliveries (user_id, status) values ($1, 'forwarded')", [id]);
    await db.query(`insert into public.identity_link_events (link_id, user_id, event, actor, event_hash)
      values (gen_random_uuid(), $1, (select pg_get_constraintdef(oid) from pg_constraint where conname='identity_link_events_event_check') is not null and false or 'linked', 'user', decode(repeat('ab',32),'hex'))`, [id]).catch(async () => {
      // Fall back to the first allowed event value if 'linked' is not one of them.
      const def = (await db.query<{ d: string }>("select pg_get_constraintdef(oid) as d from pg_constraint where conname='identity_link_events_event_check'")).rows[0]!.d;
      const ev = /'([^']+)'/.exec(def)![1];
      await db.query(`insert into public.identity_link_events (link_id, user_id, event, actor, event_hash)
        values (gen_random_uuid(), $1, $2, 'user', decode(repeat('ab',32),'hex'))`, [id, ev]);
    });
  }
  await db.exec("set session_replication_role = origin;");
  await db.query("insert into public.account_deletions (user_id, requested_at, purge_after) values ($1, now() - interval '8 days', now() - interval '1 day')", [U]);
}, 300_000);
afterAll(async () => {
  await db?.close();
});

const count = async (table: string, id: string) =>
  (await db.query<{ n: number }>(`select count(*)::int as n from public.${table} where user_id = $1`, [id])).rows[0]!.n;

async function asApp(sql: string, user: string) {
  await db.exec("begin;");
  try {
    await db.query("select set_config('rout.current_user_id', $1, true), set_config('rout.purge_user_id', $1, true)", [user]);
    await db.exec("set local role rout_app;");
    await db.query(sql, [user]);
    await db.exec("commit;");
  } catch (e) {
    await db.exec("rollback;");
    throw e;
  }
}

describe("db/0296 account deletion of relay deliveries and identity history", () => {
  it("rout_app cannot delete either table directly", async () => {
    await expect(asApp("delete from public.oauth_email_deliveries where user_id = $1", U)).rejects.toThrow(/permission denied/);
    await expect(asApp("delete from public.identity_link_events where user_id = $1", U)).rejects.toThrow(/permission denied/);
  });

  it("refuses when the account's deletion is not due", async () => {
    await expect(asApp("select public.rout_identity_records_purge($1::uuid)", V)).rejects.toThrow(/purge_not_due/);
    expect(await count("oauth_email_deliveries", V)).toBe(1);
    expect(await count("identity_link_events", V)).toBe(1);
  });

  it("history stays append-only outside a due purge, even for the table owner", async () => {
    await expect(db.query("delete from public.identity_link_events where user_id = $1", [V])).rejects.toThrow(/identity_events_append_only/);
  });

  it("a due purge clears both tables for that account only, in one transaction", async () => {
    await asApp("select public.rout_identity_records_purge($1::uuid)", U);
    expect(await count("oauth_email_deliveries", U)).toBe(0);
    expect(await count("identity_link_events", U)).toBe(0);
    expect(await count("oauth_email_deliveries", V)).toBe(1);
    expect(await count("identity_link_events", V)).toBe(1);
  });

  it("the helper is a definer on the pinned search_path and only rout_app may run it", async () => {
    const r = (await db.query<{ secdef: boolean; cfg: string[]; app: boolean; pub: boolean }>(`select p.prosecdef as secdef, p.proconfig as cfg,
      has_function_privilege('rout_app', p.oid, 'execute') as app,
      exists (select 1 from aclexplode(p.proacl) a where a.grantee = 0) as pub
      from pg_proc p where p.oid = 'public.rout_identity_records_purge(uuid)'::regprocedure`)).rows[0]!;
    expect(r.secdef).toBe(true);
    expect(r.cfg).toContain("search_path=pg_catalog, pg_temp");
    expect(r.app).toBe(true);
    expect(r.pub).toBe(false);
  });
});
