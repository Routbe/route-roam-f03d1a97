// @vitest-environment node
/**
 * db/0295 on an offline replay of db/: the shared DPoP jti replay ledger. rout_app has no table
 * rights and reaches it only through rout_dpop_jti_claim; a hash is claimed exactly once while its
 * hold lasts (also by two server instances in a row), can be claimed again only after the hold
 * expired on the database clock, and malformed input is refused. Neon is not touched.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { PGlite } from "@electric-sql/pglite";
import { replayDb } from "../../scripts/formal-rls/replay";
import { DualLayerReplayGuard, JtiReplayCache, jtiReplayHash } from "@/lib/eudi/dpop";

let db: PGlite;
beforeAll(async () => {
  db = await replayDb();
}, 300_000);
afterAll(async () => {
  await db?.close();
});

async function asApp<T>(query: string, params: unknown[] = []): Promise<T[]> {
  await db.exec("begin; set local role rout_app;");
  try {
    const r = (await db.query<T>(query, params)).rows;
    await db.exec("commit;");
    return r;
  } catch (e) {
    await db.exec("rollback;");
    throw e;
  }
}
const claim = async (hash: string, hold = 120) =>
  (await asApp<{ ok: boolean }>("select public.rout_dpop_jti_claim($1, $2) as ok", [hash, hold]))[0]!.ok;
const H = (c: string) => c.repeat(64);

describe("db/0295 DPoP jti replay ledger", () => {
  it("rout_app cannot read or write the table directly", async () => {
    await expect(asApp("select * from public.dpop_jti_replays")).rejects.toThrow(/permission denied/);
    await expect(asApp("insert into public.dpop_jti_replays values ($1, now())", [H("a")])).rejects.toThrow(/permission denied/);
    await expect(asApp("delete from public.dpop_jti_replays")).rejects.toThrow(/permission denied/);
  });

  it("claims a hash once; a second claim within the hold is a replay", async () => {
    expect(await claim(H("b"))).toBe(true);
    expect(await claim(H("b"))).toBe(false);
    expect(await claim(H("c"))).toBe(true);
  });

  it("a hash can be claimed again only after its hold expired", async () => {
    expect(await claim(H("d"))).toBe(true);
    await db.query("update public.dpop_jti_replays set expires_at = now() - interval '1 second' where jti_hash = $1", [H("d")]);
    expect(await claim(H("d"))).toBe(true);
    expect(await claim(H("d"))).toBe(false);
  });

  it("prunes expired rows while claiming", async () => {
    await db.query("insert into public.dpop_jti_replays values ($1, now() - interval '1 minute')", [H("e")]);
    expect(await claim(H("f"))).toBe(true);
    const left = (await db.query<{ n: number }>("select count(*)::int as n from public.dpop_jti_replays where jti_hash = $1", [H("e")])).rows[0]!.n;
    expect(left).toBe(0);
  });

  it("refuses malformed hashes and hold times", async () => {
    await expect(claim("not-a-hash")).rejects.toThrow(/invalid dpop jti claim/);
    await expect(claim(H("A"))).rejects.toThrow(/invalid dpop jti claim/);
    await expect(claim(H("1"), 0)).rejects.toThrow(/invalid dpop jti claim/);
    await expect(claim(H("1"), 601)).rejects.toThrow(/invalid dpop jti claim/);
  });

  it("two server instances (separate layer-1 caches) on one ledger: the second sees a replay", async () => {
    const ledger = (h: string, s: number) => claim(h, s);
    const a = new DualLayerReplayGuard(new JtiReplayCache(), ledger);
    const b = new DualLayerReplayGuard(new JtiReplayCache(), ledger);
    expect(await a.claim("thumbprint-x", "jti-cross-instance-0001", Date.now())).toBe(true);
    expect(await b.claim("thumbprint-x", "jti-cross-instance-0001", Date.now())).toBe(false);
    const stored = (await db.query<{ jti_hash: string }>("select jti_hash from public.dpop_jti_replays where jti_hash = $1", [jtiReplayHash("thumbprint-x", "jti-cross-instance-0001")])).rows;
    expect(stored).toHaveLength(1);
  });

  it("the claim function runs with the hardened search_path and only rout_app may call it", async () => {
    const row = (await db.query<{ cfg: string[]; definer: boolean; pub: boolean; app: boolean }>(
      `select p.proconfig as cfg, p.prosecdef as definer,
              has_function_privilege('public', p.oid, 'execute') as pub,
              has_function_privilege('rout_app', p.oid, 'execute') as app
         from pg_proc p where p.oid = 'public.rout_dpop_jti_claim(text,integer)'::regprocedure`,
    )).rows[0]!;
    expect(row.definer).toBe(true);
    expect(row.cfg).toContain("search_path=pg_catalog, pg_temp");
    expect(row.pub).toBe(false);
    expect(row.app).toBe(true);
  });
});
