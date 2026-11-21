// @vitest-environment node
/**
 * db/0293 on an offline replay of db/: the support treasury. rout_app has no table rights,
 * levels 2/3 never store a member, a paid donation appends exactly the next Merkle leaf (the
 * stored siblings reproduce the TypeScript tree), provider references are cleared on payment,
 * and the status page needs the access token. Neon is not touched.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { PGlite } from "@electric-sql/pglite";
import { replayDb } from "../../scripts/formal-rls/replay";
import { MemoryTree, fromHex, leafCommitment, pathFor, siblingsFor, toHex, verifyInclusion, type NodeReader } from "@/lib/support/treasury-tree";

const MEMBER = "00000000-0000-4000-8000-0000000002a1";
const KYC = "00000000-0000-4000-8000-0000000002a2";
const H = (c: string) => c.repeat(64).slice(0, 64);
const SIG_ED = "e".repeat(86);

let db: PGlite;
beforeAll(async () => {
  db = await replayDb();
  await db.exec(`
    insert into public.users (id, email) values ('${MEMBER}', 'm@example.test'), ('${KYC}', 'k@example.test');
    insert into public.profiles (id, username) values ('${MEMBER}', 'jona'), ('${KYC}', 'kyc')
      on conflict (id) do update set username = excluded.username;
    insert into public.identity_verifications (user_id, is_verified, verification_provider, unique_human_id) values ('${KYC}', true, 'didit', 'n-kyc');
  `);
}, 300_000);
afterAll(async () => { await db?.close(); });

async function as<T>(userId: string | null, query: string, params: unknown[] = [], commit = false): Promise<T[]> {
  await db.exec("begin; set local role rout_app;");
  try {
    if (userId) await db.query("select set_config('rout.current_user_id', $1, true)", [userId]);
    const r = (await db.query<T>(query, params)).rows;
    await db.exec(commit ? "commit;" : "rollback;");
    return r;
  } catch (e) {
    await db.exec("rollback;");
    throw e;
  }
}
const create = (user: string | null, level: number, rail: string, amount: number, ogm: string | null, access: string) =>
  as<{ id: string | null; attested: boolean | null }>(user, "select * from public.rout_support_create($1::smallint, $2, $3, $4, $5)", [level, rail, amount, ogm, access], true);

const dbReader = async (index: bigint): Promise<NodeReader> => {
  const rows = await as<{ level: number; hash: string }>(null, "select * from public.rout_public_treasury_siblings($1)", [index.toString()]);
  const byLevel = new Map(rows.map((r) => [Number(r.level), fromHex(r.hash)]));
  return { get: (level, idx) => (idx === ((index >> BigInt(level)) ^ 1n) ? byLevel.get(level) : undefined) };
};

async function pay(id: string, amount: number, index: bigint, opening: Parameters<typeof leafCommitment>[0]) {
  const leaf = leafCommitment(opening);
  const { nodes, root } = pathFor(index, leaf, siblingsFor(index, await dbReader(index)));
  const json = JSON.stringify(nodes.map((n) => ({ level: n.level, idx: n.idx.toString(), hash: toHex(n.hash) })));
  const r = await as<{ r: string }>(null, "select public.rout_support_mark_paid($1::uuid, $2, 'bunq', $3, $4, $5, $6::jsonb, $7, 'aaaaaaaaaaaaaaaa', $8, null, $9::jsonb) as r",
    [id, amount, H("a"), index.toString(), toHex(leaf), json, toHex(root), SIG_ED, JSON.stringify({ v: 1 })], true);
  return { r: r[0]!.r, leaf, root };
}

const opening = (amountCents: number, level: 1 | 2 | 3, nonce: string) => ({ level, attested: false, amountCents, month: "2026-11", nonce });

describe("db/0293 support treasury", () => {
  it("rout_app cannot touch the tables directly", async () => {
    for (const t of ["supporter_donations", "treasury_merkle_nodes", "treasury_roots", "supporter_credentials", "partner_attestations"]) {
      await expect(as(MEMBER, `select * from public.${t}`)).rejects.toThrow(/permission denied/);
    }
  });

  it("level 1 needs a signed-in member; levels 2 and 3 never store one", async () => {
    expect(await create(null, 1, "sepa", 1000, "100000000135", H("1"))).toEqual([]);
    const pseudo = (await create(KYC, 2, "stripe", 1000, null, H("2")))[0]!;
    expect(pseudo.attested).toBe(true);
    const rows = await db.query<{ user_id: string | null; attested: boolean }>("select user_id, attested from public.supporter_donations where id = $1", [pseudo.id]);
    expect(rows.rows[0]).toEqual({ user_id: null, attested: true });
  });

  it("refuses a SEPA donation without structured communication and amounts outside the range", async () => {
    expect(await create(MEMBER, 1, "sepa", 1000, null, H("3"))).toEqual([]);
    expect(await create(MEMBER, 1, "stripe", 50, null, H("3"))).toEqual([]);
  });

  it("paid donations append the next leaf; the stored siblings rebuild the same root as the TypeScript tree", async () => {
    const mem = new MemoryTree();
    const a = (await create(MEMBER, 1, "sepa", 2500, "100000000236", H("4")))[0]!.id!;
    const b = (await create(null, 2, "sepa", 1000, "100000000337", H("5")))[0]!.id!;
    const c = (await create(null, 3, "stripe", 500, null, H("6")))[0]!.id!;
    expect(await as(null, "select public.rout_support_set_provider_ref($1, $2, 'cs_test_1')", [c, H("6")], true)).toEqual([{ rout_support_set_provider_ref: true }]);

    const pending = await as<{ id: string; privacy_level: number; handle: string | null }>(null, "select * from public.rout_support_pending('100000000236', null)");
    expect(pending[0]).toMatchObject({ id: a, privacy_level: 1, handle: "jona" });

    const pa = await pay(a, 2500, 0n, opening(2500, 1, "01".repeat(31)));
    expect(pa.r).toBe("ok");
    mem.append(pa.leaf);
    expect(toHex(mem.root())).toBe(toHex(pa.root));

    expect((await pay(b, 1000, 0n, opening(1000, 2, "02".repeat(31)))).r).toBe("retry"); // index 0 is taken
    expect((await pay(b, 999, 1n, opening(1000, 2, "02".repeat(31)))).r).toBe("amount_mismatch");
    const pb = await pay(b, 1000, 1n, opening(1000, 2, "02".repeat(31)));
    expect(pb.r).toBe("ok");
    mem.append(pb.leaf);
    const pc = await pay(c, 500, 2n, opening(500, 3, "03".repeat(31)));
    mem.append(pc.leaf);
    expect(toHex(mem.root())).toBe(toHex(pc.root));
    expect((await pay(a, 2500, 3n, opening(2500, 1, "01".repeat(31)))).r).toBe("already_paid");

    // A proof from stored nodes verifies against the latest root.
    const siblings = siblingsFor(0n, await dbReader(0n));
    expect(verifyInclusion(pc.root, 0n, pa.leaf, siblings)).toBe(true);

    const cleared = await db.query<{ n: number }>("select count(*)::int as n from public.supporter_donations where status = 'paid' and (ogm is not null or provider_ref is not null)");
    expect(cleared.rows[0]!.n).toBe(0);
  });

  it("the public ledger shows the handle for level 1, the index for level 2 and neither for level 3", async () => {
    const rows = await as<{ merkle_index: string | null; privacy_level: number; handle: string | null }>(null, "select * from public.rout_public_treasury_ledger(10)");
    const byLevel = Object.fromEntries(rows.map((r) => [r.privacy_level, r]));
    expect(byLevel[1]).toMatchObject({ handle: "jona" });
    expect(byLevel[2]).toMatchObject({ handle: null, merkle_index: 1 });
    expect(byLevel[3]).toMatchObject({ handle: null, merkle_index: null });
    const sum = await as<{ total_cents: string; size: string }>(null, "select * from public.rout_public_treasury_summary()");
    expect(sum[0]).toMatchObject({ total_cents: 4000, size: 3 });
  });

  it("the status page needs the access token; only level-1 credentials get a public presentation", async () => {
    const [{ id }] = (await db.query<{ id: string }>("select id from public.supporter_donations where privacy_level = 1 and status = 'paid'")).rows as [{ id: string }];
    expect(await as(null, "select * from public.rout_support_by_access($1, $2)", [id, H("9")])).toEqual([]);
    expect((await as<{ status: string }>(null, "select * from public.rout_support_by_access($1, $2)", [id, H("4")]))[0]!.status).toBe("paid");
    await as(null, "select public.rout_support_store_credential($1, $2, 'ct', 'iv', 'presentation~', now() + interval '1 year')", [id, H("b")], true);
    expect(await as(null, "select public.rout_public_supporter_presentation('jona') as p")).toEqual([{ p: "presentation~" }]);
    expect((await as<{ id: string }>(MEMBER, "select * from public.rout_support_mine()")).length).toBe(1);
    expect(await as(KYC, "select * from public.rout_support_mine()")).toEqual([]);
  });

  it("a merge is refused while the secondary account owns a donation or credential", async () => {
    const def = (await db.query<{ d: string }>("select pg_get_functiondef('public.execute_account_merge(text,text,text,text)'::regprocedure) as d")).rows[0]!.d;
    const del = def.indexOf("delete from public.users where id=v_secondary");
    for (const t of ["supporter_donations", "supporter_credentials"]) {
      const at = def.indexOf(`'merge_blocked:${t}'`);
      expect(at, t).toBeGreaterThan(0);
      expect(at, t).toBeLessThan(del);
    }
  });

  it("every new function is a definer with the safe search_path; PUBLIC cannot execute them", async () => {
    const r = await db.query<{ fn: string; definer: boolean; path: string | null; anyone: boolean; app: boolean }>(`
      select p.oid::regprocedure::text as fn, p.prosecdef as definer, pg_catalog.array_to_string(p.proconfig, ',') as path,
             has_function_privilege('public', p.oid, 'execute') as anyone, has_function_privilege('rout_app', p.oid, 'execute') as app
        from pg_proc p where p.pronamespace = 'public'::regnamespace
         and (p.proname like 'rout_support_%' or p.proname like 'rout_public_treasury_%' or p.proname in ('rout_public_supporter_presentation', 'rout_public_partner_attestations'))`);
    expect(r.rows.length).toBe(12);
    for (const row of r.rows) expect(row, row.fn).toMatchObject({ definer: true, path: "search_path=pg_catalog, pg_temp", anyone: false, app: true });
  });
});
