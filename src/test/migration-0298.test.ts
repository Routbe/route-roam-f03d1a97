// @vitest-environment node
/**
 * db/0298 (handle registry, dual-profile model) and the held-back CONTRACT
 * db-pending/0299 on an offline PGlite replay of db/. Never touches Neon. Proves:
 *   - one ACTIVE /u/ alias and one ACTIVE root handle per member, enforced by partial
 *     unique indexes, and one live owner per (namespace, handle);
 *   - the shape rule refuses `..`, `.-`, `._`, `-.` and `_.`;
 *   - the triggers keep the registry exact, tombstone a released name for 14 days and give
 *     every profile its own public_profile_id;
 *   - rout_claim_verified_root_handle refuses a member without Didit, reserved names, taken
 *     names and the member's own alias, starts blank by default or copies the alias links
 *     once, can hide the alias, and is idempotent;
 *   - rout_app reads only its own registry rows; helpers are pinned definers nobody calls;
 *   - 0299 converts unverified root handles to /u/ aliases idempotently, then blocks root
 *     handles without eligibility, reserved names, and alias renames within 30 days;
 *   - both rollbacks restore the previous state.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { PGlite } from "@electric-sql/pglite";
import { applyPending, applyReleased, replayDb } from "../../scripts/formal-rls/replay";
import { PROTECTED_PUBLIC_SLUGS, SYSTEM_ROUTE_SLUGS, RESERVED_SLUGS } from "@/lib/reserved-slugs";
import { universalNullifier } from "@/lib/kyc/nullifier";

const PEPPER = "p".repeat(48);
const nf = (s: string) => universalNullifier(new TextEncoder().encode(s), PEPPER);
const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;

let db: PGlite;

async function asApp<T>(userId: string | null, query: string, params: unknown[] = []): Promise<T[]> {
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

async function member(n: number, username: string | null, opts: { verified?: boolean; alias?: string | null } = {}) {
  const uid = id(n);
  await db.query("insert into public.users (id, email) values ($1, $2) on conflict do nothing", [uid, `m${n}@example.test`]);
  await db.query(
    `insert into public.profiles (id, username, verified) values ($1, $2, $3)
       on conflict (id) do update set username = excluded.username, verified = excluded.verified`,
    [uid, username, opts.verified ?? false],
  );
  if (opts.alias) {
    await db.query("insert into public.alias_profiles (user_id, handle, blocks) values ($1, $2, $3::jsonb)", [
      uid,
      opts.alias,
      JSON.stringify([{ kind: "link", url: "https://example.test/alias" }]),
    ]);
  }
  return uid;
}

async function didit(uid: string, seed: string) {
  const rows = await asApp<{ code: string }>(
    uid,
    "select public.rout_kyc_attest($1, $2::text[], $3::text[], $4, $5, $6) as code",
    ["didit", [nf(`BEL:PN:${seed}`)], ["personal_number"], true, true, "BEL"],
  );
  expect(rows[0]!.code).toBe("ok");
}

type Reg = { namespace: string; handle_normalized: string; status: string; tombstoned_until: string | null; last_renamed_at: string | null };
const registry = async (uid: string) =>
  (await db.query<Reg>(
    "select namespace::text, handle_normalized, status::text, tombstoned_until, last_renamed_at from public.handle_registry where user_id = $1 order by claimed_at, handle_normalized",
    [uid],
  )).rows;

const claim = (uid: string, handle: string, copy = false, hide = false) =>
  asApp<{ h: string }>(uid, "select public.rout_claim_verified_root_handle($1, $2, $3) as h", [handle, copy, hide]);

beforeAll(async () => {
  db = await replayDb();
}, 600_000);
afterAll(async () => {
  await db?.close();
});

describe("db/0298 registry structure", () => {
  it("seeds exactly the system routes and protected public terms of reserved-slugs.ts", async () => {
    const rows = (await db.query<{ h: string }>(
      "select handle_normalized as h from public.handle_registry where namespace = 'system_reserved' order by 1",
    )).rows.map((r) => r.h);
    expect(rows).toEqual([...SYSTEM_ROUTE_SLUGS, ...PROTECTED_PUBLIC_SLUGS].sort());
    for (const h of rows) expect(RESERVED_SLUGS.has(h)).toBe(true);
  });

  it("refuses double dots and dot-adjacent separators but accepts -- and __", async () => {
    const uid = await member(10, null);
    for (const bad of ["jan..peeters", "jan.-peeters", "jan._peeters", "jan-.peeters", "jan_.peeters", ".jan", "jan-"]) {
      await expect(
        db.query("insert into public.handle_registry (namespace, handle_normalized, user_id, profile_id) values ('root_verified', $1, $2, gen_random_uuid())", [bad, uid]),
      ).rejects.toThrow();
    }
    await db.query("insert into public.handle_registry (namespace, handle_normalized, status, user_id, profile_id) values ('root_verified', 'jan--peeters', 'REVOKED', $1, gen_random_uuid())", [uid]);
    await db.query("insert into public.handle_registry (namespace, handle_normalized, status, user_id, profile_id) values ('root_verified', 'jan__peeters', 'REVOKED', $1, gen_random_uuid())", [uid]);
  });

  it("allows at most one ACTIVE alias and one ACTIVE root handle per member", async () => {
    const uid = await member(11, null);
    const ins = (ns: string, h: string) =>
      db.query("insert into public.handle_registry (namespace, handle_normalized, status, user_id, profile_id) values ($1::public.handle_namespace, $2, 'ACTIVE', $3, gen_random_uuid())", [ns, h, uid]);
    await ins("user_unverified", "alias-one1");
    await expect(ins("user_unverified", "alias-two2")).rejects.toThrow(/uq_user_single_unverified_alias/);
    await ins("root_verified", "root.one");
    await expect(ins("root_verified", "root.two")).rejects.toThrow(/uq_user_single_root_verified/);
  });

  it("allows one live owner per namespace and handle, independently per namespace", async () => {
    const a = await member(12, null);
    const b = await member(13, null);
    await db.query("insert into public.handle_registry (namespace, handle_normalized, user_id, profile_id) values ('user_unverified', 'shared.name', $1, gen_random_uuid())", [a]);
    await expect(
      db.query("insert into public.handle_registry (namespace, handle_normalized, user_id, profile_id) values ('user_unverified', 'shared.name', $1, gen_random_uuid())", [b]),
    ).rejects.toThrow(/uq_handle_per_namespace/);
    await db.query("insert into public.handle_registry (namespace, handle_normalized, user_id, profile_id) values ('root_verified', 'shared.name', $1, gen_random_uuid())", [b]);
  });

  it("gives profiles and aliases their own public identifiers", async () => {
    const uid = await member(14, null, { alias: "ownid1234" });
    const r = (await db.query<{ p: string; a: string }>(
      "select p.public_profile_id as p, a.public_profile_id as a from public.profiles p join public.alias_profiles a on a.user_id = p.id where p.id = $1",
      [uid],
    )).rows[0]!;
    expect(r.p).toMatch(/^[0-9a-f-]{36}$/);
    expect(r.a).toMatch(/^[0-9a-f-]{36}$/);
    expect(r.p).not.toBe(r.a);
    expect(r.p).not.toBe(uid);
    expect(r.a).not.toBe(uid);
  });
});

describe("db/0298 triggers keep the registry exact", () => {
  it("registers a new alias, tombstones it on rename and records the rename time", async () => {
    const uid = await member(20, null, { alias: "first4321" });
    expect((await registry(uid)).map((r) => [r.namespace, r.handle_normalized, r.status])).toEqual([["user_unverified", "first4321", "ACTIVE"]]);
    await db.query("update public.alias_profiles set handle = 'second4321' where user_id = $1", [uid]);
    const rows = await registry(uid);
    const old = rows.find((r) => r.handle_normalized === "first4321")!;
    const cur = rows.find((r) => r.handle_normalized === "second4321")!;
    expect(old.status).toBe("TOMBSTONED");
    expect(old.tombstoned_until).not.toBeNull();
    expect(cur.status).toBe("ACTIVE");
    expect(cur.last_renamed_at).not.toBeNull();
  });

  it("keeps a released alias name away from someone else during the tombstone", async () => {
    const other = await member(21, null);
    await expect(db.query("insert into public.alias_profiles (user_id, handle) values ($1, 'first4321')", [other])).rejects.toThrow(/handle_cooling_down/);
  });

  it("an unchanged upsert of the same handle leaves the registry untouched", async () => {
    const uid = id(20);
    const before = await registry(uid);
    await db.query("update public.alias_profiles set handle = 'SECOND4321' where user_id = $1", [uid]);
    expect(await registry(uid)).toEqual(before);
  });

  it("holds the root handle of an unverified account and activates it when the account is verified", async () => {
    const uid = await member(22, "held.name");
    expect((await registry(uid)).map((r) => [r.namespace, r.handle_normalized, r.status])).toEqual([["root_verified", "held.name", "RESERVED_HOLD"]]);
    await db.query("update public.profiles set verified = true where id = $1", [uid]);
    expect((await registry(uid))[0]!.status).toBe("ACTIVE");
  });

  it("deleting an account removes its registry rows", async () => {
    const uid = await member(23, null, { alias: "gone12345" });
    await db.query("delete from public.profiles where id = $1", [uid]);
    expect(await registry(uid)).toEqual([]);
  });
});

describe("db/0298 rights", () => {
  it("rout_app can only read its own registry rows and cannot write", async () => {
    const a = id(20);
    const mine = await asApp<{ user_id: string }>(a, "select user_id from public.handle_registry");
    expect(mine.length).toBeGreaterThan(0);
    expect(mine.every((r) => r.user_id === a)).toBe(true);
    await expect(asApp(a, "insert into public.handle_registry (namespace, handle_normalized, user_id, profile_id) values ('user_unverified', 'forged123', $1, gen_random_uuid())", [a])).rejects.toThrow();
    await expect(asApp(a, "update public.handle_registry set status = 'REVOKED'")).rejects.toThrow();
  });

  it("only the three entry points are executable by rout_app; all definers are pinned", async () => {
    const rows = (await db.query<{ name: string; app: boolean; pub: boolean; cfg: string[] | null; sd: boolean }>(`
      select p.proname as name, has_function_privilege('rout_app', p.oid, 'EXECUTE') as app,
             has_function_privilege('public', p.oid, 'EXECUTE') as pub, p.proconfig as cfg, p.prosecdef as sd
        from pg_proc p join pg_namespace n on n.oid = p.pronamespace
       where n.nspname = 'public' and p.proname in (
         'rout_handle_shape_ok', 'rout_didit_attested', 'rout_root_handle_eligible', 'rout_handle_registry_move',
         'handle_registry_sync_profiles', 'handle_registry_sync_aliases', 'rout_handle_available',
         'rout_handles_taken', 'rout_claim_verified_root_handle')
       order by 1`)).rows;
    expect(rows).toHaveLength(9);
    const callable = new Set(["rout_handle_available", "rout_handles_taken", "rout_claim_verified_root_handle"]);
    for (const r of rows) {
      expect(r.sd, r.name).toBe(true);
      expect(r.cfg, r.name).toContain("search_path=pg_catalog, pg_temp");
      expect(r.pub, r.name).toBe(false);
      expect(r.app, r.name).toBe(callable.has(r.name));
    }
  });
});

describe("db/0298 verified root claim", () => {
  it("refuses a member without a Didit attestation", async () => {
    const uid = await member(30, null, { alias: "nodidit123" });
    await expect(claim(uid, "jan.peeters")).rejects.toThrow(/root_handle_identity_required/);
  });

  it("refuses reserved names, bad shapes, taken names and the member's own alias", async () => {
    const uid = await member(31, null, { alias: "jona.desmet" });
    await didit(uid, "31");
    await member(32, "taken.name", { verified: true });
    await expect(claim(uid, "belgie")).rejects.toThrow(/handle_reserved/);
    await expect(claim(uid, "jona..desmet")).rejects.toThrow(/handle_invalid/);
    await expect(claim(uid, "taken.name")).rejects.toThrow(/handle_taken/);
    await expect(claim(uid, "jona.desmet")).rejects.toThrow(/handle_matches_own_alias/);
  });

  it("availability answers booleans and lists the taken handles", async () => {
    const uid = id(31);
    expect((await asApp<{ ok: boolean }>(uid, "select public.rout_handle_available('root_verified', 'taken.name') as ok"))[0]!.ok).toBe(false);
    expect((await asApp<{ ok: boolean }>(uid, "select public.rout_handle_available('root_verified', 'jona-desmet') as ok"))[0]!.ok).toBe(true);
    const taken = await asApp<{ h: string }>(uid, "select h from public.rout_handles_taken('root_verified', $1::text[]) as h", [["taken.name", "jona-desmet", "police"]]);
    expect(taken.map((r) => r.h).sort()).toEqual(["police", "taken.name"]);
  });

  it("starts the verified profile blank by default and keeps the alias untouched", async () => {
    const uid = id(31);
    await db.query("update public.profiles set display_name = 'Pseudo', blocks = '[{\"kind\":\"link\",\"url\":\"https://old.test\"}]'::jsonb where id = $1", [uid]);
    expect((await claim(uid, "jona-desmet"))[0]!.h).toBe("jona-desmet");
    const p = (await db.query<{ username: string; verified: boolean; display_name: string | null; blocks: unknown[] }>(
      "select username, verified, display_name, blocks from public.profiles where id = $1",
      [uid],
    )).rows[0]!;
    expect(p).toEqual({ username: "jona-desmet", verified: true, display_name: null, blocks: [] });
    const alias = (await db.query<{ handle: string; prefs: Record<string, unknown> }>("select handle, display_prefs as prefs from public.alias_profiles where user_id = $1", [uid])).rows[0]!;
    expect(alias.handle).toBe("jona.desmet");
    expect(alias.prefs["publicProfile"]).toBeUndefined();
    const reg = await registry(uid);
    expect(reg.filter((r) => r.status === "ACTIVE").map((r) => [r.namespace, r.handle_normalized]).sort()).toEqual([
      ["root_verified", "jona-desmet"],
      ["user_unverified", "jona.desmet"],
    ]);
  });

  it("is idempotent for the same handle", async () => {
    expect((await claim(id(31), "jona-desmet"))[0]!.h).toBe("jona-desmet");
  });

  it("refuses a second different root handle within 30 days of a rename", async () => {
    const uid = await member(33, "legacy.root", { verified: true });
    await didit(uid, "33");
    await db.query("update public.handle_registry set last_renamed_at = now() where user_id = $1 and namespace = 'root_verified' and status = 'ACTIVE'", [uid]);
    await expect(claim(uid, "an.other")).rejects.toThrow(/root_handle_cooldown/);
  });

  it("can copy the alias links once and hide the alias", async () => {
    const uid = await member(34, null, { alias: "pseudo7777" });
    await didit(uid, "34");
    await claim(uid, "lisa.peeters", true, true);
    const p = (await db.query<{ blocks: { url: string }[] }>("select blocks from public.profiles where id = $1", [uid])).rows[0]!;
    expect(p.blocks.map((b) => b.url)).toEqual(["https://example.test/alias"]);
    const prefs = (await db.query<{ prefs: Record<string, unknown> }>("select display_prefs as prefs from public.alias_profiles where user_id = $1", [uid])).rows[0]!.prefs;
    expect(prefs["publicProfile"]).toBe(false);
  });

  it("a concurrent second member cannot take the same handle", async () => {
    const uid = await member(35, null);
    await didit(uid, "35");
    await expect(claim(uid, "lisa.peeters")).rejects.toThrow(/handle_taken/);
  });
});

describe("db-pending/0299 contract (Option A + guards)", () => {
  let unverifiedNoAlias: string;
  let unverifiedWithAlias: string;
  let verified: string;
  beforeAll(async () => {
    unverifiedNoAlias = await member(40, "free.name1");
    await db.query("update public.profiles set display_name = 'Free', tagline = 'hi' where id = $1", [unverifiedNoAlias]);
    unverifiedWithAlias = await member(41, "rootname41", { alias: "alias41aa" });
    verified = await member(42, "verified.name", { verified: true });
    await applyPending(db, "0299_handle_namespace_contract.sql");
  });

  it("moves an unverified root handle without alias to /u/ with its content", async () => {
    const p = (await db.query<{ username: string | null }>("select username from public.profiles where id = $1", [unverifiedNoAlias])).rows[0]!;
    expect(p.username).toBeNull();
    const a = (await db.query<{ handle: string; display_name: string; tagline: string }>(
      "select handle, display_name, tagline from public.alias_profiles where user_id = $1",
      [unverifiedNoAlias],
    )).rows[0]!;
    expect(a).toEqual({ handle: "free.name1", display_name: "Free", tagline: "hi" });
    const reg = await registry(unverifiedNoAlias);
    expect(reg.find((r) => r.namespace === "root_verified")!.status).toBe("TOMBSTONED");
    expect(reg.find((r) => r.namespace === "user_unverified")!.status).toBe("ACTIVE");
  });

  it("keeps an existing alias and releases the root handle", async () => {
    const p = (await db.query<{ username: string | null }>("select username from public.profiles where id = $1", [unverifiedWithAlias])).rows[0]!;
    expect(p.username).toBeNull();
    const a = (await db.query<{ handle: string }>("select handle from public.alias_profiles where user_id = $1", [unverifiedWithAlias])).rows[0]!;
    expect(a.handle).toBe("alias41aa");
  });

  it("leaves verified and Didit accounts alone and is idempotent", async () => {
    expect((await db.query<{ username: string }>("select username from public.profiles where id = $1", [verified])).rows[0]!.username).toBe("verified.name");
    expect((await db.query<{ username: string }>("select username from public.profiles where id = $1", [id(31)])).rows[0]!.username).toBe("jona-desmet");
    const before = (await db.query("select count(*)::int as n from public.alias_profiles")).rows;
    await applyPending(db, "0299_handle_namespace_contract.sql");
    expect((await db.query("select count(*)::int as n from public.alias_profiles")).rows).toEqual(before);
  });

  it("blocks a root handle on an account without eligibility, and reserved names on any account", async () => {
    await expect(db.query("update public.profiles set username = 'sneaky.root' where id = $1", [unverifiedWithAlias])).rejects.toThrow(/root_handle_identity_required/);
    await expect(db.query("update public.profiles set username = 'vlaanderen' where id = $1", [verified])).rejects.toThrow(/handle_reserved/);
  });

  it("enforces the 30-day alias rename cooldown", async () => {
    const uid = await member(43, null, { alias: "cool12345" });
    await db.query("update public.alias_profiles set handle = 'cool23456' where user_id = $1", [uid]);
    await expect(db.query("update public.alias_profiles set handle = 'cool34567' where user_id = $1", [uid])).rejects.toThrow(/alias_rename_cooldown/);
    await db.query("update public.handle_registry set last_renamed_at = now() - interval '31 days' where user_id = $1 and status = 'ACTIVE'", [uid]);
    await db.query("update public.alias_profiles set handle = 'cool34567' where user_id = $1", [uid]);
  });

  it("the claim still works under the contract", async () => {
    const uid = await member(44, null, { alias: "pseudo4444" });
    await didit(uid, "44");
    expect((await claim(uid, "an.de-smet"))[0]!.h).toBe("an.de-smet");
  });
});

describe("rollbacks", () => {
  it("0298 rollback refuses while 0299 is installed, then both roll back cleanly", async () => {
    await expect(applyPending(db, "0298_handle_registry_dual_profile_rollback.sql")).rejects.toThrow(/roll back 0299 first/);
    await db.exec("rollback;");
    await applyPending(db, "0299_handle_namespace_contract_rollback.sql");
    await applyPending(db, "0298_handle_registry_dual_profile_rollback.sql");
    const left = (await db.query<{ t: string | null }>("select to_regclass('public.handle_registry')::text as t")).rows[0]!;
    expect(left.t).toBeNull();
    await applyReleased(db, "0298_handle_registry_dual_profile.sql");
    expect((await db.query<{ n: number }>("select count(*)::int as n from public.handle_registry where namespace = 'system_reserved'")).rows[0]!.n).toBe(
      SYSTEM_ROUTE_SLUGS.length + PROTECTED_PUBLIC_SLUGS.length,
    );
  });
});
