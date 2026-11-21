// @vitest-environment node
/**
 * db/0288 (universal identity nullifiers, live on Neon since 2026-11-17) on an offline replay of db/ without it, applied with the
 * definer guard in the same transaction. Never touches Neon. Proves:
 *   - rout_app holds no write right on the table and cannot read the nullifier column;
 *   - rout_kyc_attest registers anchors only for rout.current_user_id, refuses another account's
 *     anchor through another provider with identity_already_attested_across_providers and through
 *     the same provider with duplicate_human, and is idempotent for the same member;
 *   - malformed input and a missing context are refused without writing;
 *   - the public badge and Didit counter functions read the new claims: the blue KYC mark only from a
 *     KYC attestation, the green Real Human shield EXCLUSIVELY from a zero-knowledge proof row;
 *   - no foreign key stays unindexed, the definer runs with search_path pg_catalog, pg_temp;
 *   - the rollback refuses while an attestation exists, and restores 0282 when empty.
 */
import { PGlite } from "@electric-sql/pglite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import fc from "fast-check";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { applyReleased, replayDb, ROOT } from "../../scripts/formal-rls/replay";
import { universalNullifier } from "@/lib/kyc/nullifier";

const A = "00000000-0000-4000-8000-000000000881";
const B = "00000000-0000-4000-8000-000000000882";
const C = "00000000-0000-4000-8000-000000000883";
const D = "00000000-0000-4000-8000-000000000884";
const Z = "00000000-0000-4000-8000-000000000885";
const PEPPER = "p".repeat(48);
const nf = (s: string) => universalNullifier(new TextEncoder().encode(s), PEPPER);
const ATTEST = "select public.rout_kyc_attest($1, $2::text[], $3::text[], $4, $5, $6) as code";

let db: PGlite;
beforeAll(async () => {
  db = await replayDb((f) => f < "0288");
  await applyReleased(db, "0288_universal_identity_nullifiers.sql");
  await db.exec(`
    insert into public.users (id, email) values ('${A}', 'a@example.test'), ('${B}', 'b@example.test'), ('${C}', 'c@example.test');
    insert into public.profiles (id, username) values ('${A}', 'nf-a'), ('${B}', 'nf-b'), ('${C}', 'nf-c')
      on conflict (id) do update set username = excluded.username;
  `);
}, 600_000);
afterAll(async () => { await db?.close(); });

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
const attest = async (user: string | null, provider: string, nfs: string[], kinds: string[], human = true, legal = true, j: string | null = "BEL") =>
  (await asApp<{ code: string }>(user, ATTEST, [provider, nfs, kinds, human, legal, j]))[0]!.code;
const count = async () => Number((await db.query<{ n: number }>("select count(*)::int as n from public.verified_identity_nullifiers")).rows[0]!.n);

describe("rights", () => {
  it("rout_app and PUBLIC cannot write the table or read the nullifier column", async () => {
    for (const priv of ["INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]) {
      for (const role of ["rout_app", "public"]) {
        const [r] = (await db.query<{ ok: boolean }>("select has_table_privilege($1, 'public.verified_identity_nullifiers', $2) as ok", [role, priv])).rows;
        expect(r!.ok, `${role} ${priv}`).toBe(false);
      }
    }
    const [col] = (await db.query<{ ok: boolean }>("select has_column_privilege('rout_app', 'public.verified_identity_nullifiers', 'universal_nullifier', 'SELECT') as ok")).rows;
    expect(col!.ok).toBe(false);
    await expect(asApp(A, "select universal_nullifier from public.verified_identity_nullifiers")).rejects.toThrow();
    await expect(asApp(A, "insert into public.verified_identity_nullifiers (universal_nullifier, user_id, provider, anchor_kind) values ($1, $2, 'didit', 'document')", [nf("x"), A])).rejects.toThrow();
  });

  it("rout_app executes rout_kyc_attest, PUBLIC does not; it is a pinned-path definer", async () => {
    const [r] = (await db.query<{ app: boolean; pub: boolean; cfg: string[]; sd: boolean }>(`
      select has_function_privilege('rout_app', p.oid, 'EXECUTE') as app, has_function_privilege('public', p.oid, 'EXECUTE') as pub,
             p.proconfig as cfg, p.prosecdef as sd
        from pg_proc p where p.oid = 'public.rout_kyc_attest(text,text[],text[],boolean,boolean,text)'::regprocedure`)).rows;
    expect(r).toEqual({ app: true, pub: false, cfg: ["search_path=pg_catalog, pg_temp"], sd: true });
  });

  it("leaves no foreign key in public without an index", async () => {
    const r = await db.query<{ fk: string }>(`
      select c.conrelid::regclass::text || '.' || c.conname as fk from pg_constraint c
       where c.contype = 'f' and c.connamespace = 'public'::regnamespace
         and not exists (select 1 from pg_index i where i.indrelid = c.conrelid
               and (i.indkey::int2[])[0:cardinality(c.conkey) - 1] @> c.conkey
               and c.conkey @> (i.indkey::int2[])[0:cardinality(c.conkey) - 1])`);
    expect(r.rows.map((x) => x.fk)).toEqual([]);
  });
});

describe("rout_kyc_attest", () => {
  it("refuses a missing context and malformed input without writing", async () => {
    expect(await attest(null, "didit", [nf("BEL:PN:1")], ["personal_number"])).toBe("no_context");
    expect(await attest(A, "didit", [], [])).toBe("invalid_input");
    expect(await attest(A, "didit", ["BEL:PN:85073003328"], ["personal_number"])).toBe("invalid_input");
    expect(await attest(A, "didit", [nf("a")], ["passport"])).toBe("invalid_input");
    expect(await attest(A, "didit", [nf("a"), nf("b")], ["document"])).toBe("invalid_input");
    expect(await attest(A, "didit", [nf("a")], ["document"], true, true, "BE")).toBe("invalid_input");
    expect(await attest(A, "didit", [1, 2, 3, 4, 5].map((i) => nf(`x${i}`)), Array(5).fill("document"))).toBe("invalid_input");
    await expect(attest(A, "myspace", [nf("a")], ["document"])).rejects.toThrow();
    // World ID is a zero-knowledge proof, never a KYC document.
    expect(await attest(A, "world_id", [nf("a")], ["provider_subject"])).toBe("invalid_input");
    expect(await count()).toBe(0);
  });

  it("registers the caller's anchors and is idempotent for the same member", async () => {
    const anchors = [nf("BEL:PN:85073003328"), nf("BEL:I:592123456789")];
    expect(await attest(A, "didit", anchors, ["personal_number", "document"])).toBe("ok");
    expect(await attest(A, "didit", anchors, ["personal_number", "document"])).toBe("ok");
    expect(await count()).toBe(2);
    const own = await asApp<{ user_id: string; provider: string; jurisdiction: string }>(A, "select user_id, provider, jurisdiction from public.verified_identity_nullifiers");
    expect(own).toEqual([{ user_id: A, provider: "didit", jurisdiction: "BEL" }, { user_id: A, provider: "didit", jurisdiction: "BEL" }]);
    expect(await asApp(B, "select user_id from public.verified_identity_nullifiers")).toEqual([]);
  });

  it("refuses the same person on another account: across providers and within one", async () => {
    // Same Belgian national number, read by itsme on another account.
    expect(await attest(B, "itsme", [nf("BEL:PN:85073003328")], ["personal_number"])).toBe("identity_already_attested_across_providers");
    // A new passport of the same person through Didit again: the national number still matches.
    expect(await attest(B, "didit", [nf("BEL:PN:85073003328"), nf("BEL:P:EN1234567")], ["personal_number", "document"])).toBe("duplicate_human");
    expect(await count()).toBe(2);
    expect(await attest(B, "itsme", [nf("BEL:PN:90010112345")], ["personal_number"])).toBe("ok");
  });

  it("fast-check: a nullifier never ends up on two accounts", async () => {
    await fc.assert(fc.asyncProperty(fc.array(fc.tuple(fc.constantFrom(A, B, C), fc.constantFrom("didit", "itsme", "digid"), fc.integer({ min: 0, max: 5 })), { minLength: 1, maxLength: 12 }), async (steps) => {
      for (const [u, p, i] of steps) await attest(u, p, [nf(`NLD:PN:10000000${i}`)], ["personal_number"]);
      const [r] = (await db.query<{ n: number }>("select count(*)::int as n from (select universal_nullifier from public.verified_identity_nullifiers group by 1 having count(distinct user_id) > 1) d")).rows;
      expect(r!.n).toBe(0);
    }), { numRuns: 15 });
  });

  it("records every KYC attestation as kyc_document evidence", async () => {
    const [r] = (await db.query<{ n: number }>("select count(*)::int as n from public.verified_identity_nullifiers where evidence <> 'kyc_document'")).rows;
    expect(r!.n).toBe(0);
  });

  it("a zero-knowledge proof row can never claim a legal identity", async () => {
    await expect(db.query(`insert into public.verified_identity_nullifiers
        (universal_nullifier, user_id, provider, anchor_kind, is_real_human, has_legal_identity, evidence)
        values ($1, $2, 'world_id', 'provider_subject', true, true, 'zk_proof')`, [nf("zk-legal"), C])).rejects.toThrow(/zk_no_legal/);
  });

  it("blue KYC mark only from KYC, green Real Human shield only from a zero-knowledge proof", async () => {
    // Z: only a zero-knowledge humanity proof (written as owner; its verifier is a later migration).
    // D: legacy W Identity and manual attestations no longer grant the green shield.
    await db.exec(`insert into public.users (id, email) values ('${D}', 'd@example.test'), ('${Z}', 'z@example.test');
      insert into public.profiles (id, username) values ('${D}', 'nf-d'), ('${Z}', 'nf-z') on conflict (id) do update set username = excluded.username;
      insert into public.identity_verifications (user_id, is_verified, verification_provider, unique_human_id)
        values ('${D}', true, 'w_identity', 'legacy-d');`);
    await db.query(`insert into public.verified_identity_nullifiers
        (universal_nullifier, user_id, provider, anchor_kind, is_real_human, has_legal_identity, evidence)
        values ($1, $2, 'world_id', 'provider_subject', true, false, 'zk_proof')`, [nf("zk-z"), Z]);
    const rows = await asApp<{ user_id: string; didit_legal_identity: boolean; real_human: boolean }>(
      null, "select * from public.rout_public_identity_badges($1::uuid[]) order by user_id", [[A, B, C, D, Z]]);
    const byId = Object.fromEntries(rows.map((r) => [r.user_id, r]));
    // A passed Didit with liveness (is_real_human = true): blue only, never green.
    expect(byId[A]).toMatchObject({ didit_legal_identity: true, real_human: false });
    expect(byId[Z]).toMatchObject({ didit_legal_identity: false, real_human: true });
    expect(byId[D]).toMatchObject({ didit_legal_identity: false, real_human: false });
    const [n] = await asApp<{ n: number }>(null, "select public.rout_public_didit_member_count() as n");
    expect(n!.n).toBeGreaterThanOrEqual(2);
  });
});

describe("rollback", () => {
  it("refuses while attestations exist, then restores 0282 when empty", async () => {
    const rollback = readFileSync(join(ROOT, "db-pending", "0288_universal_identity_nullifiers_rollback.sql"), "utf8");
    await expect(db.exec(`begin;\n${rollback}\n;commit;`)).rejects.toThrow(/rollback_refused/);
    await db.exec("rollback;").catch(() => undefined);
    await db.exec("delete from public.verified_identity_nullifiers");
    await db.exec(`begin;\n${rollback}\n;commit;`);
    const [t] = (await db.query<{ t: string | null }>("select to_regclass('public.verified_identity_nullifiers')::text as t")).rows;
    expect(t!.t).toBeNull();
    const [f] = (await db.query<{ src: string }>("select prosrc as src from pg_proc where oid = 'public.rout_public_identity_badges(uuid[])'::regprocedure")).rows;
    expect(f!.src).not.toContain("verified_identity_nullifiers");
    const [g] = (await db.query<{ ok: boolean }>("select has_function_privilege('rout_app', 'public.rout_public_identity_badges(uuid[])', 'EXECUTE') as ok")).rows;
    expect(g!.ok).toBe(true);
  });
});
