// @vitest-environment node
/**
 * db/0290 (live on Neon since 2026-11-17) on an offline replay of db/ up to 0289, applied with the definer guard in the same
 * transaction. Never touches Neon. Proves:
 *   - the age floor is stored only through rout_kyc_attest (0..21), only rises for the same member,
 *     and the 6-argument form keeps working without an age;
 *   - rout_my_identity_claims answers only the caller's own claims (green only from zk_proof rows);
 *   - a KYC-attested owner may link an IBAN without the name match, a domain-only workspace keeps it;
 *   - sign requests: rout_app has no table rights, only signed-in members open them, only a member
 *     with a KYC legal identity marks one signed, once, and only the owner revokes;
 *   - every new definer runs with search_path pg_catalog, pg_temp; PUBLIC executes none of them;
 *   - the rollback refuses while data exists and restores 0288/0283 when empty.
 */
import type { PGlite } from "@electric-sql/pglite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { applyReleased, replayDb, ROOT } from "../../scripts/formal-rls/replay";
import { universalNullifier } from "@/lib/kyc/nullifier";

const KYC = "00000000-0000-4000-8000-000000002901";
const OTHER = "00000000-0000-4000-8000-000000002902";
const PLAIN = "00000000-0000-4000-8000-000000002903";
const WS_KYC = "00000000-0000-4000-8000-000000002911";
const WS_DOMAIN = "00000000-0000-4000-8000-000000002912";
const IBAN = "BE68539007547034";
const nf = (s: string) => universalNullifier(new TextEncoder().encode(s), "p".repeat(48));
const ATTEST7 = "select public.rout_kyc_attest($1, $2::text[], $3::text[], $4, $5, $6, $7::smallint) as code";
const ATTEST6 = "select public.rout_kyc_attest($1, $2::text[], $3::text[], $4, $5, $6) as code";

let db: PGlite;
beforeAll(async () => {
  db = await replayDb((f) => f < "0290");
  await applyReleased(db, "0290_identity_os_sign.sql");
  await db.exec(`
    insert into public.users (id, email) values ('${KYC}', 'k@example.test'), ('${OTHER}', 'o@example.test'), ('${PLAIN}', 'p@example.test');
    insert into public.workspaces (id, name, slug, domain, domain_verified_at) values
      ('${WS_KYC}', 'Kyc Club', 'kyc-club', null, null), ('${WS_DOMAIN}', 'Domein BV', 'domein-bv-0290', 'domein0290.example', now());
    insert into public.workspace_members (workspace_id, user_id, role) values ('${WS_KYC}', '${KYC}', 'owner'), ('${WS_DOMAIN}', '${PLAIN}', 'owner');
  `);
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

describe("age floor and own claims", () => {
  it("validates the age floor and stores it only for the caller", async () => {
    expect((await one<{ code: string }>(KYC, ATTEST7, ["didit", [nf("BEL:PN:1")], ["personal_number"], true, true, "BEL", 22])).code).toBe("invalid_input");
    expect((await one<{ code: string }>(KYC, ATTEST7, ["didit", [nf("BEL:PN:1")], ["personal_number"], true, true, "BEL", 17])).code).toBe("ok");
    // Re-attesting may raise, never lower, the floor.
    expect((await one<{ code: string }>(KYC, ATTEST7, ["didit", [nf("BEL:PN:1")], ["personal_number"], true, true, "BEL", 19])).code).toBe("ok");
    expect((await one<{ code: string }>(KYC, ATTEST7, ["didit", [nf("BEL:PN:1")], ["personal_number"], true, true, "BEL", 13])).code).toBe("ok");
    const [r] = (await db.query<{ a: number }>(`select age_floor as a from public.verified_identity_nullifiers where user_id = '${KYC}'`)).rows;
    expect(r!.a).toBe(19);
    // Another member cannot touch that row's age through a conflict.
    expect((await one<{ code: string }>(OTHER, ATTEST7, ["itsme", [nf("BEL:PN:1")], ["personal_number"], true, true, "BEL", 21])).code).toBe("identity_already_attested_across_providers");
  });

  it("keeps the 6-argument form (the 0288 marker) working without an age", async () => {
    expect((await one<{ code: string }>(OTHER, ATTEST6, ["didit", [nf("NLD:D:X1")], ["document"], true, true, "NLD"])).code).toBe("ok");
    const [r] = (await db.query<{ a: number | null }>(`select age_floor as a from public.verified_identity_nullifiers where user_id = '${OTHER}'`)).rows;
    expect(r!.a).toBeNull();
  });

  it("answers only the caller's own claims; the green flag only from a zero-knowledge row", async () => {
    const mine = await one<Record<string, unknown>>(KYC, "select * from public.rout_my_identity_claims()");
    expect(mine).toEqual({ has_legal_identity: true, is_real_human: false, age_floor: 19, root_nullifier: nf("BEL:PN:1") });
    const plain = await one<Record<string, unknown>>(PLAIN, "select * from public.rout_my_identity_claims()");
    expect(plain).toEqual({ has_legal_identity: false, is_real_human: false, age_floor: null, root_nullifier: null });
    expect(await as(null, "select * from public.rout_my_identity_claims()")).toEqual([]);
  });

  it("rout_app still cannot read the nullifier column directly", async () => {
    await expect(as(KYC, "select universal_nullifier from public.verified_identity_nullifiers")).rejects.toThrow();
  });
});

describe("workspace IBAN", () => {
  const SAVE = "select public.rout_ws_support_save($1::uuid, true, $2, $3, '{500}'::int[], true, 100, null, false) as r";
  it("a KYC-attested owner links an IBAN without a stored name", async () => {
    expect((await one<{ r: string }>(KYC, SAVE, [WS_KYC, IBAN, "Any Holder"])).r).toBe("ok");
    const page = await as<{ iban: string }>(null, "select iban from public.rout_public_ws_support('kyc-club')");
    expect(page.map((p) => p.iban)).toEqual([IBAN]);
    expect((await one<{ owner_didit: boolean }>(KYC, "select owner_didit from public.rout_ws_support_get($1::uuid)", [WS_KYC])).owner_didit).toBe(true);
  });
  it("a domain-only workspace keeps the holder-name match", async () => {
    expect((await one<{ r: string }>(PLAIN, SAVE, [WS_DOMAIN, IBAN, "Someone Else"])).r).toBe("name_mismatch");
    expect((await one<{ r: string }>(PLAIN, SAVE, [WS_DOMAIN, IBAN, "Domein BV"])).r).toBe("ok");
  });
  it("outsiders cannot manage, and the owner-KYC helper is not callable by the app", async () => {
    expect((await one<{ r: string }>(OTHER, SAVE, [WS_KYC, IBAN, "X"])).r).toBe("forbidden");
    await expect(as(KYC, "select public.rout_ws_support_owner_kyc($1::uuid)", [WS_KYC])).rejects.toThrow();
  });
});

describe("sign requests", () => {
  const ct = () => new Uint8Array(128).map((_, i) => i);
  const hex = (c: string) => c.repeat(64);
  let id = "";

  it("rout_app and PUBLIC hold no table rights", async () => {
    for (const priv of ["SELECT", "INSERT", "UPDATE", "DELETE"]) {
      for (const role of ["rout_app", "public"]) {
        const [r] = (await db.query<{ ok: boolean }>("select has_table_privilege($1, 'public.sign_requests', $2) as ok", [role, priv])).rows;
        expect(r!.ok, `${role} ${priv}`).toBe(false);
      }
    }
  });

  it("creates only with a context and valid input", async () => {
    expect((await one<{ id: string | null }>(null, "select public.rout_sign_request_create($1, 7, 30) as id", [ct()])).id).toBeNull();
    expect((await one<{ id: string | null }>(PLAIN, "select public.rout_sign_request_create($1, 31, 30) as id", [ct()])).id).toBeNull();
    expect((await one<{ id: string | null }>(PLAIN, "select public.rout_sign_request_create($1, 7, 5) as id", [ct()])).id).toBeNull();
    id = (await one<{ id: string }>(PLAIN, "select public.rout_sign_request_create($1, 7, 30) as id", [ct()])).id;
    expect(id).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("opens for signed-in members only, signed copy only for owner or signer", async () => {
    expect(await as(null, "select * from public.rout_sign_request_open($1::uuid)", [id])).toEqual([]);
    const r = await one<Record<string, unknown>>(OTHER, "select status, is_owner, signed_ciphertext from public.rout_sign_request_open($1::uuid)", [id]);
    expect(r).toEqual({ status: "open", is_owner: false, signed_ciphertext: null });
  });

  it("only a KYC legal identity marks it signed, exactly once", async () => {
    const MARK = "select public.rout_sign_request_mark_signed($1::uuid, $2, $3, $4, $5) as r";
    const src = (await one<{ s: string }>(PLAIN, "select ciphertext_sha256 as s from public.rout_sign_request_open($1::uuid)", [id])).s;
    expect((await one<{ r: string }>(PLAIN, MARK, [id, src, hex("a"), hex("b"), ct()])).r).toBe("no_legal_identity");
    expect((await one<{ r: string }>(KYC, MARK, [id, src, "zz", hex("b"), ct()])).r).toBe("invalid_input");
    expect((await one<{ r: string }>(KYC, MARK, [id, hex("e"), hex("a"), hex("b"), ct()])).r).toBe("source_changed");
    expect((await one<{ r: string }>(KYC, MARK, [id, src, hex("a"), hex("b"), ct()])).r).toBe("ok");
    expect((await one<{ r: string }>(OTHER, MARK, [id, src, hex("c"), hex("d"), ct()])).r).toBe("not_open");
    const owner = await one<{ status: string; signed_ciphertext: Uint8Array | null }>(PLAIN, "select status, signed_ciphertext from public.rout_sign_request_open($1::uuid)", [id]);
    expect(owner.status).toBe("signed");
    expect(owner.signed_ciphertext).not.toBeNull();
  });

  it("only the owner revokes an open request; revoked requests disappear", async () => {
    const other = (await one<{ id: string }>(PLAIN, "select public.rout_sign_request_create($1, 1, 10) as id", [ct()])).id;
    expect((await one<{ r: string }>(KYC, "select public.rout_sign_request_revoke($1::uuid) as r", [other])).r).toBe("not_found");
    expect((await one<{ r: string }>(PLAIN, "select public.rout_sign_request_revoke($1::uuid) as r", [other])).r).toBe("ok");
    expect(await as(KYC, "select * from public.rout_sign_request_open($1::uuid)", [other])).toEqual([]);
    const mine = await as<{ id: string }>(PLAIN, "select id from public.rout_sign_requests_mine()");
    expect(mine.map((m) => m.id)).toEqual([id]);
  });
});

describe("definers", () => {
  it("pin search_path and are not executable by PUBLIC", async () => {
    const rows = (await db.query<{ f: string; cfg: string[]; pub: boolean }>(`
      select p.oid::regprocedure::text as f, p.proconfig as cfg, has_function_privilege('public', p.oid, 'EXECUTE') as pub
        from pg_proc p where p.pronamespace = 'public'::regnamespace
         and p.proname in ('rout_kyc_attest', 'rout_my_identity_claims', 'rout_ws_support_owner_kyc', 'rout_sign_request_create',
           'rout_sign_request_open', 'rout_sign_request_mark_signed', 'rout_sign_request_revoke', 'rout_sign_requests_mine')`)).rows;
    expect(rows.length).toBe(9);
    for (const r of rows) {
      expect(r.cfg, r.f).toEqual(["search_path=pg_catalog, pg_temp"]);
      expect(r.pub, r.f).toBe(false);
    }
  });
});

describe("rollback", () => {
  it("refuses while data exists, restores 0288/0283 when empty", async () => {
    const body = readFileSync(join(ROOT, "db-pending", "0290_identity_os_sign_rollback.sql"), "utf8");
    await expect(db.exec(`begin;\n${body}\ncommit;`)).rejects.toThrow(/rollback_0290_refused/);
    await db.exec("rollback;");
    await db.exec("delete from public.sign_requests; update public.verified_identity_nullifiers set age_floor = null;");
    await db.exec(`begin;\n${body}\ncommit;`);
    const [r] = (await db.query<{ seven: string | null; claims: string | null; col: number }>(`
      select to_regprocedure('public.rout_kyc_attest(text,text[],text[],boolean,boolean,text,smallint)')::text as seven,
             to_regprocedure('public.rout_my_identity_claims()')::text as claims,
             (select count(*)::int from information_schema.columns where table_name = 'verified_identity_nullifiers' and column_name = 'age_floor') as col`)).rows;
    expect(r).toEqual({ seven: null, claims: null, col: 0 });
    expect((await one<{ code: string }>(PLAIN, ATTEST6, ["didit", [nf("FRA:D:Z9")], ["document"], true, true, "FRA"])).code).toBe("ok");
  });
});
