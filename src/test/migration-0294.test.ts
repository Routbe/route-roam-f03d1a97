// @vitest-environment node
/**
 * db/0294 on an offline replay of db/: EUDI wallet issuance, revocation and verification state.
 * rout_app has no table rights, offers go only to verified humans (claims come from the database,
 * never the caller), a pre-authorized code is redeemed once with a lock after five wrong
 * transaction codes, an access token yields exactly one credential, revocation is owner-only and
 * flips the public status input, and an OpenID4VP request completes once, with the right state,
 * readable only by its owner. Neon is not touched.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { PGlite } from "@electric-sql/pglite";
import { replayDb } from "../../scripts/formal-rls/replay";

const KYC = "00000000-0000-4000-8000-0000000004a1";
const PLAIN = "00000000-0000-4000-8000-0000000004a2";
const OTHER = "00000000-0000-4000-8000-0000000004a3";
const H = (c: string) => c.repeat(64).slice(0, 64);
const S = (c: string) => c.repeat(43).slice(0, 43);

let db: PGlite;
beforeAll(async () => {
  db = await replayDb();
  await db.exec(`
    insert into public.users (id, email) values ('${KYC}', 'k@example.test'), ('${PLAIN}', 'p@example.test'), ('${OTHER}', 'o@example.test');
    insert into public.identity_verifications (user_id, is_verified, verification_provider, unique_human_id) values ('${KYC}', true, 'didit', 'n-0294');
    insert into public.verified_identity_nullifiers (universal_nullifier, user_id, provider, anchor_kind, has_legal_identity, evidence, age_floor)
      values ('${H("d")}', '${KYC}', 'didit', 'document', true, 'kyc_document', 18);
  `);
}, 300_000);
afterAll(async () => {
  await db?.close();
});

async function as<T>(userId: string | null, query: string, params: unknown[] = []): Promise<T[]> {
  await db.exec("begin; set local role rout_app;");
  try {
    if (userId) await db.query("select set_config('rout.current_user_id', $1, true)", [userId]);
    const r = (await db.query<T>(query, params)).rows;
    await db.exec("commit;");
    return r;
  } catch (e) {
    await db.exec("rollback;");
    throw e;
  }
}
const offer = async (user: string | null, code: string, tx: string) =>
  (await as<{ id: string | null }>(user, "select public.rout_vci_offer_create('rout_verified_human', $1, $2) as id", [code, tx]))[0]!.id;
const redeem = async (code: string, tx: string, token: string) =>
  (await as<{ r: string }>(null, "select public.rout_vci_redeem($1, $2, $3) as r", [code, tx, token]))[0]!.r;
const issue = (token: string, jti: string, days = 365) =>
  as<{ status_idx: string; config: string; claims: Record<string, unknown>; expires_at: string }>(null, "select * from public.rout_vci_issue($1, $2, $3)", [token, jti, days]);
const active = async () => (await as<{ status_idx: string }>(null, "select status_idx from public.rout_public_status_active()")).map((r) => Number(r.status_idx));

describe("db/0294 EUDI wallet", () => {
  it("rout_app cannot read or write the tables or the status sequence directly", async () => {
    for (const t of ["oid4vci_offers", "wallet_credentials", "oid4vp_requests"]) {
      await expect(as(KYC, `select * from public.${t}`)).rejects.toThrow(/permission denied/);
    }
    await expect(as(KYC, "select nextval('public.wallet_credentials_status_idx_seq')")).rejects.toThrow(/permission denied/);
  });

  it("offers go only to a signed-in verified human, with claims taken from the database", async () => {
    expect(await offer(null, H("1"), H("2"))).toBeNull();
    expect(await offer(PLAIN, H("1"), H("2"))).toBeNull();
    expect(await offer(KYC, "not-a-hash", H("2"))).toBeNull();
    const id = await offer(KYC, H("1"), H("2"));
    expect(id).toMatch(/^[0-9a-f-]{36}$/);
    const row = (await db.query<{ claims: unknown; user_id: string }>("select claims, user_id from public.oid4vci_offers where id = $1", [id])).rows[0]!;
    expect(row).toEqual({ claims: { verified_human: true, age_floor: 18 }, user_id: KYC });
  });

  it("allows at most five offers per member per ten minutes", async () => {
    for (const c of ["3", "4", "5", "6"]) expect(await offer(KYC, H(c), H("2"))).not.toBeNull();
    expect(await offer(KYC, H("7"), H("2"))).toBeNull();
  });

  it("five wrong transaction codes lock the offer; the right one then no longer works", async () => {
    for (let i = 0; i < 5; i++) expect(await redeem(H("3"), H("9"), H("a"))).toBe("invalid_tx");
    expect(await redeem(H("3"), H("2"), H("a"))).toBe("locked");
  });

  it("redeems a code once and refuses unknown, malformed and expired codes", async () => {
    expect(await redeem(H("f"), H("2"), H("b"))).toBe("invalid");
    expect(await redeem("x", H("2"), H("b"))).toBe("invalid");
    expect(await redeem(H("1"), H("2"), H("b"))).toBe("ok");
    expect(await redeem(H("1"), H("2"), H("c"))).toBe("used");
    await db.query("update public.oid4vci_offers set expires_at = now() - interval '1 second' where code_hash = $1", [H("4")]);
    expect(await redeem(H("4"), H("2"), H("c"))).toBe("expired");
  });

  it("an access token yields exactly one credential, starting at status index 0, at most 365 days", async () => {
    expect(await issue(H("e"), H("7"))).toEqual([]);
    const [row] = await issue(H("b"), H("7"), 9999);
    expect(Number(row!.status_idx)).toBe(0);
    expect(row!.config).toBe("rout_verified_human");
    expect(row!.claims).toEqual({ verified_human: true, age_floor: 18 });
    const days = (new Date(row!.expires_at).getTime() - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(364.9);
    expect(days).toBeLessThan(365.1);
    expect(await issue(H("b"), H("8"))).toEqual([]);
    expect(await active()).toEqual([0]);
  });

  it("refuses a token redeemed more than five minutes ago", async () => {
    expect(await redeem(H("5"), H("2"), H("d"))).toBe("ok");
    await db.query("update public.oid4vci_offers set redeemed_at = now() - interval '6 minutes' where token_hash = $1", [H("d")]);
    expect(await issue(H("d"), H("9"))).toEqual([]);
  });

  it("only the owner lists and revokes a credential, and revocation removes it from the status input", async () => {
    expect(await as(OTHER, "select * from public.rout_vci_mine()")).toEqual([]);
    expect((await as<{ ok: boolean }>(OTHER, "select public.rout_vci_revoke(0) as ok"))[0]!.ok).toBe(false);
    expect(await active()).toEqual([0]);
    const mine = await as<{ status_idx: string; revoked_at: string | null }>(KYC, "select * from public.rout_vci_mine()");
    expect(mine.map((r) => [Number(r.status_idx), r.revoked_at])).toEqual([[0, null]]);
    expect((await as<{ ok: boolean }>(KYC, "select public.rout_vci_revoke(0) as ok"))[0]!.ok).toBe(true);
    expect((await as<{ ok: boolean }>(KYC, "select public.rout_vci_revoke(0) as ok"))[0]!.ok).toBe(false);
    expect(await active()).toEqual([]);
  });

  it("an expired credential is no longer in the status input", async () => {
    expect(await redeem(H("6"), H("2"), H("6"))).toBe("ok");
    const [row] = await issue(H("6"), H("a"));
    expect(await active()).toEqual([Number(row!.status_idx)]);
    await db.query("update public.wallet_credentials set expires_at = now() - interval '1 second' where status_idx = $1", [row!.status_idx]);
    expect(await active()).toEqual([]);
  });

  it("an OpenID4VP request completes once, only with its state, and only its owner reads the result", async () => {
    const dcql = { credentials: [{ id: "rout", format: "dc+sd-jwt", claims: [{ path: ["age_over_18"] }] }] };
    expect((await as<{ id: string | null }>(null, "select public.rout_vp_request_create('x', $1, $2, $3::jsonb) as id", [S("n"), S("s"), JSON.stringify(dcql)]))[0]!.id).toBeNull();
    const id = (await as<{ id: string }>(OTHER, "select public.rout_vp_request_create('Bar', $1, $2, $3::jsonb) as id", [S("n"), S("s"), JSON.stringify(dcql)]))[0]!.id;
    const wallet = (await as<{ nonce: string; state: string; status: string }>(null, "select * from public.rout_vp_request_for_wallet($1::uuid)", [id]))[0]!;
    expect(wallet).toMatchObject({ nonce: S("n"), state: S("s"), status: "pending" });
    const complete = async (state: string, status: string) =>
      (await as<{ ok: boolean }>(null, "select public.rout_vp_request_complete($1::uuid, $2, $3, $4::jsonb) as ok", [id, state, status, JSON.stringify({ valid: status === "verified" })]))[0]!.ok;
    expect(await complete(S("t"), "verified")).toBe(false);
    expect(await complete(S("s"), "pending")).toBe(false);
    expect(await complete(S("s"), "verified")).toBe(true);
    expect(await complete(S("s"), "rejected")).toBe(false);
    expect(await as(KYC, "select * from public.rout_vp_request_mine($1::uuid)", [id])).toEqual([]);
    const mine = (await as<{ status: string; result: unknown }>(OTHER, "select * from public.rout_vp_request_mine($1::uuid)", [id]))[0]!;
    expect(mine).toMatchObject({ status: "verified", result: { valid: true } });
  });

  it("an expired OpenID4VP request can no longer be completed", async () => {
    const id = (await as<{ id: string }>(OTHER, "select public.rout_vp_request_create('Late', $1, $2, '{}'::jsonb) as id", [S("m"), S("q")]))[0]!.id;
    await db.query("update public.oid4vp_requests set expires_at = now() - interval '1 second' where id = $1", [id]);
    expect((await as<{ ok: boolean }>(null, "select public.rout_vp_request_complete($1::uuid, $2, 'verified', '{}'::jsonb) as ok", [id, S("q")]))[0]!.ok).toBe(false);
  });
});
