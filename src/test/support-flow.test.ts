// @vitest-environment node
/**
 * The donation flow end to end on an offline replay of db/ (Neon untouched): start a SEPA
 * donation, confirm it from a bunq payment with the structured communication, then read back
 * the signed receipt, the supporter SD-JWT VC and the inclusion proof, and check the last two
 * in the crypto worker exactly as the page does.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { PGlite } from "@electric-sql/pglite";
import { replayDb } from "../../scripts/formal-rls/replay";

let db: PGlite;
const ctx = new AsyncLocalStorage<{ userId: string }>();
vi.mock("@/lib/neon", () => {
  const run = async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const text = strings.reduce((acc, s, i) => acc + s + (i < values.length ? `$${i + 1}` : ""), "");
    await db.exec("begin");
    try {
      await db.exec("set local role rout_app");
      await db.query("select set_config('rout.current_user_id', $1, true)", [ctx.getStore()?.userId ?? ""]);
      const r = await db.query(text, values);
      await db.exec("commit");
      return r.rows;
    } catch (e) {
      await db.exec("rollback");
      throw e;
    }
  };
  return { sql: run, withDbContext: (c: { userId: string }, fn: () => unknown) => ctx.run(c, fn) };
});
vi.mock("@/lib/schema-features.server", () => ({ hasSchemaFeature: async () => true }));
vi.mock("@/lib/verification.server", () => ({ stripeKey: () => null }));

const MEMBER = "00000000-0000-4000-8000-0000000003a1";
const s = await import("@/lib/support/support.server");
const { runEnclaveOp } = await import("@/lib/crypto-enclave/enclave-core");
const { supportPublicKey } = await import("@/lib/support/keys.server");
const { verifyHybrid, b64uDecode } = await import("@/lib/support/hybrid-signature");
const { receiptMessage } = await import("@/lib/support/receipt");

beforeAll(async () => {
  process.env["ROUT_TREASURY_IBAN"] = "BE68 5390 0754 7034";
  process.env["ROUT_TREASURY_NAME"] = "ROUT Test";
  process.env["ROUT_SUBJECT_MASTER_KEY"] = "test-master-key-0123456789abcdef0123456789";
  process.env["ROUT_VAULT_KEK"] = "test-vault-kek-0123456789abcdef0123456789abc";
  db = await replayDb();
  await db.exec(`
    insert into public.users (id, email) values ('${MEMBER}', 'jona@example.test');
    insert into public.profiles (id, username) values ('${MEMBER}', 'jona') on conflict (id) do update set username = excluded.username;
  `);
}, 300_000);
afterAll(async () => {
  await db?.close();
  for (const k of ["ROUT_TREASURY_IBAN", "ROUT_TREASURY_NAME", "ROUT_SUBJECT_MASTER_KEY", "ROUT_VAULT_KEK"]) delete process.env[k];
});

type Sepa = Extract<Awaited<ReturnType<typeof s.startSupport>>, { rail: "sepa" }>;
const startSepa = async (level: 1 | 2 | 3, amountCents: number, userId?: string) => {
  const run = () => s.startSupport({ level, rail: "sepa", amountCents, signedIn: Boolean(userId), origin: "https://rout.be" });
  const r = userId ? await ctx.run({ userId }, run) : await run();
  expect(r.ok).toBe(true);
  return r as Sepa;
};

describe("support donation flow", () => {
  let pseudo: Sepa;
  let pub: Sepa;

  it("starts SEPA donations with a valid structured communication in the EPC QR", async () => {
    pseudo = await startSepa(2, 2500);
    expect(pseudo.ogmText).toMatch(/^\+\+\+\d{3}\/\d{4}\/\d{5}\+\+\+$/);
    expect(pseudo.epc).toContain(pseudo.ogmText);
    expect(pseudo.epc).toContain("BE68539007547034");
    expect(pseudo.epc).toContain("EUR25.00");
    pub = await startSepa(1, 1000, MEMBER);
  });

  it("refuses level 1 without a session and amounts outside the range", async () => {
    expect(await s.startSupport({ level: 1, rail: "sepa", amountCents: 1000, signedIn: false, origin: "https://rout.be" })).toEqual({ ok: false, reason: "sign_in_required" });
    expect(await s.startSupport({ level: 2, rail: "sepa", amountCents: 50, signedIn: false, origin: "https://rout.be" })).toEqual({ ok: false, reason: "invalid_amount" });
    expect(await s.startSupport({ level: 2, rail: "stripe", amountCents: 1000, signedIn: false, origin: "https://rout.be" })).toEqual({ ok: false, reason: "stripe_not_configured" });
  });

  it("a bunq payment with the wrong amount is not counted; the right one is, once", async () => {
    expect(await s.confirmByOgm(pseudo.ogm, "bunq-1", 2400)).toBe("amount_mismatch");
    expect(await s.confirmByOgm(pseudo.ogm, "bunq-1", 2500)).toBe("ok");
    expect(await s.confirmByOgm(pseudo.ogm, "bunq-1", 2500)).toBe("unknown"); // communication cleared after payment
    expect(await s.confirmByOgm(pub.ogm, "bunq-2", 1000)).toBe("ok");
  });

  it("the donor reads back a hybrid-signed receipt and a proof the crypto worker accepts", async () => {
    const view = (await s.readDonation(pseudo.id, pseudo.token))!;
    expect(view.status).toBe("paid");
    const pk = (await supportPublicKey())!;
    expect(verifyHybrid(receiptMessage(view.receipt!.receipt), view.receipt!.signature, pk, { requirePq: true })).toEqual({ valid: true, pq: true });
    expect(view.receipt!.receipt).toMatchObject({ amountCents: 2500, level: 2, supporterIndex: "0" });

    const keys = { edPublicKey: b64uDecode(pk.ed25519), pqPublicKey: b64uDecode(pk.mldsa65!), kid: pk.kid };
    // The proof was made when the tree had 1 leaf; a later root must still accept a fresh proof.
    const again = (await s.readDonation(pseudo.id, pseudo.token))!;
    expect(await runEnclaveOp("support.verify_inclusion", { proof: JSON.stringify(again.proof), ...keys })).toEqual({ ok: true, result: { valid: true, pq: true, reason: null } });
    expect(again.proof!.signedRoot.size).toBe("2");

    const vc = await runEnclaveOp("support.verify_vc", { compact: view.credential!, edPublicKey: b64uDecode(pk.ed25519), kid: pk.kid, now: Date.now() });
    expect(vc).toMatchObject({ ok: true, result: { valid: true, claims: { level: "pseudonymous", supporter_index: 0 } } });
    expect((vc as { result: { claims: Record<string, unknown> } }).result.claims["handle"]).toBeUndefined();
  });

  it("the wrong token sees nothing", async () => {
    expect(await s.readDonation(pseudo.id, pub.token)).toBeNull();
  });

  it("a public donor's profile presentation verifies with the handle and hides the rest", async () => {
    const presentation = (await s.readSupporterPresentation("@jona"))!;
    const pk = (await supportPublicKey())!;
    const r = await runEnclaveOp("support.verify_vc", { compact: presentation, edPublicKey: b64uDecode(pk.ed25519), kid: pk.kid, now: Date.now() });
    expect(r).toMatchObject({ ok: true, result: { valid: true, claims: { level: "public", handle: "@jona", since: expect.any(String) } } });
    expect((r as { result: { claims: Record<string, unknown> } }).result.claims["supporter_index"]).toBeUndefined();
    expect(await s.readSupporterPresentation("nobody")).toBeNull();
  });

  it("the public ledger and the member's own list", async () => {
    const o = await s.readOverview();
    expect(o.ready).toBe(true);
    expect(o.totalCents).toBe(3500);
    expect(o.ledger.map((e) => [e.level, e.handle, e.index])).toEqual(expect.arrayContaining([[1, "jona", "1"], [2, null, "0"]]));
    expect(o.coverage).toMatchObject({ state: "known", costCents: 15090 });
    const mine = await ctx.run({ userId: MEMBER }, () => s.readMyDonations());
    expect(mine).toHaveLength(1);
    expect(mine[0]!.credential).toBeTruthy();
  });
});
