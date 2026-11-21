/**
 * Treasury account resolution: ROUT_TREASURY_* first, bunq's main EUR account as fallback,
 * and the beneficiary name defaulting to "ROUT Sovereign Identity OS".
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const bunq = vi.hoisted(() => ({
  configured: false,
  accounts: [] as Array<{ iban: string | null; currency: string; status: string; ibanCountry: string | null }>,
  calls: 0,
  fail: false,
}));

vi.mock("@/lib/neon", () => ({ sql: vi.fn() }));
vi.mock("@/lib/bunq.server", () => ({
  bunqConfigured: () => bunq.configured,
  listMonetaryAccounts: async () => {
    bunq.calls++;
    if (bunq.fail) throw new Error("bunq down");
    return bunq.accounts;
  },
  mainEurAccount: (a: typeof bunq.accounts) => a.find((x) => x.currency === "EUR" && x.iban) ?? null,
}));

import { DEFAULT_TREASURY_NAME, resetTreasuryCache, treasuryAccount } from "./support.server";

const KEYS = ["ROUT_TREASURY_IBAN", "ROUT_TREASURY_NAME", "ROUT_TREASURY_BIC"];

beforeEach(() => {
  for (const k of KEYS) delete process.env[k];
  Object.assign(bunq, { configured: false, accounts: [], calls: 0, fail: false });
  resetTreasuryCache();
  vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => {
  for (const k of KEYS) delete process.env[k];
  vi.restoreAllMocks();
});

describe("treasury account", () => {
  it("defaults the beneficiary name to ROUT Sovereign Identity OS", async () => {
    process.env["ROUT_TREASURY_IBAN"] = "BE68 5390 0754 7034";
    expect(DEFAULT_TREASURY_NAME).toBe("ROUT Sovereign Identity OS");
    expect(await treasuryAccount()).toEqual({ iban: "BE68539007547034", name: "ROUT Sovereign Identity OS", bic: null });
  });

  it("takes name and BIC from the environment when set", async () => {
    process.env["ROUT_TREASURY_IBAN"] = "BE68539007547034";
    process.env["ROUT_TREASURY_NAME"] = "ROUT Test";
    process.env["ROUT_TREASURY_BIC"] = "bunq be2b";
    expect(await treasuryAccount()).toEqual({ iban: "BE68539007547034", name: "ROUT Test", bic: "BUNQBE2B" });
    expect(bunq.calls).toBe(0);
  });

  it("falls back to bunq's EUR account when ROUT_TREASURY_IBAN is missing, and caches it", async () => {
    Object.assign(bunq, { configured: true, accounts: [{ iban: "NL91ABNA0417164300", currency: "EUR", status: "ACTIVE", ibanCountry: "NL" }] });
    expect(await treasuryAccount()).toEqual({ iban: "NL91ABNA0417164300", name: "ROUT Sovereign Identity OS", bic: null });
    await treasuryAccount();
    expect(bunq.calls).toBe(1);
  });

  it("rejects an invalid IBAN from the environment or bunq", async () => {
    process.env["ROUT_TREASURY_IBAN"] = "BE00000000000000";
    Object.assign(bunq, { configured: true, accounts: [{ iban: "NL00ABNA0000000000", currency: "EUR", status: "ACTIVE", ibanCountry: "NL" }] });
    expect(await treasuryAccount()).toBeNull();
  });

  it("answers null without IBAN, without bunq, or when bunq fails", async () => {
    expect(await treasuryAccount()).toBeNull();
    resetTreasuryCache();
    Object.assign(bunq, { configured: true, fail: true });
    expect(await treasuryAccount()).toBeNull();
  });
});
