// @vitest-environment node
import { describe, expect, it } from "vitest";
import { identityPepper, readPepper } from "./pepper.server";

const P = "x".repeat(40);

describe("nullifier pepper", () => {
  it("accepts IDENTITY_HASH_PEPPER", () => {
    expect(readPepper({ IDENTITY_HASH_PEPPER: P })).toEqual({ ok: true, pepper: P });
  });
  it("accepts PEPPER_SECRET", () => {
    expect(readPepper({ PEPPER_SECRET: P })).toEqual({ ok: true, pepper: P });
  });
  it("accepts both when they are identical", () => {
    expect(identityPepper({ IDENTITY_HASH_PEPPER: P, PEPPER_SECRET: P })).toBe(P);
  });
  it("refuses two different peppers, which would split the registry", () => {
    expect(readPepper({ IDENTITY_HASH_PEPPER: P, PEPPER_SECRET: `${P}y` })).toEqual({ ok: false, reason: "conflict" });
    expect(() => identityPepper({ IDENTITY_HASH_PEPPER: P, PEPPER_SECRET: `${P}y` })).toThrow("kyc_not_configured");
  });
  it("refuses a missing or short pepper (minimum 32 characters)", () => {
    expect(readPepper({})).toEqual({ ok: false, reason: "missing" });
    expect(readPepper({ PEPPER_SECRET: "x".repeat(31) })).toEqual({ ok: false, reason: "too_short" });
    expect(readPepper({ PEPPER_SECRET: "x".repeat(32) }).ok).toBe(true);
  });
});
