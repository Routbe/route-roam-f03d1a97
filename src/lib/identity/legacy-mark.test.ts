import { describe, expect, it } from "vitest";
import { isLegacyReviewed } from "./legacy-mark";

const base = { verified: true, verified_legal_name: "Jona Delplanche", verified_at: "2026-10-10T08:16:00Z" };

describe("legacy reviewed blue mark", () => {
  it("an admin-approved profile with a legal name and date keeps the blue mark", () => {
    expect(isLegacyReviewed(base)).toBe(true);
  });
  it("payment or Pro without a confirmed legal name never gives the mark", () => {
    expect(isLegacyReviewed({ ...base, verified_legal_name: null })).toBe(false);
    expect(isLegacyReviewed({ ...base, verified_legal_name: "  " })).toBe(false);
  });
  it("needs the verified flag and a valid verification date", () => {
    expect(isLegacyReviewed({ ...base, verified: false })).toBe(false);
    expect(isLegacyReviewed({ ...base, verified_at: null })).toBe(false);
    expect(isLegacyReviewed({ ...base, verified_at: "not a date" })).toBe(false);
  });
  it("a banned or suspended profile shows no mark", () => {
    expect(isLegacyReviewed({ ...base, is_banned: true })).toBe(false);
    expect(isLegacyReviewed({ ...base, is_suspended: true })).toBe(false);
  });
});
