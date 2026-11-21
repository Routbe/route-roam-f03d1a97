import { describe, expect, it } from "vitest";
import { ageGatePasses, ageVectorFlags, ageVectorFromBirthDate, isValidVector } from "./age-vector";

const NOW = new Date(Date.UTC(2026, 10, 17)); // 2026-11-17

describe("ageVectorFromBirthDate", () => {
  it("sets one bit per threshold 13..21 and turns a year older on the birthday itself", () => {
    expect(ageVectorFromBirthDate("2008-11-17", NOW)).toBe(0b111111); // 18: over 13..18
    expect(ageVectorFromBirthDate("2008-11-18", NOW)).toBe(0b11111); // 17
    expect(ageVectorFromBirthDate("2013-11-17", NOW)).toBe(0b1); // 13
    expect(ageVectorFromBirthDate("2013-11-18", NOW)).toBe(0); // 12
  });
  it("tops out at 21 so older ages reveal nothing more", () => {
    expect(ageVectorFromBirthDate("1980-01-01", NOW)).toBe(511);
    expect(ageVectorFromBirthDate("2005-11-17", NOW)).toBe(511);
  });
  it("refuses unusable input", () => {
    for (const v of [null, 19800101, "1980/01/01", "2001-02-30", "2027-01-01", "1800-01-01", ""]) {
      expect(ageVectorFromBirthDate(v, NOW)).toBeNull();
    }
  });
  it("names the flags without exposing anything else", () => {
    const f = ageVectorFlags(ageVectorFromBirthDate("2010-06-01", NOW)); // 16
    expect(f).toMatchObject({ is_over_13: true, is_over_14: true, is_over_15: true, is_over_16: true, is_over_18: false, is_over_21: false });
  });
});

describe("ageGatePasses", () => {
  it("answers only the app's own threshold", () => {
    expect(ageGatePasses(0b111111, 18)).toBe(true);
    expect(ageGatePasses(0b11111, 18)).toBe(false);
    expect(ageGatePasses(0b1111, 16)).toBe(true);
    expect(ageGatePasses(511, 21)).toBe(true);
  });
  it("fails closed without a vector, with a non-monotone vector or a minimum outside 13..21", () => {
    expect(ageGatePasses(null, 18)).toBe(false);
    expect(ageGatePasses(0b100000, 18)).toBe(false);
    expect(isValidVector(0b101)).toBe(false);
    expect(ageGatePasses(511, 12)).toBe(false);
    expect(ageGatePasses(511, 22)).toBe(false);
  });
});
