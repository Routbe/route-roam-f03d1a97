import { describe, expect, it } from "vitest";
import { ageFloorFromBirthDate, ageFloorFromDobBytes, isAgeFloor, legacyDateForFloor } from "./age-floor";

const today = new Date(Date.UTC(2026, 10, 17)); // 2026-11-17

describe("ageFloorFromBirthDate", () => {
  it("counts whole years and turns a year older on the birthday", () => {
    expect(ageFloorFromBirthDate("2010-11-18", today)).toBe(15);
    expect(ageFloorFromBirthDate("2010-11-17", today)).toBe(16);
    expect(ageFloorFromBirthDate("2013-11-17", today)).toBe(13);
    expect(ageFloorFromBirthDate("2008-11-17", today)).toBe(18);
  });
  it("caps at 21", () => {
    expect(ageFloorFromBirthDate("1990-01-01", today)).toBe(21);
  });
  it("rejects impossible, future and malformed dates", () => {
    for (const bad of ["2010-02-30", "2027-01-01", "1899-12-31", "2010-1-01", "2010/01/01", "abcd-ef-gh", "", null, 20100101]) {
      expect(ageFloorFromBirthDate(bad, today), String(bad)).toBeNull();
    }
  });
  it("accepts a leap day", () => {
    expect(ageFloorFromBirthDate("2008-02-29", today)).toBe(18);
  });
});

describe("ageFloorFromDobBytes", () => {
  it("zero-fills the bytes it read, also on invalid input", () => {
    const ok = new TextEncoder().encode("2010-11-17");
    expect(ageFloorFromDobBytes(ok, today)).toBe(16);
    expect([...ok].every((b) => b === 0)).toBe(true);
    const bad = new TextEncoder().encode("2010-13-01");
    expect(ageFloorFromDobBytes(bad, today)).toBeNull();
    expect([...bad].every((b) => b === 0)).toBe(true);
  });
});

describe("legacyDateForFloor", () => {
  it("gives the youngest date that still has the floor", () => {
    expect(legacyDateForFloor(15, today)).toBe("2011-11-17");
    expect(ageFloorFromBirthDate(legacyDateForFloor(15, today), today)).toBe(15);
    expect(legacyDateForFloor(13, new Date(Date.UTC(2028, 1, 29)))).toBe("2015-02-28");
  });
});

describe("isAgeFloor", () => {
  it("accepts integers 0..21 only", () => {
    expect([0, 13, 21].every(isAgeFloor)).toBe(true);
    expect([-1, 22, 1.5, "16", null].some(isAgeFloor)).toBe(false);
  });
});
