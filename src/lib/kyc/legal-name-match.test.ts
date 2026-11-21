import { describe, expect, it } from "vitest";
import { holderMatchesLegalName, normName } from "./legal-name-match";

describe("holderMatchesLegalName", () => {
  const legal = { first: "Carmen", last: "Española Núñez" };
  it("matches the account holder in either name order, ignoring accents, case and spacing", () => {
    expect(holderMatchesLegalName("CARMEN ESPANOLA NUNEZ", legal)).toBe(true);
    expect(holderMatchesLegalName("Española-Núñez, Carmen", legal)).toBe(true);
  });
  it("refuses another name, a partial name or a missing legal name", () => {
    expect(holderMatchesLegalName("Carmen Española", legal)).toBe(false);
    expect(holderMatchesLegalName("Jan Peeters", legal)).toBe(false);
    expect(holderMatchesLegalName("Carmen Española Núñez", null)).toBe(false);
    expect(holderMatchesLegalName("", legal)).toBe(false);
  });
  it("normalises like the database", () => {
    expect(normName("  Ève-Marie O'Brien ")).toBe("evemarieobrien");
  });
});
