import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { blake3 } from "@noble/hashes/blake3.js";
import { isNullifier, universalNullifier } from "./nullifier";
import { poseidon256 } from "./poseidon";

const P = "p".repeat(48);
const e = new TextEncoder();

describe("universal_nullifier = BLAKE3(Poseidon256(canonical_id) || pepper)", () => {
  it("follows the formula exactly", () => {
    const c = e.encode("BEL:PN:85073003328");
    const expected = Buffer.from(blake3(new Uint8Array([...poseidon256(c), ...e.encode(P)]))).toString("hex");
    expect(universalNullifier(c, P)).toBe(expected);
  });

  it("is deterministic, 64 hex characters, and does not depend on the provider", () => {
    fc.assert(fc.property(fc.string({ minLength: 1, maxLength: 40 }), (s) => {
      const a = universalNullifier(e.encode(s), P);
      expect(isNullifier(a)).toBe(true);
      expect(universalNullifier(e.encode(s), P)).toBe(a);
    }), { numRuns: 40 });
  });

  it("changes with the pepper and with the identifier", () => {
    const c = e.encode("NLD:PN:123456782");
    expect(universalNullifier(c, P)).not.toBe(universalNullifier(c, "q".repeat(48)));
    expect(universalNullifier(c, P)).not.toBe(universalNullifier(e.encode("NLD:PN:123456783"), P));
  });

  it("refuses a missing or short pepper", () => {
    expect(() => universalNullifier(e.encode("x"), "")).toThrow("pepper_missing");
    expect(() => universalNullifier(e.encode("x"), "short")).toThrow("pepper_too_short");
  });

  it("leaves the caller's canonical buffer untouched and never contains it", () => {
    const c = e.encode("ESP:PN:99999999R");
    const n = universalNullifier(c, P);
    expect(new TextDecoder().decode(c)).toBe("ESP:PN:99999999R");
    expect(n).not.toContain(Buffer.from(c).toString("hex"));
  });
});
