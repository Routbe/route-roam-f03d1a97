import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { deriveFieldKek, FieldKeyError, generateFieldKey, openFieldKeyring, WRAPPED_FIELD_KEY_BYTES, type StoredFieldKey } from "./field-keys";
import { deriveVaultKek } from "@/lib/vault/server-kek";

const secret = fc.stringMatching(/^[A-Za-z0-9]{64,80}$/);
const version = fc.integer({ min: 1, max: 255 });

describe("A1 field-key wrap under ROUT_VAULT_KEK", () => {
  it("round-trips a key for its own version and kid only", () => {
    fc.assert(fc.property(secret, version, version, (s, v, v2) => {
      const kek = deriveFieldKek(s);
      const { stored, key } = generateFieldKey(kek, v);
      expect(stored.wrapped.length).toBe(WRAPPED_FIELD_KEY_BYTES);
      expect(kek.unwrap(v, stored.kid, stored.wrapped)).toEqual(key);
      if (v2 !== v) expect(() => kek.unwrap(v2, stored.kid, stored.wrapped)).toThrow(FieldKeyError);
      const otherKid = stored.kid.slice();
      otherKid[0]! ^= 1;
      expect(() => kek.unwrap(v, otherKid, stored.wrapped)).toThrow(FieldKeyError);
      kek.dispose();
    }), { numRuns: 60 });
  });

  it("refuses any flipped bit, another KEK and the server-vault wrap", () => {
    fc.assert(fc.property(secret, secret, fc.nat(), fc.integer({ min: 0, max: 7 }), (s, s2, pos, bit) => {
      const kek = deriveFieldKek(s);
      const { stored } = generateFieldKey(kek, 1);
      const bad = stored.wrapped.slice();
      bad[pos % bad.length]! ^= 1 << bit;
      expect(() => kek.unwrap(1, stored.kid, bad)).toThrow(FieldKeyError);
      if (s2 !== s) expect(() => deriveFieldKek(s2).unwrap(1, stored.kid, stored.wrapped)).toThrow(FieldKeyError);
    }), { numRuns: 80 });
    // Same environment secret, other purpose: a server-vault seed wrap never opens as a field key.
    const s = "A".repeat(64);
    const seedWrap = deriveVaultKek(s).wrap(new Uint8Array(16), new Uint8Array(32).fill(3));
    expect(() => deriveFieldKek(s).unwrap(1, new Uint8Array(16), seedWrap)).toThrow(FieldKeyError);
    expect(deriveFieldKek(s).kekId).not.toEqual(deriveVaultKek(s).kekId);
  });

  it("rejects a weak secret and refuses use after dispose", () => {
    expect(() => deriveFieldKek("short")).toThrow(FieldKeyError);
    expect(() => deriveFieldKek("x".repeat(63))).toThrow(FieldKeyError);
    const kek = deriveFieldKek("B".repeat(64));
    kek.dispose();
    expect(() => generateFieldKey(kek, 1)).toThrow(FieldKeyError);
  });
});

describe("A1 key ring", () => {
  const ringOf = (s: string, versions: number[], active: number) => {
    const kek = deriveFieldKek(s);
    const made = versions.map((v) => generateFieldKey(kek, v));
    const stored: StoredFieldKey[] = made.map((m) => ({ ...m.stored, active: m.stored.version === active }));
    return { kek, made, stored };
  };

  it("opens every version, newest first, and wipes them on dispose", () => {
    const { kek, made, stored } = ringOf("C".repeat(64), [1, 2, 3], 3);
    const ring = openFieldKeyring(kek, stored);
    expect(ring.activeVersion).toBe(3);
    expect(ring.versions).toEqual([3, 2, 1]);
    for (const m of made) expect(ring.key(m.stored.version)).toEqual(m.key);
    const held = ring.key(2);
    ring.dispose();
    expect(held.every((b) => b === 0)).toBe(true);
    expect(() => ring.key(3)).toThrow(FieldKeyError);
  });

  it("fails closed on a forged, missing-active, double-active, stale-active or foreign-KEK ring", () => {
    const { kek, stored } = ringOf("D".repeat(64), [1, 2], 2);
    expect(() => openFieldKeyring(kek, [])).toThrow(FieldKeyError);
    expect(() => openFieldKeyring(kek, stored.map((s) => ({ ...s, active: false })))).toThrow(FieldKeyError);
    expect(() => openFieldKeyring(kek, stored.map((s) => ({ ...s, active: true })))).toThrow(FieldKeyError);
    expect(() => openFieldKeyring(kek, stored.map((s) => ({ ...s, active: s.version === 1 })))).toThrow(FieldKeyError);
    const forged = stored.map((s, i) => (i === 0 ? { ...s, wrapped: s.wrapped.map((b, j) => (j === 40 ? b ^ 1 : b)) } : s));
    expect(() => openFieldKeyring(kek, forged)).toThrow(FieldKeyError);
    expect(() => openFieldKeyring(deriveFieldKek("E".repeat(64)), stored)).toThrow(FieldKeyError);
    expect(() => openFieldKeyring(kek, [...stored, stored[0]!])).toThrow(FieldKeyError);
  });
});
