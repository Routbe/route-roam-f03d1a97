import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { blindIndex, FieldSealError, INDEX_ONLY_FIELDS, INDEXED_PROFILE_FIELDS, normalizeForIndex, openProfileField, PRIVATE_PROFILE_FIELDS, sealProfileField } from "./field-seal";

const key = () => fc.uint8Array({ minLength: 32, maxLength: 32 });
const field = fc.constantFrom(...PRIVATE_PROFILE_FIELDS);
const uuid = fc.uuid({ version: 4 });
const value = fc.string({ unit: "grapheme", maxLength: 300 });

describe("A1 profile field AEAD", () => {
  it("round-trips every value", () => {
    fc.assert(fc.property(key(), field, uuid, value, (k, f, id, v) => {
      expect(openProfileField(k, f, id, sealProfileField(k, 1, f, id, v))).toBe(v);
    }), { numRuns: 300 });
  });

  it("refuses another profile, column or key", () => {
    fc.assert(fc.property(key(), key(), field, field, uuid, uuid, value, (k, k2, f, f2, id, id2, v) => {
      const blob = sealProfileField(k, 1, f, id, v);
      if (id2 !== id) expect(() => openProfileField(k, f, id2, blob)).toThrow(FieldSealError);
      if (f2 !== f) expect(() => openProfileField(k, f2, id, blob)).toThrow(FieldSealError);
      if (k2.some((b, i) => b !== k[i])) expect(() => openProfileField(k2, f, id, blob)).toThrow(FieldSealError);
    }), { numRuns: 200 });
  });

  it("detects any single flipped bit", () => {
    fc.assert(fc.property(key(), field, uuid, value, fc.nat(), fc.integer({ min: 0, max: 7 }), (k, f, id, v, pos, bit) => {
      const blob = sealProfileField(k, 1, f, id, v);
      blob[pos % blob.length]! ^= 1 << bit;
      expect(() => openProfileField(k, f, id, blob)).toThrow(FieldSealError);
    }), { numRuns: 300 });
  });

  it("never repeats a ciphertext and only leaks a 64-byte bucket", () => {
    fc.assert(fc.property(key(), field, uuid, fc.string({ maxLength: 61 }), (k, f, id, v) => {
      const a = sealProfileField(k, 1, f, id, v);
      const b = sealProfileField(k, 1, f, id, v);
      expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
      expect(a.length).toBe(4 + 1 + 24 + 64 + 16);
    }));
  });

  it("rejects a short key and an unknown column", () => {
    expect(() => sealProfileField(new Uint8Array(16), 1, "business_vat", crypto.randomUUID(), "x")).toThrow(FieldSealError);
    expect(() => sealProfileField(new Uint8Array(32), 1, "bio" as never, crypto.randomUUID(), "x")).toThrow(FieldSealError);
  });
});

describe("A1 HMAC-BLAKE3 blind index", () => {
  const blind = fc.constantFrom(...INDEXED_PROFILE_FIELDS, ...INDEX_ONLY_FIELDS);
  const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

  it("is deterministic per column and key version", () => {
    fc.assert(fc.property(key(), blind, value, (k, f, v) => {
      expect(hex(blindIndex(k, 1, f, v))).toBe(hex(blindIndex(k, 1, f, v)));
    }), { numRuns: 200 });
  });

  it("meets equivalent spellings where the column allows it", () => {
    const k = new Uint8Array(32).fill(7);
    expect(blindIndex(k, 1, "business_vat", "BE 0123.456.789")).toEqual(blindIndex(k, 1, "business_vat", "be0123456789"));
    expect(blindIndex(k, 1, "email", " Ann@Example.COM ")).toEqual(blindIndex(k, 1, "email", "ann@example.com"));
    expect(blindIndex(k, 1, "forwarding_email", "A@B.be")).toEqual(blindIndex(k, 1, "forwarding_email", "a@b.be"));
    fc.assert(fc.property(key(), fc.stringMatching(/^[a-z0-9._@-]{0,40}$/), (kk, v) => {
      expect(blindIndex(kk, 1, "email", ` ${v.toUpperCase()} `)).toEqual(blindIndex(kk, 1, "email", v));
      expect(blindIndex(kk, 1, "business_vat", v.toUpperCase().split("").join(" "))).toEqual(blindIndex(kk, 1, "business_vat", v));
    }), { numRuns: 200 });
  });

  it("keeps case-sensitive Stripe ids and opaque tokens apart", () => {
    const k = new Uint8Array(32).fill(9);
    expect(hex(blindIndex(k, 1, "stripe_account_id", "acct_1AbC"))).not.toBe(hex(blindIndex(k, 1, "stripe_account_id", "acct_1abc")));
    expect(hex(blindIndex(k, 1, "forwarding_email_token", "Tok"))).not.toBe(hex(blindIndex(k, 1, "forwarding_email_token", "tok")));
    expect(blindIndex(k, 1, "stripe_account_id", " acct_1AbC ")).toEqual(blindIndex(k, 1, "stripe_account_id", "acct_1AbC"));
  });

  it("separates columns, key versions, keys and distinct canonical values", () => {
    fc.assert(fc.property(key(), key(), blind, blind, value, value, (k, k2, f, f2, v, v2) => {
      const h = hex(blindIndex(k, 1, f, v));
      if (f !== f2) expect(hex(blindIndex(k, 1, f2, v))).not.toBe(h);
      expect(hex(blindIndex(k, 2, f, v))).not.toBe(h);
      if (k2.some((b, i) => b !== k[i])) expect(hex(blindIndex(k2, 1, f, v))).not.toBe(h);
      if (normalizeForIndex(f, v) !== normalizeForIndex(f, v2)) expect(hex(blindIndex(k, 1, f, v2))).not.toBe(h);
    }), { numRuns: 300 });
  });

  it("refuses unindexed columns and short keys, and never contains the plaintext", () => {
    expect(() => blindIndex(new Uint8Array(32), 1, "moderation_reason" as never, "x")).toThrow(FieldSealError);
    expect(() => blindIndex(new Uint8Array(16), 1, "email", "x")).toThrow(FieldSealError);
    const h = blindIndex(new Uint8Array(32).fill(1), 1, "business_vat", "be0123456789");
    expect(h.length).toBe(32);
    expect(Buffer.from(h).toString("latin1")).not.toContain("0123456789");
  });
});
