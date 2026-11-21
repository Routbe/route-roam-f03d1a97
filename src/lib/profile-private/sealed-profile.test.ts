import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { deriveFieldKek, generateFieldKey, openFieldKeyring, type FieldKeyring } from "./field-keys";
import { FieldSealError, INDEXED_PROFILE_FIELDS, PRIVATE_PROFILE_FIELDS, type PrivateProfileField } from "./field-seal";
import { bidxColumn, indexCandidates, openProfileRow, sealedColumn, sealProfilePatch } from "./sealed-profile";

function ring(versions = [1], active = 1): FieldKeyring {
  const kek = deriveFieldKek("F".repeat(64));
  return openFieldKeyring(kek, versions.map((v) => ({ ...generateFieldKey(kek, v).stored, active: v === active })));
}
const field = fc.constantFrom(...PRIVATE_PROFILE_FIELDS);
const id = fc.uuid({ version: 4 });
const text = fc.string({ unit: "grapheme", minLength: 1, maxLength: 200 });
const hex = (b: unknown) => Buffer.from(b as Uint8Array).toString("hex");

describe("A1 sealed profile patch", () => {
  it("never writes plaintext: the plaintext column is NULL, the sealed column opens to the value", () => {
    const r = ring();
    fc.assert(fc.property(field, id, text, (f, pid, v) => {
      const patch = sealProfilePatch(r, pid, { [f]: v });
      expect(patch[f]).toBeNull();
      const blob = patch[sealedColumn(f)] as Uint8Array;
      if (Buffer.byteLength(v) >= 8) expect(Buffer.from(blob).includes(Buffer.from(v))).toBe(false);
      const row = openProfileRow(r, { id: pid, ...patch }, [f]);
      expect(row[f]).toBe(v);
      expect(sealedColumn(f) in row).toBe(false);
    }), { numRuns: 300 });
  });

  it("clears ciphertext and index for an empty value", () => {
    const r = ring();
    for (const f of PRIVATE_PROFILE_FIELDS) {
      for (const empty of [null, ""]) {
        const patch = sealProfilePatch(r, crypto.randomUUID(), { [f]: empty });
        expect(patch[f]).toBeNull();
        expect(patch[sealedColumn(f)]).toBeNull();
        if ((INDEXED_PROFILE_FIELDS as readonly string[]).includes(f)) expect(patch[bidxColumn(f as never)]).toBeNull();
      }
    }
  });

  it("a ciphertext moved to another profile or column fails closed", () => {
    const r = ring();
    fc.assert(fc.property(field, field, id, id, text, (f, f2, a, b, v) => {
      const blob = sealProfilePatch(r, a, { [f]: v })[sealedColumn(f)];
      if (a !== b) expect(() => openProfileRow(r, { id: b, [sealedColumn(f)]: blob }, [f])).toThrow(FieldSealError);
      if (f !== f2) expect(() => openProfileRow(r, { id: a, [sealedColumn(f2)]: blob }, [f2 as PrivateProfileField])).toThrow(FieldSealError);
    }), { numRuns: 200 });
  });

  it("falls back to the legacy column only when nothing is sealed", () => {
    const r = ring();
    const pid = crypto.randomUUID();
    expect(openProfileRow(null, { id: pid, business_vat: "BE1", business_vat_sealed: null }, ["business_vat"]).business_vat).toBe("BE1");
    const sealed = sealProfilePatch(r, pid, { business_vat: "BE2" });
    expect(openProfileRow(r, { id: pid, business_vat: "BE1", ...sealed }, ["business_vat"]).business_vat).toBe("BE2");
    expect(() => openProfileRow(null, { id: pid, ...sealed }, ["business_vat"])).toThrow(FieldSealError);
  });

  it("a lookup matches values sealed under any key version, and nothing else", () => {
    const rotated = ring([1, 2], 2);
    const pid = crypto.randomUUID();
    const underV2 = hex(sealProfilePatch(rotated, pid, { email: "a@b.be" }).email_bidx);
    expect(indexCandidates(rotated, "email", "A@B.be").map(hex)).toContain(underV2);
    expect(indexCandidates(rotated, "email", "A@B.be")).toHaveLength(2);
    const old = ring([1], 1);
    fc.assert(fc.property(fc.constantFrom(...INDEXED_PROFILE_FIELDS), id, text, text, (f, pid, v, w) => {
      const patch = sealProfilePatch(old, pid, { [f]: v });
      const stored = hex(patch[bidxColumn(f)]);
      const hits = indexCandidates(old, f, v).map(hex);
      expect(hits).toContain(stored);
      if (indexCandidates(old, f, w).map(hex).includes(stored)) {
        expect(indexCandidates(old, f, w)).toEqual(indexCandidates(old, f, v));
      }
    }), { numRuns: 200 });
  });
});
