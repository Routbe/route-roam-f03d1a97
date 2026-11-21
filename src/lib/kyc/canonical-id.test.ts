import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { canonicalAnchors, canonicalCountry, canonicalValue, documentClass, wipeAnchors } from "./canonical-id";

const text = (a: { bytes: Uint8Array }) => new TextDecoder().decode(a.bytes);

describe("canonical ICAO / eIDAS anchors", () => {
  it("reads the Didit example ID card as national number first, then the document", () => {
    const a = canonicalAnchors({ issuingState: "ESP", documentType: "Identity Card", documentNumber: "CAA000000", personalNumber: "99999999R" });
    expect(a.map((x) => [x.kind, text(x)])).toEqual([["personal_number", "ESP:PN:99999999R"], ["document", "ESP:I:CAA000000"]]);
  });

  it("maps ICAO and alpha-2 issuers to ISO 3166-1 alpha-3", () => {
    expect(canonicalCountry("D")).toBe("DEU");
    expect(canonicalCountry("be")).toBe("BEL");
    expect(canonicalCountry("NLD")).toBe("NLD");
    expect(canonicalCountry("ZZ")).toBeNull();
    expect(canonicalCountry("")).toBeNull();
  });

  it("classifies documents from provider labels and MRZ types", () => {
    expect(documentClass("Passport")).toBe("P");
    expect(documentClass("PO")).toBe("P");
    expect(documentClass("Identity Card")).toBe("I");
    expect(documentClass("ID")).toBe("I");
    expect(documentClass("Residence Permit")).toBe("R");
    expect(documentClass("Driving License")).toBe("DL");
    expect(documentClass("something")).toBe("X");
  });

  it("is invariant under case, spacing, hyphens, MRZ fillers and diacritics", () => {
    const base = canonicalAnchors({ issuingState: "BEL", documentType: "ID", documentNumber: "592123456789", personalNumber: "85073003328" }).map(text);
    const noisy = canonicalAnchors({ issuingState: " bel ", documentType: "identity card", documentNumber: "592-1234567-89<<", personalNumber: "85.07.30-033.28" }).map(text);
    expect(noisy).toEqual(base);
    expect(canonicalValue("Àb-ç 1<")).toBe("ABC1");
  });

  it("canonicalValue is idempotent and only emits A-Z0-9", () => {
    fc.assert(fc.property(fc.string({ maxLength: 60 }), (s) => {
      const v = canonicalValue(s);
      expect(v).toMatch(/^[A-Z0-9]*$/);
      expect(canonicalValue(v)).toBe(v);
    }));
  });

  it("gives the same personal-number anchor for a passport and an ID card of one person", () => {
    const pass = canonicalAnchors({ issuingState: "BEL", documentType: "Passport", documentNumber: "EN1234567", personalNumber: "85073003328" });
    const card = canonicalAnchors({ issuingState: "BEL", documentType: "Identity Card", documentNumber: "592123456789", personalNumber: "85073003328" });
    expect(text(pass[0]!)).toBe(text(card[0]!));
    expect(text(pass[1]!)).not.toBe(text(card[1]!));
  });

  it("never anchors a personal number to a non-state issuer, and refuses unusable claims", () => {
    expect(canonicalAnchors({ issuingState: "XXA", documentType: "P", documentNumber: "AB123456", personalNumber: "1234567" }).map((a) => a.kind)).toEqual(["document"]);
    expect(canonicalAnchors({ issuingState: null, documentNumber: "AB123456" })).toEqual([]);
    expect(canonicalAnchors({ issuingState: "NLD", documentNumber: "12" })).toEqual([]);
  });

  it("does not duplicate an anchor when the document number equals the personal number", () => {
    expect(canonicalAnchors({ issuingState: "NLD", documentType: "ID", documentNumber: "123456782", personalNumber: "123456782" })).toHaveLength(1);
  });

  it("wipeAnchors zero-fills every buffer", () => {
    const a = canonicalAnchors({ issuingState: "ESP", documentType: "ID", documentNumber: "CAA000000", personalNumber: "99999999R" });
    wipeAnchors(a);
    for (const x of a) expect([...x.bytes].every((b) => b === 0)).toBe(true);
  });
});

describe("anchor memory", () => {
  it("returns unpooled Node.js Buffers that fill(0) wipes completely", async () => {
    const { Buffer } = await import("node:buffer");
    const a = canonicalAnchors({ issuingState: "BEL", documentType: "Identity Card", documentNumber: "592123456789", personalNumber: "85073003328" });
    expect(a).toHaveLength(2);
    for (const x of a) {
      expect(Buffer.isBuffer(x.bytes)).toBe(true);
      // Own ArrayBuffer, not a slice of Node's shared allocation pool.
      expect(x.bytes.byteOffset).toBe(0);
      expect(x.bytes.buffer.byteLength).toBe(x.bytes.length);
    }
    wipeAnchors(a);
    for (const x of a) expect(x.bytes.every((b) => b === 0)).toBe(true);
  });
});
