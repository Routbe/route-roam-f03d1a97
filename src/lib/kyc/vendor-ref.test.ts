import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { openVendorRef, sealVendorRef } from "./vendor-ref";

const SECRET = "s".repeat(40);
const USER = "0b1c2d3e-4f50-4617-8899-aabbccddeeff";
const STATE = "ab".repeat(24);

describe("sealed Didit vendor reference", () => {
  it("round-trips member id and state", () => {
    expect(openVendorRef(sealVendorRef(USER, STATE, SECRET), SECRET)).toEqual({ userId: USER, state: STATE });
  });

  it("never shows the member id to Didit and is fresh every time", () => {
    const a = sealVendorRef(USER, STATE, SECRET);
    const b = sealVendorRef(USER, STATE, SECRET);
    expect(a).not.toBe(b);
    expect(a).not.toContain(USER.replace(/-/g, "").slice(0, 8));
    expect(Buffer.from(a.slice(4), "base64url").toString("hex")).not.toContain(USER.replace(/-/g, ""));
  });

  it("rejects a reference opened with another secret", () => {
    expect(openVendorRef(sealVendorRef(USER, STATE, SECRET), "t".repeat(40))).toBeNull();
  });

  it("rejects every tampered byte", () => {
    const ref = sealVendorRef(USER, STATE, SECRET);
    const raw = Buffer.from(ref.slice(4), "base64url");
    fc.assert(fc.property(fc.integer({ min: 0, max: raw.length - 1 }), fc.integer({ min: 1, max: 255 }), (i, x) => {
      const t = Buffer.from(raw);
      t[i]! ^= x;
      expect(openVendorRef("rk1." + t.toString("base64url"), SECRET)).toBeNull();
    }));
  });

  it("never throws on arbitrary input", () => {
    fc.assert(fc.property(fc.anything(), (v) => {
      expect(openVendorRef(v, SECRET)).toBeNull();
    }));
    expect(openVendorRef("rk1." + "A".repeat(300), SECRET)).toBeNull();
  });

  it("refuses bad input and a short secret when sealing", () => {
    expect(() => sealVendorRef("not-a-uuid", STATE, SECRET)).toThrow("kyc_invalid_ref");
    expect(() => sealVendorRef(USER, "zz", SECRET)).toThrow("kyc_invalid_ref");
    expect(() => sealVendorRef(USER, STATE, "short")).toThrow("kyc_not_configured");
  });
});
