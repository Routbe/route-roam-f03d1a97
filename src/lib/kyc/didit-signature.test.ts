import { createHmac } from "node:crypto";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { digestsEqual, MAX_SKEW_SECONDS, verifyDiditSignature } from "./didit-signature";

const SECRET = "whsec_" + "k".repeat(40);
const NOW = 1_800_000_000;
const sign = (raw: Uint8Array, secret = SECRET) => createHmac("sha256", secret).update(raw).digest("hex");
const check = (raw: Uint8Array, signature: string | null, extra: Partial<Parameters<typeof verifyDiditSignature>[0]> = {}) =>
  verifyDiditSignature({ raw, secret: SECRET, signature, timestamp: String(NOW), nowSeconds: NOW, ...extra });

describe("Didit webhook HMAC-SHA256 (timing-safe)", () => {
  it("accepts the exact signature over any raw body", () => {
    fc.assert(fc.property(fc.uint8Array({ maxLength: 512 }), (raw) => {
      expect(check(raw, sign(raw))).toEqual({ ok: true });
    }));
  });

  it("accepts upper-case hex and surrounding whitespace", () => {
    const raw = new TextEncoder().encode('{"a":1}');
    expect(check(raw, ` ${sign(raw).toUpperCase()} `).ok).toBe(true);
  });

  it("rejects any single-bit change of the body", () => {
    fc.assert(fc.property(fc.uint8Array({ minLength: 1, maxLength: 256 }), fc.nat(), fc.integer({ min: 0, max: 7 }), (raw, i, bit) => {
      const sig = sign(raw);
      const tampered = new Uint8Array(raw);
      tampered[i % raw.length]! ^= 1 << bit;
      expect(check(tampered, sig)).toEqual({ ok: false, reason: "bad_signature" });
    }));
  });

  it("rejects any change of the signature", () => {
    fc.assert(fc.property(fc.uint8Array({ maxLength: 128 }), fc.integer({ min: 0, max: 63 }), (raw, pos) => {
      const sig = sign(raw);
      const flipped = sig.slice(0, pos) + (sig[pos] === "0" ? "1" : "0") + sig.slice(pos + 1);
      expect(check(raw, flipped).ok).toBe(false);
    }));
  });

  it("rejects a signature made with another secret", () => {
    fc.assert(fc.property(fc.uint8Array({ maxLength: 128 }), fc.string({ minLength: 1, maxLength: 40 }), (raw, other) => {
      fc.pre(other !== SECRET);
      expect(check(raw, sign(raw, other)).ok).toBe(false);
    }));
  });

  it("enforces the 300-second window in both directions", () => {
    const raw = new TextEncoder().encode("{}");
    fc.assert(fc.property(fc.integer({ min: -MAX_SKEW_SECONDS, max: MAX_SKEW_SECONDS }), (d) => {
      expect(check(raw, sign(raw), { timestamp: String(NOW + d) }).ok).toBe(true);
    }));
    fc.assert(fc.property(fc.integer({ min: MAX_SKEW_SECONDS + 1, max: 10 ** 7 }), fc.boolean(), (d, past) => {
      expect(check(raw, sign(raw), { timestamp: String(past ? NOW - d : NOW + d) })).toEqual({ ok: false, reason: "stale" });
    }));
  });

  it("refuses missing pieces with a precise reason", () => {
    const raw = new TextEncoder().encode("{}");
    expect(check(raw, sign(raw), { secret: undefined })).toEqual({ ok: false, reason: "no_secret" });
    expect(check(raw, sign(raw), { timestamp: null })).toEqual({ ok: false, reason: "no_timestamp" });
    expect(check(raw, sign(raw), { timestamp: "12.5" })).toEqual({ ok: false, reason: "no_timestamp" });
    expect(check(raw, null)).toEqual({ ok: false, reason: "no_signature" });
    expect(check(raw, "not-hex")).toEqual({ ok: false, reason: "no_signature" });
    expect(check(raw, sign(raw).slice(0, 62))).toEqual({ ok: false, reason: "no_signature" });
  });

  it("accepts X-Signature-Previous during a secret rotation", () => {
    const raw = new TextEncoder().encode('{"x":2}');
    expect(check(raw, "0".repeat(64), { previousSignature: sign(raw) }).ok).toBe(true);
    expect(check(raw, "0".repeat(64), { previousSignature: "1".repeat(64) }).ok).toBe(false);
  });

  it("digestsEqual never throws on length mismatch and is reflexive", () => {
    fc.assert(fc.property(fc.uint8Array({ maxLength: 40 }), fc.uint8Array({ maxLength: 40 }), (a, b) => {
      const r = digestsEqual(a, b);
      expect(r).toBe(a.length > 0 && Buffer.from(a).equals(Buffer.from(b)));
    }));
  });
});
