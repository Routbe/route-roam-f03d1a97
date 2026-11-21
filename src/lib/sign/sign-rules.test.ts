import { describe, expect, it } from "vitest";
import { maySign, signerBinding } from "./sign-rules";

const N = "a".repeat(64);
const D = "b".repeat(64);
const ID = "11111111-2222-3333-4444-555555555555";

describe("maySign", () => {
  it("needs the full scroll and the read time", () => {
    expect(maySign({ elapsedSeconds: 30, minReadSeconds: 30, scrolledToEnd: true, pageCount: 2 })).toBe(true);
    expect(maySign({ elapsedSeconds: 29, minReadSeconds: 30, scrolledToEnd: true, pageCount: 2 })).toBe(false);
    expect(maySign({ elapsedSeconds: 99, minReadSeconds: 30, scrolledToEnd: false, pageCount: 2 })).toBe(false);
    expect(maySign({ elapsedSeconds: 99, minReadSeconds: 30, scrolledToEnd: true, pageCount: 0 })).toBe(false);
  });
});

describe("signerBinding", () => {
  it("is deterministic and changes with person, request and document", () => {
    const b = signerBinding(N, ID, D);
    expect(b).toMatch(/^[0-9a-f]{64}$/);
    expect(signerBinding(N, ID, D)).toBe(b);
    expect(signerBinding("c".repeat(64), ID, D)).not.toBe(b);
    expect(signerBinding(N, ID.replace("1", "9"), D)).not.toBe(b);
    expect(signerBinding(N, ID, "e".repeat(64))).not.toBe(b);
  });
  it("refuses malformed input", () => {
    expect(() => signerBinding("x", ID, D)).toThrow();
  });
});
