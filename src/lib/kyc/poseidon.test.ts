import { readFileSync } from "node:fs";
import { join } from "node:path";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { poseidon256, poseidonHash2, poseidonPermutation, TAG_MERKLE_2 } from "./poseidon";

const FIX = join(process.cwd(), "wasm/rout-zk/tests/fixtures");
const ref = JSON.parse(readFileSync(join(FIX, "poseidon/x5_255_3.json"), "utf8")) as { vectors: { input: string[]; output: string[] }[] };
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("Poseidon x5_255_3 (same instance as wasm/rout-zk)", () => {
  it("matches the hadeshash reference permutation vector", () => {
    for (const v of ref.vectors) {
      const out = poseidonPermutation(v.input.map((x) => BigInt(x)));
      expect(out.map((x) => `0x${x.toString(16).padStart(64, "0")}`)).toEqual(v.output);
    }
  });

  it("reproduces the rout-zk empty 256-deep SMT root (hash2 with the Merkle tag)", () => {
    let h = 0n;
    for (let i = 0; i < 256; i++) h = poseidonHash2(TAG_MERKLE_2, h, h);
    expect(h.toString(16).padStart(64, "0")).toBe(readFileSync(join(FIX, "smt/empty_root.hex"), "utf8").trim());
  });

  it("poseidon256 is deterministic and 32 bytes", () => {
    fc.assert(fc.property(fc.uint8Array({ maxLength: 200 }), (b) => {
      const a = poseidon256(b);
      expect(a).toHaveLength(32);
      expect(hex(poseidon256(b))).toBe(hex(a));
    }), { numRuns: 60 });
  });

  it("binds the length, so zero padding never collides", () => {
    const e = new TextEncoder();
    expect(hex(poseidon256(e.encode("BEL:PN:1")))).not.toBe(hex(poseidon256(new Uint8Array([...e.encode("BEL:PN:1"), 0]))));
    expect(hex(poseidon256(new Uint8Array(0)))).not.toBe(hex(poseidon256(new Uint8Array(31))));
  });

  it("distinct inputs give distinct digests", () => {
    fc.assert(fc.property(fc.uint8Array({ maxLength: 96 }), fc.uint8Array({ maxLength: 96 }), (a, b) => {
      fc.pre(hex(a) !== hex(b) || a.length !== b.length);
      expect(hex(poseidon256(a))).not.toBe(hex(poseidon256(b)));
    }), { numRuns: 60 });
  });

  it("refuses oversized input", () => {
    expect(() => poseidon256(new Uint8Array(513))).toThrow("poseidon_input_too_long");
  });
});
