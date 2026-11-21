import { describe, expect, it } from "vitest";
import { ecvrfProofToHash, ecvrfProve, ecvrfPublicKey, ecvrfVerify } from "./ecvrf";

const hex = (s: string) => Uint8Array.from(s.match(/../g)?.map((b) => parseInt(b, 16)) ?? []);
const toHex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

// RFC 9381 Appendix B.3, ECVRF-EDWARDS25519-SHA512-TAI, example 16 (alpha = empty string).
const SK = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
const PK = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const PI = "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805";
const BETA = "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae";

describe("ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381)", () => {
  it("matches the RFC public key, proof and output", () => {
    expect(toHex(ecvrfPublicKey(SK))).toBe(PK);
    const pi = ecvrfProve(SK, new Uint8Array());
    expect(toHex(pi)).toBe(PI);
    expect(toHex(ecvrfProofToHash(pi))).toBe(BETA);
  });

  it("verifies its own proof and rejects a tampered one or another input", () => {
    const alpha = new TextEncoder().encode("rout");
    const pi = ecvrfProve(SK, alpha);
    expect(toHex(ecvrfVerify(hex(PK), pi, alpha)!)).toBe(toHex(ecvrfProofToHash(pi)));
    const bad = pi.slice(); bad[40] ^= 1;
    expect(ecvrfVerify(hex(PK), bad, alpha)).toBeNull();
    expect(ecvrfVerify(hex(PK), pi, new TextEncoder().encode("other"))).toBeNull();
  });
});
