import { describe, expect, it } from "vitest";
import { AGE_GATE_SCOPES, ageGateMin, appNullifier, applyMinorFirewall, identityOsClaims, requestedMinAge } from "./identity-os-scopes";
import { SUPPORTED_SCOPES, OPTIONAL_SCOPES, validateRequestedScopes } from "./scope-rules";

const ROOT = "a".repeat(64);
const KEY = new Uint8Array(32).fill(7);
const KEY2 = new Uint8Array(32).fill(9);
const none = { legalIdentity: false, realHuman: false, ageVector: null, rootNullifier: null, legalName: null };

describe("age gate scopes", () => {
  it("cover exactly 13..21", () => {
    expect(AGE_GATE_SCOPES[0]).toBe("age_gate:13");
    expect(AGE_GATE_SCOPES.at(-1)).toBe("age_gate:21");
    expect(AGE_GATE_SCOPES).toHaveLength(9);
    expect(ageGateMin("age_gate:18")).toBe(18);
    for (const s of ["age_gate:12", "age_gate:22", "age_gate:1", "age_gate:18x", "age_gate?min_age=12", "age_gate?min_age=22"]) expect(ageGateMin(s)).toBeNull();
  });
  it("are issued and switchable on the consent screen", () => {
    for (const s of ["sybil_proof", "real_human", "legal_identity", "age_gate:18"]) {
      expect((SUPPORTED_SCOPES as readonly string[]).includes(s)).toBe(true);
      expect(OPTIONAL_SCOPES.includes(s)).toBe(true);
    }
    expect(validateRequestedScopes(["openid", "age_gate:22"], ["openid", "age_gate:22"])).toEqual({ ok: false, unknown: "age_gate:22" });
  });
});

describe("appNullifier", () => {
  it("is stable per app and differs across apps", () => {
    expect(appNullifier(ROOT, "app-1", KEY)).toBe(appNullifier(ROOT, "app-1", KEY));
    expect(appNullifier(ROOT, "app-1", KEY)).not.toBe(appNullifier(ROOT, "app-2", KEY));
    expect(appNullifier(ROOT, "app-1", KEY)).toMatch(/^[0-9a-f]{64}$/);
    expect(appNullifier(ROOT, "app-1", KEY)).not.toContain(ROOT);
  });
  it("cannot be reproduced without the server key", () => {
    expect(appNullifier(ROOT, "app-1", KEY)).not.toBe(appNullifier(ROOT, "app-1", KEY2));
  });
  it("refuses malformed input", () => {
    expect(() => appNullifier("BEL:PN:1", "app", KEY)).toThrow();
    expect(() => appNullifier(ROOT, "", KEY)).toThrow();
    expect(() => appNullifier(ROOT, "app", new Uint8Array(16))).toThrow();
  });
});

describe("identityOsClaims", () => {
  it("answers each granted scope and nothing else", () => {
    const r = identityOsClaims(["openid", "sybil_proof", "age_gate:18", "real_human", "legal_identity"], "app-1",
      { legalIdentity: true, realHuman: false, ageVector: 127, rootNullifier: ROOT, legalName: null }, KEY);
    expect(r.claims).toEqual({ sybil_proof: true, app_nullifier: appNullifier(ROOT, "app-1", KEY), age_verified: true, min_age: 18, is_real_human: false, has_legal_identity: true });
    expect(r.disclosed.sort()).toEqual(["age_gate:18", "legal_identity", "real_human", "sybil_proof"]);
    expect(identityOsClaims(["openid", "profile"], "app-1", none)).toEqual({ claims: {}, disclosed: [] });
  });
  it("issues no nullifier without the server key", () => {
    const r = identityOsClaims(["sybil_proof"], "app-1", { ...none, rootNullifier: ROOT });
    expect(r.claims).toEqual({ sybil_proof: false });
  });
  it("fails closed without an attestation", () => {
    const r = identityOsClaims(["sybil_proof", "age_gate:13", "legal_identity", "real_human"], "app-1", none);
    expect(r.claims).toEqual({ sybil_proof: false, age_verified: false, min_age: 13, has_legal_identity: false, is_real_human: false });
  });
  it("releases a legal name only with a legal identity", () => {
    const name = { first_name: "Ann", last_name: "Peeters", full_legal_name: "Ann Peeters" };
    expect(identityOsClaims(["legal_identity"], "a", { ...none, legalName: name }).claims).toEqual({ has_legal_identity: false });
    expect(identityOsClaims(["legal_identity"], "a", { ...none, legalIdentity: true, legalName: name }).claims).toEqual({ has_legal_identity: true, ...name });
  });
});

describe("dynamic age gate (age_gate?min_age=N)", () => {
  it("parses min_age 13..21 and defaults bare age_gate to 18", () => {
    expect(ageGateMin("age_gate?min_age=16")).toBe(16);
    expect(ageGateMin("age_gate?min_age=21")).toBe(21);
    expect(ageGateMin("age_gate")).toBe(18);
  });
  it("answers only age_verified and min_age", () => {
    // vector bits 13,14,15,16 set => 16 years old
    const r = identityOsClaims(["age_gate?min_age=16"], "a", { ...none, ageVector: 0b1111 });
    expect(r.claims).toEqual({ age_verified: true, min_age: 16 });
    expect(identityOsClaims(["age_gate?min_age=18"], "a", { ...none, ageVector: 0b1111 }).claims).toEqual({ age_verified: false, min_age: 18 });
  });
  it("uses the strictest of several age scopes", () => {
    expect(requestedMinAge(["age_gate:16", "age_gate?min_age=21"])).toBe(21);
  });
  it("is accepted by scope validation", () => {
    expect(validateRequestedScopes(["openid", "age_gate?min_age=16"], ["openid", "age_gate?min_age=16"])).toMatchObject({ ok: true });
  });
});

describe("minor firewall (< 18)", () => {
  const asked = ["openid", "sybil_proof", "real_human", "age_gate", "legal_identity", "email", "profile", "identity:legal_name"];
  it("strips every personal-data scope for a 16-year-old", () => {
    expect(applyMinorFirewall(asked, 0b1111)).toEqual(["openid", "sybil_proof", "real_human", "age_gate"]);
  });
  it("strips them for a 13-year-old (only the 13 bit set)", () => {
    expect(applyMinorFirewall(asked, 0b1)).not.toContain("legal_identity");
  });
  it("keeps the request for an adult", () => {
    expect(applyMinorFirewall(asked, 127)).toEqual(asked);
  });
  it("never returns a legal name to a minor even when legal_identity slips through", () => {
    const name = { first_name: "Ann", last_name: "Peeters", full_legal_name: "Ann Peeters" };
    expect(identityOsClaims(["legal_identity"], "a", { ...none, ageVector: 0b1111, legalIdentity: true, legalName: name }).claims).toEqual({});
  });
});
