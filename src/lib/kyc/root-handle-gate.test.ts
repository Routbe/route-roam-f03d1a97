import { describe, expect, it } from "vitest";
import { rootHandleAllowed } from "./root-handle-gate";

describe("root handle only after Didit KYC", () => {
  it("refuses a member without any verification", () => {
    expect(rootHandleAllowed({ attestations: [], legacy: null })).toBe(false);
  });
  it("allows a Didit document attestation with legal identity", () => {
    expect(rootHandleAllowed({ attestations: [{ provider: "didit", evidence: "kyc_document", has_legal_identity: true }], legacy: null })).toBe(true);
  });
  it("refuses a zero-knowledge humanity proof or another provider", () => {
    expect(rootHandleAllowed({ attestations: [{ provider: "world_id", evidence: "zk_proof", has_legal_identity: false }], legacy: null })).toBe(false);
    expect(rootHandleAllowed({ attestations: [{ provider: "itsme", evidence: "kyc_document", has_legal_identity: true }], legacy: null })).toBe(false);
  });
  it("accepts the legacy Didit record, but not an unverified one", () => {
    expect(rootHandleAllowed({ attestations: [], legacy: { is_verified: true, verification_provider: "didit" } })).toBe(true);
    expect(rootHandleAllowed({ attestations: [], legacy: { is_verified: false, verification_provider: "didit" } })).toBe(false);
  });
});
