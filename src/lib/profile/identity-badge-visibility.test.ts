import { describe, expect, it } from "vitest";
import { showsIdentityBadge, type IdentityBadgeInput } from "./identity-badge-visibility";

const base: IdentityBadgeInput = {
  space: "root", kycAttested: false, zkHuman: false, humanLinked: false,
  badgeVisible: true, badgeType: "verified", isBusiness: false, isInfluencer: false, aliasBadgeVisible: false,
};

describe("identity badge visibility", () => {
  it("blue shield is always shown on a KYC-attested root profile, even when switched off", () => {
    expect(showsIdentityBadge({ ...base, kycAttested: true, badgeVisible: false, badgeType: "none" })).toBe(true);
  });
  it("no mark on a root profile without KYC or zero-knowledge proof", () => {
    expect(showsIdentityBadge(base)).toBe(false);
  });
  it("green shield on root needs a zero-knowledge proof", () => {
    expect(showsIdentityBadge({ ...base, badgeType: "human", zkHuman: true })).toBe(true);
    expect(showsIdentityBadge({ ...base, badgeType: "human", zkHuman: false })).toBe(false);
  });
  it("alias shows nothing unless the alias toggle is on", () => {
    expect(showsIdentityBadge({ ...base, space: "alias", humanLinked: true, kycAttested: true })).toBe(false);
    expect(showsIdentityBadge({ ...base, space: "alias", humanLinked: true, aliasBadgeVisible: true })).toBe(true);
  });
});
