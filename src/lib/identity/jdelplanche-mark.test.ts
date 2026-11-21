import { describe, expect, it } from "vitest";
import { isLegacyReviewed } from "./legacy-mark";
import { showsIdentityBadge } from "@/lib/profile/identity-badge-visibility";

// A member approved by the ROUT team (verified + legal name + date, like @jdelplanche) always
// carries the blue mark on the main profile, even when the badge toggle is off.
describe("team-verified main profile", () => {
  const row = { verified: true, verified_legal_name: "Jona Delplanche", verified_at: "2026-10-10T08:16:00Z", is_banned: false, is_suspended: false };
  it("counts as verified", () => expect(isLegacyReviewed(row)).toBe(true));
  it("always shows the mark on rout.be/<handle>", () => {
    const kycAttested = isLegacyReviewed(row);
    expect(showsIdentityBadge({ space: "root", kycAttested, zkHuman: false, humanLinked: false, badgeVisible: false, badgeType: "none", isBusiness: false, isInfluencer: false, aliasBadgeVisible: false })).toBe(true);
  });
  it("alias shows the white mark only when switched on", () => {
    const base = { space: "alias" as const, kycAttested: false, zkHuman: false, humanLinked: true, badgeVisible: true, badgeType: "verified", isBusiness: false, isInfluencer: false };
    expect(showsIdentityBadge({ ...base, aliasBadgeVisible: false })).toBe(false);
    expect(showsIdentityBadge({ ...base, aliasBadgeVisible: true })).toBe(true);
  });
});
