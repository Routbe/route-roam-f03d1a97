/**
 * Which identity mark a public profile shows next to the name.
 *
 * - Root profile with a KYC attestation: the blue "KYC Attested" shield is always shown;
 *   the member cannot switch it off on their main identity.
 * - Root profile without KYC: the green "Real Human" shield only after a zero-knowledge proof
 *   and only when the member chose it (and the badge is visible).
 * - Alias profile: a mark appears only when the member explicitly switched on
 *   "Verificatiebadge op je aliasprofiel" (off by default, protecting pseudonymity).
 */
export type IdentityBadgeInput = {
  space: "root" | "alias";
  kycAttested: boolean;
  zkHuman: boolean;
  humanLinked: boolean;
  badgeVisible: boolean;
  badgeType: string;
  isBusiness: boolean;
  isInfluencer: boolean;
  aliasBadgeVisible: boolean;
};

export function showsIdentityBadge(i: IdentityBadgeInput): boolean {
  if (i.space === "alias") return i.aliasBadgeVisible && (i.humanLinked || i.kycAttested || i.zkHuman);
  if (i.kycAttested) return true;
  return (
    i.badgeVisible &&
    i.badgeType === "human" &&
    i.zkHuman &&
    !i.isBusiness &&
    !i.isInfluencer
  );
}
