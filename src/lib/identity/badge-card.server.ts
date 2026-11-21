/**
 * Everything the blue-mark card needs from the server, prepared once per public profile read:
 * the legal name (sealed column first, legacy team-review name second), the minor firewall,
 * and the Ed25519 attestation over exactly what the card will show.
 */
import { maskMinorLegalName, monthKey, type BadgeAttestation, type BadgeMethod } from "./badge-attestation";

export async function prepareBadgeCard(input: {
  profileId: string;
  handle: string | null;
  method: BadgeMethod | null;
  namesAllowed: boolean;
  legacyName: string | null;
  country: string | null;
  verifiedAt: string | null;
}): Promise<{ name: string | null; nameMasked: boolean; attestation: BadgeAttestation | null }> {
  let name: string | null = null;
  if (input.namesAllowed) {
    const { openPublicLegalName } = await import("@/lib/kyc/legal-name-vault.server");
    name = (await openPublicLegalName(input.profileId)) ?? ((input.legacyName ?? "").trim() || null);
  }
  let nameMasked = false;
  if (name) {
    const { isPublicOwnerMinor } = await import("./public-minor.server");
    if (await isPublicOwnerMinor(input.profileId)) {
      name = maskMinorLegalName(name) || null;
      nameMasked = true;
    }
  }
  let attestation: BadgeAttestation | null = null;
  const handle = (input.handle ?? "").trim().toLowerCase();
  if (input.method && /^[a-z0-9._-]{1,64}$/.test(handle)) {
    try {
      const { signBadgeClaims } = await import("./badge-attestation.server");
      attestation = await signBadgeClaims({
        v: 1,
        handle,
        method: input.method,
        name,
        country: input.namesAllowed ? ((input.country ?? "").trim().toUpperCase() || null) : null,
        month: monthKey(input.verifiedAt),
        iat: Math.floor(Date.now() / 1000),
      });
    } catch (error) {
      console.warn("[badge-card:attestation:skipped]", error);
    }
  }
  return { name, nameMasked, attestation };
}
