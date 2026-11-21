/**
 * Pure rule: may this account use the Developer Console?
 * Verified / paid / early believer, a claimed approved root handle, or a full
 * admin — and never when banned or suspended. Free /u/ aliases have none of
 * these signals and stay blocked.
 */
export type ConsoleAccessInput = {
  verified?: boolean | null;
  isPaid?: boolean | null;
  isEarlyBeliever?: boolean | null;
  isBanned?: boolean | null;
  isSuspended?: boolean | null;
  hasClaimedRootHandle?: boolean;
  isAdmin?: boolean;
};

export function canUseDeveloperConsole(input: ConsoleAccessInput | null | undefined): boolean {
  if (!input) return false;
  if (input.isBanned === true || input.isSuspended === true) return false;
  return (
    input.verified === true ||
    input.isPaid === true ||
    input.isEarlyBeliever === true ||
    input.hasClaimedRootHandle === true ||
    input.isAdmin === true
  );
}

/**
 * Creating new OAuth clients or API keys needs a KYC legal identity (the blue "KYC Attested" mark,
 * public-identity.server.ts). Pro, early-believer, an approved handle or admin rights never suffice,
 * and a banned or suspended member never qualifies. Existing apps and keys keep working.
 */
export function canIssueDeveloperCredentials(input: { legalIdentity?: boolean | null; isBanned?: boolean | null; isSuspended?: boolean | null } | null | undefined): boolean {
  if (!input) return false;
  if (input.isBanned === true || input.isSuspended === true) return false;
  return input.legalIdentity === true;
}

export const LEGAL_IDENTITY_REQUIRED = "LEGAL_IDENTITY_REQUIRED";
