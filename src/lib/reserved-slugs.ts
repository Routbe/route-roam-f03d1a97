/**
 * Single source of truth for handles that can never be claimed, because they
 * collide with product routes (`/studio`, `/claim`) or with the flat QR tool
 * pages on the root domain (`/iban-qr`, `/wifi-qr`, `/vcard-qr`).
 *
 * Client-safe: no server-only imports, so the signup form, the claim flow and
 * the server-side probe all validate against the exact same list.
 */

/** Flat QR tool pages living directly on the root domain. */
export const TOOL_SLUGS = [
  "iban-qr",
  "wifi-qr",
  "vcard-qr",
  "url-qr",
  "email-qr",
  "sms-qr",
  "text-qr",
] as const;

/** App/product routes and common reserved words. */
export const SYSTEM_SLUGS = [
  "about",
  "admin",
  "api",
  "auth",
  "batch",
  "billing",
  "blog",
  "card",
  "discover",
  "claim",
  "contact",
  "dashboard",
  "de",
  "dev",
  "docs",
  "domains",
  "email-templates",
  "en",
  "faq",
  "fr",
  "free",
  "go",
  "help",
  "hub",
  "legal",
  "login",
  "logout",
  "manifesto",
  "me",
  "my-data",
  "nl",
  "pricing",
  "privacy",
  "profile",
  "r",
  "register",
  "rout",
  "s",
  "security",
  "subscribe",
  "self-hosting",
  "settings",
  "signature",
  "signin",
  "signup",
  "sovereignty",
  "stats",
  "status",
  "studio",
  "support",
  "terms",
  "tools",
  "u",
  "verify",
] as const;

/**
 * Prioriteit 3 — systeemroutes en technische paden die nooit een handle mogen
 * worden (ook niet na Didit). Gespiegeld in db/0298 (handle_registry, system_reserved).
 */
export const SYSTEM_ROUTE_SLUGS = [
  "u",
  "api",
  "auth",
  "login",
  "register",
  "admin",
  "dashboard",
  "settings",
  "about",
  "verify",
  "badge",
  "badges",
  "workspace",
  "workspaces",
  "org",
  "support",
  "privacy",
  "terms",
  "legal",
  "security",
  "status",
  "rout",
  "delplanche",
  "postmaster",
  "abuse",
  "well-known",
  "robots.txt",
  "sitemap.xml",
] as const;

/**
 * Beschermde publieke, koninklijke en overheidsnamen. Nooit via Didit claimbaar;
 * enkel een admin kent ze handmatig toe aan een officiële Organisatie-Workspace.
 */
export const PROTECTED_PUBLIC_SLUGS = [
  "monarchie",
  "koninklijkpaleis",
  "palaisroyal",
  "belgie",
  "belgique",
  "belgien",
  "belgium",
  "brussels",
  "bruxelles",
  "brussel",
  "vlaanderen",
  "wallonie",
  "vrt",
  "rtbf",
  "federaal",
  "overheid",
  "gouvernement",
  "politie",
  "police",
] as const;

export const RESERVED_SLUGS: ReadonlySet<string> = new Set<string>([
  ...TOOL_SLUGS,
  ...SYSTEM_SLUGS,
  ...SYSTEM_ROUTE_SLUGS,
  ...PROTECTED_PUBLIC_SLUGS,
]);

const PROTECTED_SET: ReadonlySet<string> = new Set<string>(PROTECTED_PUBLIC_SLUGS);

/** Beschermde publieke term (koninklijk/overheid) — alleen admin-toekenning aan een workspace. */
export function isProtectedPublicSlug(handle: string): boolean {
  return PROTECTED_SET.has(handle.trim().replace(/^@/, "").toLowerCase());
}

export const RESERVED_SLUG_MESSAGE = "This handle is reserved by the platform.";

export function isReservedSlug(handle: string): boolean {
  return RESERVED_SLUGS.has(handle.trim().replace(/^@/, "").toLowerCase());
}
