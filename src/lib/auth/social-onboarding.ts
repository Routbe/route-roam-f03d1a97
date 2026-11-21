/**
 * Passkey-enforced social onboarding (owner directive 2026-11-18).
 *
 * A new visitor who signs in with Google, GitHub or GitLab gets NO account from the OAuth
 * callback: providers keep `disableSignUp`. Instead the callback hands back a short-lived,
 * HMAC-signed onboarding ticket in an HttpOnly cookie, in state `pending_passkey_setup`. The
 * onboarding dialog then asks the age (server keeps only the whole-year floor) and registers
 * a passkey; only that verified ceremony creates the account and links the provider identity
 * (passkey-enrollment.server.ts). Abandoning the flow leaves nothing in the database.
 *
 * Format: `so.<b64url(json)>.<b64url(hmac)>`, valid 10 minutes. Pure and runtime-neutral.
 */
const enc = new TextEncoder();

export const SOCIAL_ONBOARD_PREFIX = "so.";
export const SOCIAL_ONBOARD_TTL_S = 10 * 60;
/** __Host- prefix: Secure, Path=/ and no Domain are enforced by the browser. */
export const SOCIAL_ONBOARD_COOKIE = "__Host-rout_social_onboard";
export const PENDING_PASSKEY_SETUP = "pending_passkey_setup" as const;
/** Providers whose verified e-mail may start an account (each still needs a passkey). */
export const ONBOARDING_PROVIDERS = new Set(["google", "github", "gitlab"]);
/** Where the callback sends a new member; the sign-up card opens the dialog from this value. */
export const SOCIAL_ONBOARD_PATH = "/auth/sign-up?onboard=social";

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export type SocialOnboarding = {
  status: typeof PENDING_PASSKEY_SETUP;
  provider: string;
  accountId: string;
  email: string;
  name: string;
  exp: number;
  nonce: string;
};

/** What the provider's userinfo call returned during the callback. */
export type CapturedSocialProfile = {
  provider: string;
  user: { id?: unknown; email?: unknown; emailVerified?: unknown; name?: unknown };
};

/**
 * Onboarding data from a captured profile, or null. Only allowed providers, only a stable
 * account id, and only an address the provider itself marks verified: an unverified address
 * would let anyone pre-claim someone else's e-mail.
 */
export function onboardingFromProfile(p: CapturedSocialProfile | null | undefined): Omit<SocialOnboarding, "exp" | "nonce" | "status"> | null {
  if (!p || !ONBOARDING_PROVIDERS.has(p.provider)) return null;
  const id = typeof p.user.id === "number" ? String(p.user.id) : p.user.id;
  if (typeof id !== "string" || !id || id.length > 255) return null;
  if (p.user.emailVerified !== true || typeof p.user.email !== "string") return null;
  const email = p.user.email.trim().toLowerCase();
  if (!EMAIL.test(email) || email.length > 254) return null;
  const name = typeof p.user.name === "string" ? p.user.name.trim().slice(0, 80) : "";
  return { provider: p.provider, accountId: id, email, name };
}

const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64url = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));

function key(secret: string) {
  // Own domain label: a sign-up ticket can never pass as an onboarding ticket or the reverse.
  return crypto.subtle.importKey("raw", enc.encode(`rout-social-onboard:v1:${secret}`), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

export async function signSocialOnboarding(secret: string, data: Omit<SocialOnboarding, "exp" | "nonce" | "status">, nowS: number): Promise<string> {
  const t: SocialOnboarding = { status: PENDING_PASSKEY_SETUP, ...data, exp: nowS + SOCIAL_ONBOARD_TTL_S, nonce: b64url(crypto.getRandomValues(new Uint8Array(12))) };
  const body = b64url(enc.encode(JSON.stringify(t)));
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", await key(secret), enc.encode(body)));
  return `${SOCIAL_ONBOARD_PREFIX}${body}.${b64url(sig)}`;
}

export async function verifySocialOnboarding(secret: string, token: string | null | undefined, nowS: number): Promise<SocialOnboarding | null> {
  if (!token || token.length > 2048 || !token.startsWith(SOCIAL_ONBOARD_PREFIX)) return null;
  const [body, sig] = token.slice(SOCIAL_ONBOARD_PREFIX.length).split(".");
  if (!body || !sig) return null;
  try {
    if (!(await crypto.subtle.verify("HMAC", await key(secret), fromB64url(sig) as BufferSource, enc.encode(body)))) return null;
    const t = JSON.parse(new TextDecoder().decode(fromB64url(body))) as SocialOnboarding;
    if (t.status !== PENDING_PASSKEY_SETUP || typeof t.exp !== "number" || t.exp < nowS) return null;
    if (!ONBOARDING_PROVIDERS.has(t.provider) || typeof t.accountId !== "string" || !t.accountId || typeof t.email !== "string") return null;
    return t;
  } catch {
    return null;
  }
}

export function onboardingCookie(value: string): string {
  return `${SOCIAL_ONBOARD_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SOCIAL_ONBOARD_TTL_S}`;
}

export function clearOnboardingCookie(): string {
  return `${SOCIAL_ONBOARD_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

export function readOnboardingCookie(cookieHeader: string | null | undefined): string | null {
  for (const part of (cookieHeader ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === SOCIAL_ONBOARD_COOKIE) return part.slice(i + 1).trim() || null;
  }
  return null;
}
