/**
 * Pure rules for Sudo Mode: a short window in which passkey-gated actions run without a new tap.
 * A sudo session exists only after a verified user-verifying passkey assertion (the Better Auth
 * WebAuthn hook grants a passkey step-up proof; /api/v1/auth/sudo exchanges it). Its lifetime is a
 * hard 300 s counted from that passkey verification, never extended or renewed, and the signed token
 * is bound to the member and to the current sign-in session.
 */
export const SUDO_TTL_SEC = 300;
export const SUDO_REQUIRED = "SUDO_REQUIRED";
/** __Host- prefix: Secure, Path=/ and no Domain are enforced by the browser. */
export const SUDO_COOKIE = "__Host-sudo_session";
/** Signed body: `s1.<user>.<session binding>.<passkey verified at s>.<expires at s>.<proof id>`. */
const VERSION = "s1";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const BINDING = /^[0-9a-f]{32}$/;
const JTI = /^[A-Za-z0-9_-]{22}$/;
/** Clock skew tolerated for a token stamped slightly in the future. */
const SKEW_SEC = 5;

export type SudoClaims = {
  userId: string;
  binding: string;
  verifiedAtSec: number;
  expiresAtSec: number;
  jti: string;
};

export function sudoPayload(
  userId: string,
  binding: string,
  verifiedAtSec: number,
  jti: string,
): string {
  if (
    !UUID.test(userId) ||
    !BINDING.test(binding) ||
    !JTI.test(jti) ||
    !Number.isSafeInteger(verifiedAtSec)
  )
    throw new Error("sudo_payload_invalid");
  return `${VERSION}.${userId}.${binding}.${verifiedAtSec}.${verifiedAtSec + SUDO_TTL_SEC}.${jti}`;
}

/** Owner, session, shape and the hard 300 s window; anything else is null. */
export function parseSudoPayload(
  payload: string,
  userId: string,
  binding: string,
  nowSec: number,
): SudoClaims | null {
  const parts = payload.split(".");
  if (parts.length !== 6) return null;
  const [v, uid, bind, at, exp, jti] = parts as [string, string, string, string, string, string];
  if (v !== VERSION || !UUID.test(uid) || uid !== userId) return null;
  if (!BINDING.test(bind) || !BINDING.test(binding) || !constantTimeEqual(bind, binding))
    return null;
  if (!JTI.test(jti)) return null;
  const verifiedAtSec = Number(at);
  const expiresAtSec = Number(exp);
  if (!Number.isSafeInteger(verifiedAtSec) || !Number.isSafeInteger(expiresAtSec)) return null;
  // The lifetime is fixed: a token claiming any other window was not minted here.
  if (expiresAtSec - verifiedAtSec !== SUDO_TTL_SEC) return null;
  if (verifiedAtSec > nowSec + SKEW_SEC || nowSec >= expiresAtSec) return null;
  return { userId: uid, binding: bind, verifiedAtSec, expiresAtSec, jti };
}

/** Only a general passkey proof (never an action-scoped or other-factor proof) may open sudo. */
export function proofOpensSudo(
  proof: { method: string; scope: string } | null | undefined,
): boolean {
  return !!proof && proof.method === "passkey" && proof.scope === "*";
}

export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

export function isSudoRequiredError(e: unknown): boolean {
  return e instanceof Error && e.message.includes(SUDO_REQUIRED);
}

/** Reads one cookie from a Cookie header; the first occurrence wins, malformed encoding is ignored. */
export function readCookieHeader(
  header: string | null | undefined,
  name: string,
): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 0 || part.slice(0, i).trim() !== name) continue;
    const raw = part.slice(i + 1).trim();
    try {
      return decodeURIComponent(raw);
    } catch {
      return undefined;
    }
  }
  return undefined;
}

/** Better Auth session cookies carry `<token>.<signature>`; only the token identifies the session. */
export const SESSION_COOKIES = [
  "__Secure-better-auth.session_token",
  "better-auth.session_token",
] as const;
export function sessionTokenFrom(raw: string | undefined): string | null {
  if (!raw) return null;
  const token = raw.split(".")[0] ?? "";
  return token.length >= 16 && token.length <= 256 ? token : null;
}

export function sudoSetCookie(value: string, maxAgeSec: number): string {
  return `${SUDO_COOKIE}=${encodeURIComponent(value)}; Path=/; Max-Age=${Math.max(0, Math.floor(maxAgeSec))}; HttpOnly; Secure; SameSite=Strict`;
}
export function sudoClearCookie(): string {
  return `${SUDO_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}
