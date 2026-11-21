/**
 * Sudo Mode on the server. A sudo token is minted only from a fresh, general passkey step-up proof
 * (granted by the verified WebAuthn hook in better-auth.server.ts), lives exactly SUDO_TTL_SEC from
 * that passkey verification, is HMAC-signed under its own key label and bound to the member and the
 * current sign-in session. Nothing is stored server-side; ending sudo clears the cookie.
 */
import { hmacSha256Hex } from "@/lib/audit-chain";
import {
  SESSION_COOKIES,
  SUDO_COOKIE,
  SUDO_REQUIRED,
  constantTimeEqual,
  parseSudoPayload,
  proofOpensSudo,
  sessionTokenFrom,
  sudoPayload,
  type SudoClaims,
} from "./sudo-rules";

export class SudoRequiredError extends Error {
  status = 401;
  constructor() {
    super(SUDO_REQUIRED);
  }
}

async function sudoKey(): Promise<string> {
  const { resolveAuthSecret } = await import("@/lib/better-auth.server");
  const s = resolveAuthSecret();
  if (!s) throw new Error("auth secret missing");
  // Own label: a step-up proof signature can never pass as a sudo token, nor the reverse.
  return `sudo:${s.secret}`;
}

/** 128-bit binding of the sign-in session; the raw session token never enters the sudo token. */
export async function sessionBinding(sessionToken: string): Promise<string> {
  return (await hmacSha256Hex(await sudoKey(), `session:${sessionToken}`)).slice(0, 32);
}

async function sign(payload: string): Promise<string> {
  return `${payload}.${await hmacSha256Hex(await sudoKey(), payload)}`;
}

export async function verifySudoToken(
  raw: string | null | undefined,
  userId: string,
  sessionToken: string | null,
  nowSec = Math.floor(Date.now() / 1000),
): Promise<SudoClaims | null> {
  if (!raw || raw.length > 300 || !sessionToken) return null;
  const i = raw.lastIndexOf(".");
  if (i < 0) return null;
  const payload = raw.slice(0, i);
  if (!constantTimeEqual(raw.slice(i + 1), await hmacSha256Hex(await sudoKey(), payload)))
    return null;
  return parseSudoPayload(payload, userId, await sessionBinding(sessionToken), nowSec);
}

/**
 * Exchanges the step-up cookie for a sudo token. Only a general passkey proof of this member
 * opens sudo; the window ends SUDO_TTL_SEC after the passkey was verified, however late the exchange.
 */
export async function mintSudoToken(
  userId: string,
  stepUpRaw: string | null | undefined,
  sessionToken: string | null,
  nowSec = Math.floor(Date.now() / 1000),
): Promise<{ value: string; claims: SudoClaims } | null> {
  if (!sessionToken) return null;
  const { verifyStepUpProof } = await import("./step-up.server");
  const proof = await verifyStepUpProof(stepUpRaw, userId, nowSec);
  if (!proofOpensSudo(proof)) return null;
  const { newStepUpJti } = await import("./step-up-rules");
  const binding = await sessionBinding(sessionToken);
  const payload = sudoPayload(userId, binding, proof!.verifiedAtSec, newStepUpJti());
  const claims = parseSudoPayload(payload, userId, binding, nowSec);
  if (!claims) return null;
  return { value: await sign(payload), claims };
}

export function sessionTokenFromReader(read: (name: string) => string | undefined): string | null {
  for (const name of SESSION_COOKIES) {
    const raw = read(name);
    if (raw) {
      let decoded = raw;
      try {
        decoded = decodeURIComponent(raw);
      } catch {
        return null;
      }
      return sessionTokenFrom(decoded);
    }
  }
  return null;
}

/**
 * Throws SudoRequiredError (401) unless the request carries a valid sudo token for this member
 * and this session. `read` defaults to the current request's cookies.
 */
export async function ensureSudo(
  userId: string,
  label: string,
  read?: (name: string) => string | undefined,
): Promise<SudoClaims> {
  let reader = read;
  if (!reader) {
    const { readRequestCookie } = await import("@/lib/request-context");
    reader = (name) => readRequestCookie(name);
  }
  const claims = await verifySudoToken(reader(SUDO_COOKIE), userId, sessionTokenFromReader(reader));
  if (!claims) {
    if (!read) {
      try {
        const { setCurrentResponseStatus } = await import("@/lib/request-context");
        setCurrentResponseStatus(401);
      } catch {
        /* not inside a request */
      }
    }
    throw new SudoRequiredError();
  }
  const { recordSecurityEvent } = await import("@/lib/audit-log.server");
  void recordSecurityEvent({
    eventType: `sudo.used.${label}`,
    userId,
    payload: { expiresAt: claims.expiresAtSec },
  });
  return claims;
}
