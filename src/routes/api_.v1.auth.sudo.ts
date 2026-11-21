import { createFileRoute } from "@tanstack/react-router";

/**
 * /api/v1/auth/sudo — Sudo Mode for the signed-in member (same origin only).
 *   GET     { active, expiresAt, secondsLeft } of the current sudo session; no secrets.
 *   POST    after a passkey assertion (authClient.signIn.passkey(), verified with user verification
 *           by the WebAuthn hook) exchanges the fresh passkey step-up proof for the signed
 *           __Host-sudo_session cookie, valid exactly 300 s from the passkey verification.
 *   DELETE  ends sudo now.
 * Rules: src/lib/auth/sudo-rules.ts. Gate for server functions: requireSudo in middleware.ts.
 */
const noStore = { "cache-control": "no-store" } as const;

function sameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (origin) return origin === new URL(request.url).origin;
  // Browsers always send Origin on POST/DELETE; Sec-Fetch-Site covers the rest.
  const site = request.headers.get("sec-fetch-site");
  return site === null || site === "same-origin";
}

async function context(request: Request) {
  const { currentUser } = await import("@/lib/auth/session.server");
  const user = await currentUser().catch(() => null);
  if (!user) return null;
  const { readCookieHeader } = await import("@/lib/auth/sudo-rules");
  const header = request.headers.get("cookie");
  const { sessionTokenFromReader } = await import("@/lib/auth/sudo.server");
  return {
    userId: user.id,
    header,
    read: (name: string) => readCookieHeader(header, name),
    sessionToken: sessionTokenFromReader((name) => readCookieHeader(header, name)),
  };
}

function state(expiresAtSec: number | null) {
  const now = Math.floor(Date.now() / 1000);
  const left = expiresAtSec ? Math.max(0, expiresAtSec - now) : 0;
  return {
    active: left > 0,
    expiresAt: left > 0 ? new Date(expiresAtSec! * 1000).toISOString() : null,
    secondsLeft: left,
  };
}

export const Route = createFileRoute("/api_/v1/auth/sudo")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const { guardRequest } = await import("@/lib/api-guard.server");
        const limited = guardRequest(request, "auth-sudo-status", 120, 60_000);
        if (limited) return limited;
        const c = await context(request);
        if (!c) return Response.json({ error: "unauthorized" }, { status: 401, headers: noStore });
        const { SUDO_COOKIE } = await import("@/lib/auth/sudo-rules");
        const { verifySudoToken } = await import("@/lib/auth/sudo.server");
        const claims = await verifySudoToken(c.read(SUDO_COOKIE), c.userId, c.sessionToken).catch(
          () => null,
        );
        return Response.json(state(claims?.expiresAtSec ?? null), { headers: noStore });
      },
      POST: async ({ request }) => {
        const { guardRequest } = await import("@/lib/api-guard.server");
        const limited = guardRequest(request, "auth-sudo-open", 10, 60_000);
        if (limited) return limited;
        if (!sameOrigin(request))
          return Response.json({ error: "forbidden" }, { status: 403, headers: noStore });
        const c = await context(request);
        if (!c) return Response.json({ error: "unauthorized" }, { status: 401, headers: noStore });
        const { STEP_UP_COOKIE } = await import("@/lib/auth/step-up-rules");
        const { sudoSetCookie } = await import("@/lib/auth/sudo-rules");
        const { mintSudoToken } = await import("@/lib/auth/sudo.server");
        const minted = await mintSudoToken(c.userId, c.read(STEP_UP_COOKIE), c.sessionToken).catch(
          () => null,
        );
        if (!minted)
          return Response.json({ error: "passkey_required" }, { status: 401, headers: noStore });
        const { recordSecurityEvent } = await import("@/lib/audit-log.server");
        void recordSecurityEvent({
          eventType: "sudo.granted",
          userId: c.userId,
          payload: { expiresAt: minted.claims.expiresAtSec },
        });
        const body = state(minted.claims.expiresAtSec);
        return Response.json(body, {
          headers: { ...noStore, "set-cookie": sudoSetCookie(minted.value, body.secondsLeft) },
        });
      },
      DELETE: async ({ request }) => {
        if (!sameOrigin(request))
          return Response.json({ error: "forbidden" }, { status: 403, headers: noStore });
        const c = await context(request);
        const { sudoClearCookie } = await import("@/lib/auth/sudo-rules");
        if (c) {
          const { recordSecurityEvent } = await import("@/lib/audit-log.server");
          void recordSecurityEvent({ eventType: "sudo.ended", userId: c.userId, payload: {} });
        }
        return Response.json(state(null), {
          headers: { ...noStore, "set-cookie": sudoClearCookie() },
        });
      },
    },
  },
});
