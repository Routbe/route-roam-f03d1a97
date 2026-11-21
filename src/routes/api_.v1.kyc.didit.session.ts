import { createFileRoute } from "@tanstack/react-router";

/**
 * POST /api/v1/kyc/didit/session — signed-in members only (session cookie, same origin).
 * Opens a Didit v3 verification session and returns only { session_url, session_token }.
 * DIDIT_API_KEY stays in the server runtime (src/lib/kyc/didit-client.server.ts).
 */
export const Route = createFileRoute("/api_/v1/kyc/didit/session")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const noStore = { "cache-control": "no-store" };
        const { guardRequest } = await import("@/lib/api-guard.server");
        const limited = guardRequest(request, "kyc-didit-session", 10, 60_000);
        if (limited) return limited;
        const origin = request.headers.get("origin");
        if (origin && origin !== new URL(request.url).origin) return Response.json({ error: "forbidden" }, { status: 403, headers: noStore });

        const { currentUser } = await import("@/lib/auth/session.server");
        const user = await currentUser().catch(() => null);
        if (!user) return Response.json({ error: "unauthorized" }, { status: 401, headers: noStore });

        const { startDiditKyc } = await import("@/lib/kyc/kyc-engine.server");
        const result = await startDiditKyc(user.id, origin ?? new URL(request.url).origin).catch(() => ({ ok: false as const, reason: "provider_error" as const }));
        if (!result.ok) {
          const status = result.reason === "already_verified" ? 409 : result.reason === "limit_reached" ? 429 : 503;
          return Response.json({ error: result.reason }, { status, headers: noStore });
        }
        return Response.json({ session_url: result.session_url, session_token: result.session_token }, { headers: noStore });
      },
    },
  },
});
