import { createFileRoute } from "@tanstack/react-router";

/**
 * GET /api/v1/kyc/status — the signed-in member's own verification state for polling:
 * { state: "none" | "pending" | "verified", realHuman, legalIdentity }. Read from Neon only; no
 * provider call, no identity data.
 */
export const Route = createFileRoute("/api_/v1/kyc/status")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const noStore = { "cache-control": "no-store" };
        const { guardRequest } = await import("@/lib/api-guard.server");
        const limited = guardRequest(request, "kyc-status", 120, 60_000);
        if (limited) return limited;
        const { currentUser } = await import("@/lib/auth/session.server");
        const user = await currentUser().catch(() => null);
        if (!user) return Response.json({ error: "unauthorized" }, { status: 401, headers: noStore });
        const { kycStatus } = await import("@/lib/kyc/kyc-engine.server");
        try {
          return Response.json(await kycStatus(user.id), { headers: noStore });
        } catch {
          return Response.json({ error: "unavailable" }, { status: 503, headers: noStore });
        }
      },
    },
  },
});
