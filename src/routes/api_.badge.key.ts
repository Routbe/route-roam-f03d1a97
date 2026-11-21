import { createFileRoute } from "@tanstack/react-router";

/**
 * GET /api/badge/key — ROUT's public Ed25519 key for blue-mark card attestations
 * (src/lib/identity/badge-attestation.ts). Public key only; no member data.
 */
export const Route = createFileRoute("/api_/badge/key")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const { guardRequest } = await import("@/lib/api-guard.server");
        const limited = guardRequest(request, "badge-key", 120, 60_000);
        if (limited) return limited;
        const { badgePublicKey } = await import("@/lib/identity/badge-attestation.server");
        const key = await badgePublicKey().catch(() => null);
        if (!key) {
          return new Response(JSON.stringify({ error: "not_configured" }), {
            status: 503,
            headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
          });
        }
        return new Response(JSON.stringify({ alg: "Ed25519", context: "rout.badge_attestation.v1", ...key }), {
          status: 200,
          headers: { "content-type": "application/json; charset=utf-8", "cache-control": "public, max-age=3600" },
        });
      },
    },
  },
});
