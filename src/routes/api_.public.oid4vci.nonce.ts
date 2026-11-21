import { createFileRoute } from "@tanstack/react-router";

/** OID4VCI nonce endpoint: a stateless, HMAC-bound c_nonce valid for five minutes. */
const cors = { "access-control-allow-origin": "*", "cache-control": "no-store" };
export const Route = createFileRoute("/api_/public/oid4vci/nonce")({
  server: {
    handlers: {
      OPTIONS: async () => new Response(null, { status: 204, headers: { ...cors, "access-control-allow-methods": "POST, OPTIONS" } }),
      POST: async ({ request }) => {
        const { hitRateLimit, clientIp } = await import("@/lib/rate-limit-db.server");
        const { RATE_RULES, tooManyRequests } = await import("@/lib/rate-limit-rules");
        const limit = await hitRateLimit("oid4vci-nonce", clientIp(request), RATE_RULES.oauthToken);
        if (!limit.ok) return tooManyRequests(limit.retryAfter, cors);
        const { newCNonce, newDpopNonce } = await import("@/lib/eudi/keys.server");
        const c_nonce = await newCNonce();
        const dpopNonce = await newDpopNonce();
        return c_nonce
          ? Response.json({ c_nonce }, { headers: { ...cors, "access-control-expose-headers": "DPoP-Nonce", ...(dpopNonce ? { "dpop-nonce": dpopNonce } : {}) } })
          : Response.json({ error: "temporarily_unavailable" }, { status: 503, headers: cors });
      },
    },
  },
});
