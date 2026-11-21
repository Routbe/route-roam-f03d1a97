import { createFileRoute } from "@tanstack/react-router";

/** OID4VP response endpoint (response_mode direct_post) for requests started in the Developer Console. */
const cors = { "access-control-allow-origin": "*", "cache-control": "no-store" };
export const Route = createFileRoute("/api_/public/oauth/vp/response/$id")({
  server: {
    handlers: {
      OPTIONS: async () => new Response(null, { status: 204, headers: { ...cors, "access-control-allow-methods": "POST, OPTIONS", "access-control-allow-headers": "content-type" } }),
      POST: async ({ request, params }) => {
        if (!/^[0-9a-f-]{36}$/.test(params.id)) return Response.json({ error: "invalid_request" }, { status: 400, headers: cors });
        const { hitRateLimit, clientIp } = await import("@/lib/rate-limit-db.server");
        const { RATE_RULES, tooManyRequests } = await import("@/lib/rate-limit-rules");
        const limit = await hitRateLimit("oid4vp-response", clientIp(request), RATE_RULES.oauthToken);
        if (!limit.ok) return tooManyRequests(limit.retryAfter, cors);
        let form: URLSearchParams;
        try {
          const text = await request.text();
          if (text.length > 65536) throw new Error("size");
          form = new URLSearchParams(text);
        } catch {
          return Response.json({ error: "invalid_request" }, { status: 400, headers: cors });
        }
        const { issuer } = await import("@/lib/oauth/provider.server");
        const { handleVpResponse } = await import("@/lib/eudi/oid4vp.server");
        const r = await handleVpResponse(params.id, form, issuer());
        return Response.json(r.body, { status: r.status, headers: cors });
      },
    },
  },
});
