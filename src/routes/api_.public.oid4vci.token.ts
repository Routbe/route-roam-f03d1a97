import { createFileRoute } from "@tanstack/react-router";

/** OID4VCI token endpoint: pre-authorized code + transaction code + DPoP proof (RFC 9449) -> short-lived DPoP-bound access token. */
const cors = { "access-control-allow-origin": "*", "cache-control": "no-store", "access-control-expose-headers": "DPoP-Nonce, WWW-Authenticate" };
export const Route = createFileRoute("/api_/public/oid4vci/token")({
  server: {
    handlers: {
      OPTIONS: async () =>
        new Response(null, { status: 204, headers: { ...cors, "access-control-allow-methods": "POST, OPTIONS", "access-control-allow-headers": "content-type, dpop" } }),
      POST: async ({ request }) => {
        const { hitRateLimit, clientIp } = await import("@/lib/rate-limit-db.server");
        const { RATE_RULES, tooManyRequests } = await import("@/lib/rate-limit-rules");
        const limit = await hitRateLimit("oid4vci-token", clientIp(request), RATE_RULES.oauthToken);
        if (!limit.ok) return tooManyRequests(limit.retryAfter, cors);
        let form: URLSearchParams;
        try {
          const text = await request.text();
          if (text.length > 4096) throw new Error("size");
          form = new URLSearchParams(text);
        } catch {
          return Response.json({ error: "invalid_request" }, { status: 400, headers: cors });
        }
        const { issuer } = await import("@/lib/oauth/provider.server");
        const { redeemPreAuthorizedCode, freshDpopNonce } = await import("@/lib/eudi/oid4vci.server");
        const r = await redeemPreAuthorizedCode(form, { header: request.headers.get("dpop"), method: request.method, iss: issuer() });
        const nonce = await freshDpopNonce();
        const headers: Record<string, string> = { ...cors, ...(nonce ? { "dpop-nonce": nonce } : {}) };
        if (!r.ok && (r.error === "invalid_dpop_proof" || r.error === "use_dpop_nonce")) {
          headers["www-authenticate"] = `DPoP error="${r.error}", algs="ES256 Ed25519"`;
        }
        return r.ok
          ? Response.json(r.body, { headers })
          : Response.json({ error: r.error, error_description: r.description }, { status: r.status, headers });
      },
    },
  },
});
