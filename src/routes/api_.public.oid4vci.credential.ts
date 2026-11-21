import { createFileRoute } from "@tanstack/react-router";

/** OID4VCI credential endpoint: DPoP-bound access token + DPoP proof + holder key proof -> one SD-JWT VC. */
const cors = { "access-control-allow-origin": "*", "cache-control": "no-store", "access-control-expose-headers": "DPoP-Nonce, WWW-Authenticate" };
export const Route = createFileRoute("/api_/public/oid4vci/credential")({
  server: {
    handlers: {
      OPTIONS: async () =>
        new Response(null, { status: 204, headers: { ...cors, "access-control-allow-methods": "POST, OPTIONS", "access-control-allow-headers": "content-type, authorization, dpop" } }),
      POST: async ({ request }) => {
        const { hitRateLimit, clientIp } = await import("@/lib/rate-limit-db.server");
        const { RATE_RULES, tooManyRequests } = await import("@/lib/rate-limit-rules");
        const limit = await hitRateLimit("oid4vci-credential", clientIp(request), RATE_RULES.oauthToken);
        if (!limit.ok) return tooManyRequests(limit.retryAfter, cors);
        let body: unknown;
        try {
          const text = await request.text();
          if (text.length > 16384) throw new Error("size");
          body = JSON.parse(text);
        } catch {
          return Response.json({ error: "invalid_credential_request" }, { status: 400, headers: cors });
        }
        const { issuer } = await import("@/lib/oauth/provider.server");
        const { issueCredential, freshDpopNonce } = await import("@/lib/eudi/oid4vci.server");
        const r = await issueCredential(request.headers.get("authorization"), body, issuer(), { header: request.headers.get("dpop"), method: request.method });
        const nonce = await freshDpopNonce();
        const headers: Record<string, string> = { ...cors, ...(nonce ? { "dpop-nonce": nonce } : {}) };
        if (!r.ok && r.status === 401) headers["www-authenticate"] = `DPoP error="${r.error}", algs="ES256 Ed25519"`;
        return r.ok
          ? Response.json(r.body, { headers })
          : Response.json({ error: r.error, error_description: r.description }, { status: r.status, headers });
      },
    },
  },
});
