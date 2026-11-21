import { createFileRoute } from "@tanstack/react-router";

/** OpenID4VCI credential issuer metadata (src/lib/eudi/oid4vci.server.ts). */
export const Route = createFileRoute("/.well-known/openid-credential-issuer")({
  server: {
    handlers: {
      GET: async () => {
        const { issuer } = await import("@/lib/oauth/provider.server");
        const { issuerMetadata } = await import("@/lib/eudi/oid4vci.server");
        return Response.json(issuerMetadata(issuer()), { headers: { "cache-control": "public, max-age=300", "access-control-allow-origin": "*" } });
      },
    },
  },
});
