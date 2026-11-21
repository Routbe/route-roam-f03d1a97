import { createFileRoute } from "@tanstack/react-router";

/** RFC 8414 metadata of the OID4VCI token service (issuer `<origin>/oid4vci`, pre-authorized code only). */
export const Route = createFileRoute("/.well-known/oauth-authorization-server/oid4vci")({
  server: {
    handlers: {
      GET: async () => {
        const { issuer } = await import("@/lib/oauth/provider.server");
        const { authorizationServerMetadata } = await import("@/lib/eudi/oid4vci.server");
        return Response.json(authorizationServerMetadata(issuer()), { headers: { "cache-control": "public, max-age=300", "access-control-allow-origin": "*" } });
      },
    },
  },
});
