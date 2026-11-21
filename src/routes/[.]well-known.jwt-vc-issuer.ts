import { createFileRoute } from "@tanstack/react-router";

/** SD-JWT VC issuer metadata: the ES256 key that signs ROUT wallet credentials and the status list. */
export const Route = createFileRoute("/.well-known/jwt-vc-issuer")({
  server: {
    handlers: {
      GET: async () => {
        const { issuer } = await import("@/lib/oauth/provider.server");
        const { issuerJwks } = await import("@/lib/eudi/keys.server");
        return Response.json({ issuer: issuer(), jwks: await issuerJwks() }, { headers: { "cache-control": "public, max-age=3600", "access-control-allow-origin": "*" } });
      },
    },
  },
});
