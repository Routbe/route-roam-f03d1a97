import { createFileRoute } from "@tanstack/react-router";

/** ROUT's hybrid Ed25519 + ML-DSA-65 verification keys, one pair per purpose (src/lib/crypto/pq-purposes.ts). */
export const Route = createFileRoute("/.well-known/rout-pq-keys.json")({
  server: {
    handlers: {
      GET: async () => {
        const { pqKeySet } = await import("@/lib/crypto/hybrid-signer.server");
        return Response.json(await pqKeySet(), {
          headers: { "cache-control": "public, max-age=3600", "access-control-allow-origin": "*" },
        });
      },
    },
  },
});
