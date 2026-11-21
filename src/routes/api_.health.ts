import { createFileRoute } from "@tanstack/react-router";

/** Short alias of /api/public/health, so /api/health never falls through to the profile/short-link page. */
export const Route = createFileRoute("/api_/health")({
  server: {
    handlers: {
      GET: async () => {
        const started = Date.now();
        let status: "operational" | "degraded" = "operational";
        try {
          const { sql } = await import("@/lib/neon");
          await sql`SELECT 1`;
        } catch {
          status = "degraded";
        }
        const { CODE_SCHEMA_LEVEL } = await import("@/lib/schema-version");
        return Response.json(
          { status, latency_ms: Date.now() - started, schema: CODE_SCHEMA_LEVEL },
          { headers: { "cache-control": "no-store" } },
        );
      },
    },
  },
});
