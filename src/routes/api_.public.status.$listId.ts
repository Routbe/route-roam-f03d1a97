import { createFileRoute } from "@tanstack/react-router";

/** Token Status List of ROUT wallet credentials (application/statuslist+jwt, signed ES256). */
export const Route = createFileRoute("/api_/public/status/$listId")({
  server: {
    handlers: {
      GET: async ({ params }) => {
        const { STATUS_LIST_ID } = await import("@/lib/eudi/status-list");
        if (params.listId !== STATUS_LIST_ID) return new Response("Not found", { status: 404 });
        const { issuer } = await import("@/lib/oauth/provider.server");
        const { statusListToken } = await import("@/lib/eudi/status-list.server");
        const token = await statusListToken(issuer());
        if (!token) return new Response("Unavailable", { status: 503 });
        return new Response(token, {
          headers: { "content-type": "application/statuslist+jwt", "cache-control": "public, max-age=60", "access-control-allow-origin": "*" },
        });
      },
    },
  },
});
