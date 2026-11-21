import { createFileRoute } from "@tanstack/react-router";

/** GET /.well-known/mcp.json — MCP server discovery for AI assistants (public metadata only). */
export const Route = createFileRoute("/.well-known/mcp.json")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const { publicOrigin } = await import("@/lib/agent/agent-auth.server");
        const { mcpDiscovery } = await import("@/lib/agent/mcp-discovery");
        return new Response(JSON.stringify(mcpDiscovery(publicOrigin(request)), null, 2), {
          headers: { "content-type": "application/json; charset=utf-8", "cache-control": "public, max-age=3600", "access-control-allow-origin": "*" },
        });
      },
    },
  },
});
