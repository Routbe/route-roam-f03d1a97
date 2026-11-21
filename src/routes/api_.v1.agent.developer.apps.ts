import { createFileRoute } from "@tanstack/react-router";

/**
 * GET / PUT /api/v1/agent/developer/apps — "Login with ROUT" app specifications for the agent's
 * sandbox workspace. Clients are only activated when a human claims the workspace.
 */
export const Route = createFileRoute("/api_/v1/agent/developer/apps")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const { readDeveloperApps } = await import("@/lib/agent/agent-v1.server");
        return readDeveloperApps(request);
      },
      PUT: async ({ request }) => {
        const { putDeveloperApps } = await import("@/lib/agent/agent-v1.server");
        return putDeveloperApps(request);
      },
    },
  },
});
