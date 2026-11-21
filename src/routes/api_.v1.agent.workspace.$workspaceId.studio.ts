import { createFileRoute } from "@tanstack/react-router";

/**
 * GET / PATCH /api/v1/agent/workspace/:workspaceId/studio — the agent's own sandbox workspace
 * Studio draft. Sandbox key (Bearer or DPoP) and workspace ownership are checked in the backend;
 * a foreign or unknown id answers the same 404.
 */
export const Route = createFileRoute("/api_/v1/agent/workspace/$workspaceId/studio")({
  server: {
    handlers: {
      GET: async ({ request, params }) => {
        const { readWorkspaceStudio } = await import("@/lib/agent/agent-v1.server");
        return readWorkspaceStudio(request, params.workspaceId);
      },
      PATCH: async ({ request, params }) => {
        const { patchWorkspaceStudio } = await import("@/lib/agent/agent-v1.server");
        return patchWorkspaceStudio(request, params.workspaceId);
      },
    },
  },
});
