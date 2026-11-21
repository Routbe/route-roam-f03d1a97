import { createFileRoute } from "@tanstack/react-router";

/**
 * POST /api/v1/agent/workspace/create — one-shot agent workspace provisioning.
 * The backend reads the compute proof (X-ROUT-Compute-Proof, sandbox scope), verifies and
 * spends it, binds an optional DPoP key and applies rate limits; this route only adapts HTTP.
 */
export const Route = createFileRoute("/api_/v1/agent/workspace/create")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { createAgentWorkspace } = await import("@/lib/agent/agent-v1.server");
        return createAgentWorkspace(request);
      },
    },
  },
});
