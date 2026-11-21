import { createFileRoute } from "@tanstack/react-router";

/**
 * POST /api/v1/kyc/didit/webhook — called by Didit only. The raw body is authenticated with
 * HMAC-SHA256 (DIDIT_WEBHOOK_SECRET, constant time) and a 300 s timestamp window before it is parsed;
 * anything else answers 401. See src/lib/kyc/kyc-engine.server.ts.
 */
export const Route = createFileRoute("/api_/v1/kyc/didit/webhook")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { handleDiditWebhook } = await import("@/lib/kyc/kyc-engine.server");
        return handleDiditWebhook(request);
      },
    },
  },
});
