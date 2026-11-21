import { createFileRoute } from "@tanstack/react-router";

/**
 * Legacy Didit webhook URL, kept so destinations registered before 2026-11-17 keep working.
 * Same handler as /api/v1/kyc/didit/webhook: HMAC-SHA256 of the raw body (constant time) and a
 * 300 s timestamp window before anything is parsed; the identity data is re-fetched from Didit.
 */
export const Route = createFileRoute("/api_/public/identity/didit-webhook")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { handleDiditWebhook } = await import("@/lib/kyc/kyc-engine.server");
        return handleDiditWebhook(request);
      },
    },
  },
});
