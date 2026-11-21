import { createFileRoute } from "@tanstack/react-router";

/**
 * POST /api/v1/payments/stripe-webhook — Stripe events for ROUT support donations only.
 * Signature: STRIPE_SUPPORT_WEBHOOK_SECRET (falls back to STRIPE_WEBHOOK_SECRET). The general
 * /api/public/stripe-webhook forwards rout_support events to the same handler, so one Stripe
 * endpoint is enough. No tracking scripts: Checkout runs entirely on Stripe's page.
 */
export const Route = createFileRoute("/api_/v1/payments/stripe-webhook")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const secret = process.env["STRIPE_SUPPORT_WEBHOOK_SECRET"] || process.env["STRIPE_WEBHOOK_SECRET"];
        if (!secret) return new Response("Webhook not configured", { status: 503 });
        const body = await request.text();
        if (body.length > 256 * 1024) return new Response("Too large", { status: 413 });
        const { verifyStripeSignature } = await import("@/lib/webhook-replay");
        if (!verifyStripeSignature(body, request.headers.get("stripe-signature") ?? "", secret)) return new Response("Invalid signature", { status: 401 });
        let event: { type?: string; data?: { object?: Record<string, unknown> } };
        try {
          event = JSON.parse(body);
        } catch {
          return new Response("Malformed payload", { status: 400 });
        }
        const { applySupportStripeEvent } = await import("@/lib/support/support.server");
        try {
          return new Response((await applySupportStripeEvent(event)) ?? "ignored", { status: 200 });
        } catch {
          // 5xx: Stripe retries; confirming is idempotent per donation.
          return new Response("Retry later", { status: 503 });
        }
      },
    },
  },
});
