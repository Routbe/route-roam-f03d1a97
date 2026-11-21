import { createFileRoute } from "@tanstack/react-router";

/**
 * POST /api/v1/payments/bunq-webhook — bunq NotificationFilterUrl (category PAYMENT) on the
 * treasury account. The raw body must carry a valid X-Bunq-Server-Signature under
 * BUNQ_SERVER_PUBLIC_KEY; only incoming EUR credits whose description holds a valid Belgian
 * structured communication of an open donation are confirmed. Payer name and IBAN are ignored.
 */
export const Route = createFileRoute("/api_/v1/payments/bunq-webhook")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const key = process.env["BUNQ_SERVER_PUBLIC_KEY"] ?? "";
        if (!key) return new Response("Webhook not configured", { status: 503 });
        const body = await request.text();
        if (body.length > 256 * 1024) return new Response("Too large", { status: 413 });
        const { verifyBunqSignature, parseBunqPayment } = await import("@/lib/support/bunq-notification");
        if (!verifyBunqSignature(body, request.headers.get("x-bunq-server-signature"), key)) return new Response("Invalid signature", { status: 401 });
        let json: unknown;
        try {
          json = JSON.parse(body);
        } catch {
          return new Response("Malformed payload", { status: 400 });
        }
        const payment = parseBunqPayment(json);
        if (!payment || !payment.ogm) return new Response("ignored", { status: 200 });
        const { confirmByOgm } = await import("@/lib/support/support.server");
        try {
          const outcome = await confirmByOgm(payment.ogm, payment.paymentId, payment.amountCents);
          if (outcome === "not_configured" || outcome === "failed") return new Response("Retry later", { status: 503 });
          return new Response(outcome, { status: 200 });
        } catch {
          return new Response("Retry later", { status: 503 });
        }
      },
    },
  },
});
