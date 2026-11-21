import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";

/**
 * POST /api/v1/support/checkout — start a support donation (same origin only).
 * Body: { level: 1|2|3, rail: "sepa"|"stripe", amountCents, altcha }. Level 1 needs a session.
 * SEPA answers the structured communication + EPC payload; Stripe answers the Checkout URL.
 * The access token in the answer is the only key to the donation's status page.
 */
const body = z.object({
  level: z.union([z.literal(1), z.literal(2), z.literal(3)]),
  rail: z.enum(["sepa", "stripe"]),
  amountCents: z.number().int().min(100).max(500_000),
  altcha: z.string().max(4000).optional().nullable(),
});

export const Route = createFileRoute("/api_/v1/support/checkout")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const noStore = { "cache-control": "no-store" };
        const self = new URL(request.url).origin;
        const origin = request.headers.get("origin");
        if (origin && origin !== self) return Response.json({ error: "forbidden" }, { status: 403, headers: noStore });
        const { guardRequest } = await import("@/lib/api-guard.server");
        const limited = guardRequest(request, "support-checkout", 10, 60_000);
        if (limited) return limited;
        const parsed = body.safeParse(await request.json().catch(() => null));
        if (!parsed.success) return Response.json({ error: "invalid_input" }, { status: 400, headers: noStore });
        const { verifyAltcha } = await import("@/lib/altcha.server");
        if (!(await verifyAltcha(parsed.data.altcha ?? null)).ok) return Response.json({ error: "bot_check" }, { status: 400, headers: noStore });

        const { currentUser } = await import("@/lib/auth/session.server");
        const user = await currentUser().catch(() => null);
        const { startSupport } = await import("@/lib/support/support.server");
        const run = () => startSupport({ ...parsed.data, signedIn: Boolean(user), origin: origin ?? self });
        const { withDbContext } = await import("@/lib/neon");
        const result = user ? await withDbContext({ userId: user.id, workspaceId: null }, run) : await run();
        if (!result.ok) {
          const status = result.reason === "sign_in_required" ? 401 : result.reason === "invalid_amount" ? 400 : 503;
          return Response.json({ error: result.reason }, { status, headers: noStore });
        }
        return Response.json(result, { headers: noStore });
      },
    },
  },
});
