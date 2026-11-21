import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { optionalAuth, requireAuth } from "@/lib/auth/middleware";

/** RPC for /support/donations and /support/partners. Webhooks live under /api/v1/payments. */

const startSchema = z.object({
  level: z.union([z.literal(1), z.literal(2), z.literal(3)]),
  rail: z.enum(["sepa", "stripe"]),
  amountCents: z.number().int().min(100).max(500_000),
  origin: z.string().url().max(300),
  altcha: z.string().max(4000).optional().nullable(),
});

export const getSupportOverview = createServerFn({ method: "GET" }).handler(async () => {
  const { readOverview } = await import("./support.server");
  return readOverview();
});

export const startSupportDonation = createServerFn({ method: "POST" })
  .middleware([optionalAuth])
  .inputValidator((input: unknown) => startSchema.parse(input))
  .handler(async ({ data, context }) => {
    const { assertHuman } = await import("@/lib/altcha.server");
    await assertHuman(data.altcha ?? null);
    const { hitRateLimit, clientIp } = await import("@/lib/rate-limit-db.server");
    const { getRequest } = await import("@tanstack/react-start/server");
    const { trustedCheckoutOrigin } = await import("@/lib/verification.server");
    const request = getRequest();
    const limit = await hitRateLimit("support-start", context.userId ?? clientIp(request), { limit: 10, windowSec: 3600 });
    if (!limit.ok) return { ok: false as const, reason: "rate_limited" as const };
    const { startSupport } = await import("./support.server");
    return startSupport({ level: data.level, rail: data.rail, amountCents: data.amountCents, signedIn: Boolean(context.userId), origin: trustedCheckoutOrigin(request, data.origin) });
  });

/** POST so the access token never lands in a URL or an access log. */
export const getSupportDonation = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) => z.object({ id: z.string().uuid(), token: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }).parse(input))
  .handler(async ({ data }) => {
    const { readDonation } = await import("./support.server");
    return readDonation(data.id, data.token);
  });

export const getMySupport = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async () => {
    const { readMyDonations } = await import("./support.server");
    return readMyDonations();
  });

export const getSupporterPresentation = createServerFn({ method: "GET" })
  .inputValidator((input: unknown) => z.object({ handle: z.string().trim().min(2).max(41) }).parse(input))
  .handler(async ({ data }) => {
    const { readSupporterPresentation } = await import("./support.server");
    const { supportPublicKey } = await import("./keys.server");
    return { presentation: await readSupporterPresentation(data.handle), publicKey: await supportPublicKey().catch(() => null) };
  });

export const getPartnerChecks = createServerFn({ method: "GET" }).handler(async () => {
  const { PARTNERS } = await import("./partners");
  const { dnssecStatus } = await import("./dnssec.server");
  const states = await Promise.all(PARTNERS.map(async (p) => [p.id, await dnssecStatus(p.domain)] as const));
  return Object.fromEntries(states) as Record<string, import("./dnssec.server").DnssecState>;
});
