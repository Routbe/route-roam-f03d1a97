import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "@/lib/auth/middleware";

/** Developer Console RPC for EUDI wallet issuance (OID4VCI) and verification (OID4VP). */

async function iss(): Promise<string> {
  const { issuer } = await import("@/lib/oauth/provider.server");
  return issuer();
}

export const createWalletOfferFn = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    const { createOffer } = await import("./oid4vci.server");
    const r = await createOffer(context.userId, await iss());
    return r.ok ? { ok: true as const, uri: r.uri, txCode: r.txCode, expiresAt: r.expiresAt } : r;
  });

export const listMyWalletCredentialsFn = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    const { listMyWalletCredentials } = await import("./oid4vci.server");
    return listMyWalletCredentials(context.userId);
  });

export const revokeWalletCredentialFn = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) => z.object({ statusIdx: z.number().int().min(0).max(131071) }).parse(d))
  .handler(async ({ data, context }) => {
    const { revokeMyWalletCredential } = await import("./oid4vci.server");
    return { ok: await revokeMyWalletCredential(context.userId, data.statusIdx) };
  });

export const createVpRequestFn = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) =>
    z.object({
      label: z.string().trim().min(1).max(80),
      claims: z.array(z.enum(["verified_human", "age_over_16", "age_over_18", "age_over_21"])).min(1).max(4),
    }).parse(d),
  )
  .handler(async ({ data, context }) => {
    const { createVpRequest } = await import("./oid4vp.server");
    return createVpRequest(context.userId, await iss(), data);
  });

export const readVpRequestFn = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) => z.object({ id: z.string().uuid() }).parse(d))
  .handler(async ({ data, context }) => {
    const { readMyVpRequest } = await import("./oid4vp.server");
    return readMyVpRequest(context.userId, data.id);
  });
