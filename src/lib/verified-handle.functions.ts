import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "@/lib/auth/middleware";

/** Vrije wettelijke handle-varianten na Didit (berekend uit de verzegelde naam, server-side). */
export const getVerifiedHandleOptions = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    const { listVerifiedHandleOptions } = await import("./verified-root-handle.server");
    return listVerifiedHandleOptions(context.userId);
  });

/** Claimt de gekozen handle; de server hervalideert tegen de Didit-naam en claimt atomair. */
export const claimVerifiedHandle = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d) =>
    z.object({ handle: z.string().min(3).max(40), copyLinks: z.boolean(), hideAlias: z.boolean() }).parse(d),
  )
  .handler(async ({ data, context }) => {
    const { claimVerifiedRootHandle } = await import("./verified-root-handle.server");
    return claimVerifiedRootHandle(context.userId, data.handle, { copyLinks: data.copyLinks, hideAlias: data.hideAlias });
  });
