import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "@/lib/auth/middleware";
import { QA_LEVELS } from "./minor-safety";

/** Public by design: the emailed token is the parent's credential (no ROUT account needed). */
const token = z.string().regex(/^[A-Za-z0-9_-]{40,64}$/);

export const getParentView = createServerFn({ method: "GET" })
  .inputValidator((i: unknown) => z.object({ token }).parse(i))
  .handler(async ({ data }) => {
    const s = await import("./minor-safety.server");
    return { view: await s.parentView(data.token) };
  });

export const approveParentConsent = createServerFn({ method: "POST" })
  .inputValidator((i: unknown) => z.object({ token }).parse(i))
  .handler(async ({ data }) => {
    const s = await import("./minor-safety.server");
    return { ok: await s.approveConsent(data.token) };
  });

export const setParentQaLevel = createServerFn({ method: "POST" })
  .inputValidator((i: unknown) => z.object({ token, level: z.enum(QA_LEVELS) }).parse(i))
  .handler(async ({ data }) => {
    const s = await import("./minor-safety.server");
    return { ok: await s.setQaLevel(data.token, data.level) };
  });

export const startParentPayment = createServerFn({ method: "POST" })
  .inputValidator((i: unknown) => z.object({ token, origin: z.string().url().max(300) }).parse(i))
  .handler(async ({ data }) => {
    const { getRequest } = await import("@tanstack/react-start/server");
    const { trustedCheckoutOrigin } = await import("./verification.server");
    const s = await import("./minor-safety.server");
    return s.startParentCheckout(data.token, trustedCheckoutOrigin(getRequest(), data.origin));
  });

/** Whether the signed-in member is under 16 (paid actions go to the parent). */
export const getMyMinorStatus = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    const s = await import("./minor-safety.server");
    return { minor: await s.isMinorUser(context.userId) };
  });

/** Whether the signed-in member still has to fill in the age sheet (db/0291). */
export const getMyAgeStatus = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    const s = await import("./minor-safety.server");
    return { needsAge: await s.myAgeFloorMissing(context.userId) };
  });

/**
 * The age sheet: the date of birth is turned into a whole-year floor inside this handler and then
 * dropped; it is never logged, returned or stored (owner rule 2026-11-17, db/0291).
 */
export const submitMyAge = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((i: unknown) =>
    z.object({ dob: z.string().length(10), parentEmail: z.string().max(254).optional() }).parse(i))
  .handler(async ({ data, context }) => {
    const { ageFloorFromBirthDate } = await import("@/lib/age/age-floor");
    const floor = ageFloorFromBirthDate(data.dob);
    (data as { dob?: string }).dob = undefined;
    const s = await import("./minor-safety.server");
    return { outcome: await s.recordMyAge(context.userId, context.user.email ?? "", floor, data.parentEmail ?? null) };
  });
