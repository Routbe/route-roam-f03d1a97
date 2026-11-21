import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth, requireSudo } from "@/lib/auth/middleware";

const uuid = z.string().uuid();
const b64u = (min: number, max: number) => z.string().min(min).max(max).regex(/^[A-Za-z0-9_-]+$/);

/** Owner/admin only: key epochs, the caller's own sealed workspace keys and sealed questions. */
export const getWsInbox = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) => z.object({ workspaceId: uuid, slug: z.string().min(1).max(40) }).parse(d))
  .handler(async ({ data, context }) => {
    const { readWsInbox } = await import("./workspace-inbox.server");
    return readWsInbox(context.userId, data.workspaceId, data.slug.toLowerCase());
  });

/** Publishes the next key epoch and stores the caller's own envelope, atomically. */
export const initWsInboxKey = createServerFn({ method: "POST" })
  .middleware([requireAuth, requireSudo("workspace_key_rotate")])
  .inputValidator((d: unknown) =>
    z.object({
      workspaceId: uuid,
      epoch: z.number().int().min(1).max(1_000_000),
      publicKey: b64u(2134, 2134),
      kid: b64u(22, 22),
      memberRef: uuid,
      envelope: b64u(16, 24063),
    }).parse(d),
  )
  .handler(async ({ data, context }) => {
    const { initWsKey } = await import("./workspace-inbox.server");
    return { result: await initWsKey({ ...data, userId: context.userId }) };
  });

export const setWsAskEnabled = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) => z.object({ workspaceId: uuid, enabled: z.boolean() }).parse(d))
  .handler(async ({ data }) => {
    const { saveWsAsk } = await import("./workspace-inbox.server");
    return { result: await saveWsAsk(data.workspaceId, data.enabled) };
  });

/** A private answer, sealed in the manager's browser to the visitor's reply key. */
export const replyWsInboxQuestion = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) => z.object({ questionId: uuid, envelope: b64u(16, 24063), hash: b64u(43, 43) }).parse(d))
  .handler(async ({ data }) => {
    const { replyWsQuestion } = await import("./workspace-inbox.server");
    return { result: await replyWsQuestion(data.questionId, data.envelope, data.hash) };
  });

/** A deliberate public release: the manager's own (possibly rewritten) question and answer. */
export const publishWsInboxQuestion = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) =>
    z.object({ questionId: uuid, question: z.string().trim().min(1).max(2000), answer: z.string().trim().min(1).max(4000) }).parse(d),
  )
  .handler(async ({ data }) => {
    const { publishWsQuestion } = await import("./workspace-inbox.server");
    return { result: await publishWsQuestion(data.questionId, data.question, data.answer) };
  });

export const declineWsInboxQuestion = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) => z.object({ questionId: uuid }).parse(d))
  .handler(async ({ data }) => {
    const { declineWsQuestion } = await import("./workspace-inbox.server");
    return { result: await declineWsQuestion(data.questionId) };
  });
