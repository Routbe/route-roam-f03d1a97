/**
 * Workspace manager inbox (db/0285). Owners and admins read the anonymous questions of their
 * workspace and answer them. Everything here moves ciphertext, public keys or texts a manager
 * deliberately publishes; the owner/admin check runs inside each database definer, from the
 * session's member id (rout.current_user_id), never from a parameter.
 */
import { runBatch, runQuery } from "@/lib/neon";
import { b64uDecode } from "@/lib/booking-engine/sealed-booking";
import { bytesToHex } from "@/lib/booking-engine/sealed-schema.server";
import { ASK_KEY, ASK_SAVE, DECLINE, KEY_INIT, MEMBER_KEY, PUBLISH, QUESTIONS, REPLY, ROLE, STATE } from "./workspace-inbox-sql";

type Row = Record<string, unknown>;
export type WsInboxEpoch = { epoch: number; status: "active" | "retired"; kid: string; heldBy: number; missing: { userId: string; role: string }[] };
export type WsInboxQuestion = {
  id: string; epoch: number; payloadId: string; status: string; createdAt: string;
  answeredAt: string | null; envelope: string; guestPublicKey: string; hasReply: boolean;
};
export type WsOwnKey = { epoch: number; envelope: string; memberRef: string };
export type WsInbox =
  | { ok: true; userId: string; enabled: boolean; epochs: WsInboxEpoch[]; ownKeys: WsOwnKey[]; questions: WsInboxQuestion[] }
  | { ok: false; reason: "forbidden" | "unavailable" };
export type WsInboxResult = "ok" | "forbidden" | "invalid" | "epoch" | "declined" | "failed" | "unavailable";

const RESULTS = new Set<WsInboxResult>(["ok", "forbidden", "invalid", "epoch", "declined"]);
const asResult = (r: unknown): WsInboxResult => {
  const v = typeof r === "string" ? r : (r as { ok?: boolean; reason?: string } | null)?.ok ? "ok" : (r as { reason?: string } | null)?.reason;
  return v && RESULTS.has(v as WsInboxResult) ? (v as WsInboxResult) : "failed";
};
const iso = (v: unknown): string | null => (v == null ? null : v instanceof Date ? v.toISOString() : String(v));

/**
 * The inbox for one workspace: key epochs, the caller's own sealed workspace keys and the
 * sealed questions. `forbidden` for anyone who is not owner or admin there.
 */
export async function readWsInbox(userId: string, workspaceId: string, slug: string): Promise<WsInbox> {
  try {
    const [role, state, questions, ask] = await runBatch([
      { query: ROLE, params: [workspaceId] },
      { query: STATE, params: [workspaceId] },
      { query: QUESTIONS, params: [workspaceId] },
      { query: ASK_KEY, params: [slug] },
    ]);
    const myRole = String(role?.rows[0]?.["r"] ?? "");
    if (myRole !== "owner" && myRole !== "admin") return { ok: false, reason: "forbidden" };
    const askKey = ask?.rows[0]?.["r"] as { workspaceId?: string } | null | undefined;
    const epochs = ((state?.rows[0]?.["r"] as { epochs?: Row[] } | undefined)?.epochs ?? []).map((e) => ({
      epoch: Number(e["epoch"]),
      status: e["status"] === "active" ? "active" as const : "retired" as const,
      kid: String(e["kid"] ?? ""),
      heldBy: Number(e["heldBy"] ?? 0),
      missing: Array.isArray(e["missing"]) ? (e["missing"] as { userId: string; role: string }[]) : [],
    }));
    const keyRows = epochs.length
      ? await runBatch(epochs.map((e) => ({ query: MEMBER_KEY, params: [workspaceId, e.epoch] })))
      : [];
    const ownKeys: WsOwnKey[] = [];
    keyRows.forEach((res, i) => {
      const r = res.rows[0]?.["r"] as { ok?: boolean; envelope?: string; memberRef?: string } | undefined;
      if (r?.ok && r.envelope && r.memberRef) ownKeys.push({ epoch: epochs[i]!.epoch, envelope: r.envelope, memberRef: r.memberRef });
    });
    return {
      ok: true,
      userId,
      enabled: askKey?.workspaceId === workspaceId,
      epochs,
      ownKeys,
      questions: (questions?.rows ?? []).map((q) => ({
        id: String(q["id"]),
        epoch: Number(q["epoch"]),
        payloadId: String(q["payload_id"]),
        status: String(q["status"]),
        createdAt: iso(q["created_at"]) ?? "",
        answeredAt: iso(q["answered_at"]),
        envelope: String(q["envelope"] ?? ""),
        guestPublicKey: String(q["guest_public_key"] ?? ""),
        hasReply: q["has_reply"] === true,
      })),
    };
  } catch (error) {
    console.warn("[ws-inbox] unavailable", error instanceof Error ? error.message : "error");
    return { ok: false, reason: "unavailable" };
  }
}

/** First key (or a rotation): next epoch, published and held by the caller in one transaction. */
export async function initWsKey(input: {
  userId: string; workspaceId: string; epoch: number; publicKey: string; kid: string; memberRef: string; envelope: string;
}): Promise<WsInboxResult> {
  try {
    const [pub, store] = await runBatch([
      { query: KEY_INIT[0]!, params: [input.workspaceId, input.epoch, input.publicKey, input.kid] },
      { query: KEY_INIT[1]!, params: [input.workspaceId, input.epoch, input.userId, input.memberRef, input.kid, input.envelope] },
      { query: KEY_INIT[2]!, params: [input.workspaceId, input.epoch] },
    ]);
    const a = asResult(pub?.rows[0]?.["r"]);
    return a === "ok" ? asResult(store?.rows[0]?.["r"]) : a;
  } catch {
    // The held-check aborted the batch: nothing was published.
    return "failed";
  }
}

export async function saveWsAsk(workspaceId: string, enabled: boolean): Promise<WsInboxResult> {
  try {
    return asResult((await runQuery(ASK_SAVE, [workspaceId, enabled])).rows[0]?.["r"]);
  } catch {
    return "unavailable";
  }
}

export async function replyWsQuestion(questionId: string, envelope: string, hashB64u: string): Promise<WsInboxResult> {
  const hash = b64uDecode(hashB64u);
  if (!hash || hash.length !== 32 || !b64uDecode(envelope)) return "invalid";
  try {
    return asResult((await runQuery(REPLY, [questionId, envelope, bytesToHex(hash)])).rows[0]?.["r"]);
  } catch {
    return "unavailable";
  } finally {
    hash.fill(0);
  }
}

export async function publishWsQuestion(questionId: string, question: string, answer: string): Promise<WsInboxResult> {
  try {
    return asResult((await runQuery(PUBLISH, [questionId, question, answer])).rows[0]?.["r"]);
  } catch {
    return "unavailable";
  }
}

export async function declineWsQuestion(questionId: string): Promise<WsInboxResult> {
  try {
    return asResult((await runQuery(DECLINE, [questionId])).rows[0]?.["r"]);
  } catch {
    return "unavailable";
  }
}
