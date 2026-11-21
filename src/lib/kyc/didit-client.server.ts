/**
 * Didit v3 REST client (server-only). DIDIT_API_KEY and DIDIT_WORKFLOW_ID are read per call and
 * never leave this module; responses are reduced to the fields the engine needs.
 */
import { Buffer } from "node:buffer";

const BASE = "https://verification.didit.me";
/** Upper bound for a Didit JSON response; a decision with image URLs stays far below it. */
const MAX_RESPONSE = 2 * 1024 * 1024;
const TIMEOUT_MS = 15_000;

export class DiditError extends Error {
  constructor(readonly code: "not_configured" | "provider_error" | "provider_unreachable", readonly status = 0) {
    super(code);
    this.name = "DiditError";
  }
}

function apiKey(): string {
  const k = process.env["DIDIT_API_KEY"];
  if (!k) throw new DiditError("not_configured");
  return k;
}

async function call(path: string, init: RequestInit): Promise<unknown> {
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, {
      ...init,
      headers: { "x-api-key": apiKey(), accept: "application/json", ...(init.body ? { "content-type": "application/json" } : {}) },
      signal: AbortSignal.timeout(TIMEOUT_MS),
      redirect: "error",
    });
  } catch (e) {
    if (e instanceof DiditError) throw e;
    throw new DiditError("provider_unreachable");
  }
  if (!res.ok) {
    // Status only: Didit error bodies can echo submitted data.
    console.error(`[kyc] Didit ${init.method ?? "GET"} ${path.split("/").slice(0, 3).join("/")} failed [${res.status}]`);
    await res.body?.cancel().catch(() => undefined);
    throw new DiditError("provider_error", res.status);
  }
  // Read into a Buffer (not res.json()), so the response bytes can be zero-filled after parsing.
  const declared = Number(res.headers.get("content-length") ?? "0");
  if (declared > MAX_RESPONSE) {
    await res.body?.cancel().catch(() => undefined);
    throw new DiditError("provider_error", res.status);
  }
  const bytes = Buffer.from(await res.arrayBuffer());
  try {
    if (bytes.length > MAX_RESPONSE) throw new DiditError("provider_error", res.status);
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } catch (e) {
    if (e instanceof DiditError) throw e;
    throw new DiditError("provider_error", res.status);
  } finally {
    bytes.fill(0);
  }
}

export async function createDiditSession(input: { vendorData: string; callback: string }): Promise<{ sessionId: string; sessionToken: string; url: string }> {
  const workflow = process.env["DIDIT_WORKFLOW_ID"];
  if (!workflow) throw new DiditError("not_configured");
  const body = (await call("/v3/session/", {
    method: "POST",
    body: JSON.stringify({ workflow_id: workflow, vendor_data: input.vendorData, callback: input.callback, callback_method: "both" }),
  })) as Record<string, unknown>;
  const sessionId = typeof body["session_id"] === "string" ? body["session_id"] : "";
  const sessionToken = typeof body["session_token"] === "string" ? body["session_token"] : "";
  const url = typeof body["url"] === "string" ? body["url"] : "";
  if (!sessionId || !sessionToken || !/^https:\/\/[a-z0-9.-]*didit\.me\//i.test(url)) throw new DiditError("provider_error");
  return { sessionId, sessionToken, url };
}

/** Full decision object; the caller reads it through readDiditDecision and drops the reference. */
export async function fetchDiditDecision(sessionId: string): Promise<unknown> {
  if (!/^[0-9a-f-]{36}$/i.test(sessionId)) throw new DiditError("provider_error");
  return call(`/v3/session/${encodeURIComponent(sessionId)}/decision/`, { method: "GET" });
}
