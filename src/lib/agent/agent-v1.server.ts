import { agentError, agentOk, agentValidationError } from "./responses";
import { AGENT_V1, WORKSPACE_ID, agentWorkspaceCreateInput, isSlugCollision, readComputeProof } from "./agent-v1";
import type { SandboxContext } from "./agent-sandbox.server";

/**
 * Handlers behind /api/v1/agent/*. They add no storage of their own: every
 * write goes through agent-sandbox.server.ts and its rout_agent_sandbox_*
 * SECURITY DEFINER functions, so the v1 and the original sandbox routes share
 * one engine, one quota and one set of invariants.
 */

const MAX_SLUG_DRAWS = 5;

/**
 * POST /api/v1/agent/workspace/create — one request: proof-of-work (scope
 * sandbox) → sandbox key → unowned workspace /w/<base>-<xxxx> → optional first
 * Studio design and Login-with-ROUT app specs. Optional DPoP header binds the key.
 */
export async function createAgentWorkspace(request: Request): Promise<Response> {
  const { guardShared, clientIp } = await import("@/lib/rate-limit-db.server");
  // The same bucket as POST /api/agent/sandbox: two doors, one budget.
  const limited = await guardShared(request, "agent-sandbox-register", { limit: 5, windowSec: 3600 });
  if (limited) return limited;

  const rawBody: unknown = await request.json().catch(() => null);
  const parsed = agentWorkspaceCreateInput.safeParse(rawBody);
  if (!parsed.success) return agentValidationError(parsed.error, rawBody);
  const input = parsed.data;

  const { slugBaseFrom, suffixedWorkspaceSlug } = await import("@/lib/workspace-slug-suffix");
  const base = input.slug_base ?? slugBaseFrom(input.name) ?? "workspace";

  const proof = readComputeProof(request.headers, input);
  if (!proof.ok) {
    const how = "Fetch GET /api/v1/pow/challenge?scope=sandbox, solve it, and send X-ROUT-Compute-Proof: <challenge>:<solution> (or the X-ROUT-PoW-Challenge / X-ROUT-PoW-Solution pair, or challenge + solution in the body — exactly one of these).";
    const res = agentError(401, "challenge_required", proof.reason === "ambiguous" ? `The proof was sent twice. ${how}` : how);
    res.headers.set("www-authenticate", 'PoW realm="rout-agent", scope="sandbox", challenge_url="/api/v1/pow/challenge?scope=sandbox"');
    return res;
  }

  let jkt: string | undefined;
  if (request.headers.get("dpop")) {
    const { sandboxDpop, dpopFailure } = await import("./sandbox-dpop.server");
    const dpop = await sandboxDpop(request);
    if (!dpop.ok) return dpopFailure(dpop);
    jkt = dpop.jkt;
  }

  try {
    const { purgeUnclaimedAgentWorkspaces } = await import("./agent-workspaces.server");
    await purgeUnclaimedAgentWorkspaces();
  } catch (error) {
    console.error("[agent:v1] purge", (error as Error).message);
  }

  const sandbox = await import("./agent-sandbox.server");
  let reg: Awaited<ReturnType<typeof sandbox.registerSandbox>>;
  try {
    reg = await sandbox.registerSandbox({ ...proof.proof, agentName: input.agent_name, ip: clientIp(request), jkt });
  } catch (error) {
    const m = (error as Error).message ?? "";
    if (m.startsWith("challenge_")) return agentError(401, "challenge_required", `Proof-of-work rejected (${m.slice(10)}). Fetch a new challenge (scope=sandbox).`);
    if (m.includes("challenge_used")) return agentError(401, "challenge_required", "This challenge was already used. Fetch a new one.");
    if (m.includes("sandbox_quota_reached")) {
      const { SANDBOXES_PER_NETWORK_PER_DAY } = await import("./agent-protocol");
      return agentError(429, "rate_limited", `Sandbox limit for this network reached (${SANDBOXES_PER_NETWORK_PER_DAY} per 24 h).`);
    }
    console.error("[agent:v1] register failed");
    return agentError(500, "server_error", "The workspace could not be created right now.");
  }

  const credentials = {
    agent_workspace_token: reg.sandboxKey,
    token_type: reg.tokenType,
    ...(jkt ? { dpop_jkt: jkt } : {}),
    expires_at: reg.expiresAt,
  };
  let ctx: SandboxContext = { key: reg.sandboxKey, keyHash: reg.keyHash, sandboxId: reg.sandboxId, agentName: input.agent_name, workspaceId: null, slug: null, expiresAt: reg.expiresAt };

  let ws: Awaited<ReturnType<typeof sandbox.provisionSandboxWorkspace>> | null = null;
  for (let draw = 1; draw <= MAX_SLUG_DRAWS && !ws; draw++) {
    try {
      ws = await sandbox.provisionSandboxWorkspace(ctx, { name: input.name, slug: suffixedWorkspaceSlug(base), description: input.description });
    } catch (error) {
      if (isSlugCollision((error as Error).message ?? "") && draw < MAX_SLUG_DRAWS) continue;
      console.error("[agent:v1] provision failed");
      // The sandbox exists and is the agent's: hand the key back so it can retry without new work.
      return agentError(500, "server_error", "The sandbox was created but the workspace was not. Retry with POST /api/agent/sandbox/workspace using this key.", { credentials });
    }
  }
  if (!ws) return agentError(500, "server_error", "No free workspace address was found.", { credentials });
  ctx = { ...ctx, workspaceId: ws.workspaceId, slug: ws.slug };

  const warnings: string[] = [];
  let revision: number | null = null;
  if (input.profile) {
    try {
      const { splitProfilePatch } = await import("./agent-sandbox");
      const { fields, prefs } = splitProfilePatch(input.profile);
      revision = await sandbox.patchSandboxProfile(ctx, fields, prefs);
    } catch {
      warnings.push("profile_not_applied: PATCH it again via the studio endpoint.");
    }
  }
  let appCount = 0;
  if (input.apps?.length) {
    try {
      appCount = await sandbox.setSandboxApps(ctx, input.apps);
    } catch {
      warnings.push("apps_not_applied: PUT them again via the developer apps endpoint.");
    }
  }

  const { publicOrigin } = await import("./agent-auth.server");
  const { claimUrl } = await import("./agent-claims");
  const { SANDBOX_TTL_HOURS, AGENT_PROTOCOL_VERSION } = await import("./agent-protocol");
  const origin = publicOrigin(request);
  const url = claimUrl(origin, ws.claimToken);
  const svg = await sandbox.claimQrSvg(url);
  const auth = `Authorization: ${reg.tokenType} <agent_workspace_token>${jkt ? " + a fresh DPoP proof (ath = base64url(SHA-256(token)))" : ""}`;
  return agentOk(
    {
      protocol_version: AGENT_PROTOCOL_VERSION,
      workspace: {
        id: ws.workspaceId,
        slug: ws.slug,
        path: `/w/${ws.slug}`,
        url: `${origin}/w/${ws.slug}`,
        visibility: "private_until_claimed",
        expires_at: ws.expiresAt,
      },
      credentials: { ...credentials, note: "Shown once. Only SHA-256 of it is stored; it dies when a human claims the workspace." },
      claim: {
        url,
        code: ws.claimCode,
        qr_svg: `data:image/svg+xml;base64,${btoa(svg)}`,
        human_steps: [
          "Open the claim link, or:",
          "In ROUT: Profile → Personal → the gear icon next to “New workspace” → Claim workspace.",
          "Scan the QR code or type the claim code, then sign in and confirm.",
        ],
        note: `The claim code is the human's management key: single-use, expires with the sandbox (${SANDBOX_TTL_HOURS} h). Nothing is public until claimed and published by that human.`,
      },
      studio: { revision, applied: Boolean(input.profile) && revision !== null },
      apps: { specs: appCount, activation: "OAuth clients (client_id + client_secret) are issued to the human who claims, never to the agent." },
      next: {
        studio: { methods: ["GET", "PATCH"], url: `${origin}${AGENT_V1.studio(ws.workspaceId)}`, auth },
        apps: { methods: ["GET", "PUT"], url: `${origin}${AGENT_V1.apps}`, auth },
      },
      ...(warnings.length ? { warnings } : {}),
    },
    201,
  );
}

/** Sandbox key for the one workspace in the path; a foreign or unknown id answers the same 404. */
async function sandboxFor(request: Request, workspaceId: string | null): Promise<SandboxContext | Response> {
  const { authenticateSandbox } = await import("./agent-sandbox.server");
  const ctx = await authenticateSandbox(request);
  if (ctx instanceof Response) return ctx;
  if (!ctx.workspaceId) return agentError(404, "not_found", `This key has no workspace yet. Create one with POST ${AGENT_V1.create}.`);
  if (workspaceId !== null && (!WORKSPACE_ID.test(workspaceId) || workspaceId !== ctx.workspaceId)) {
    return agentError(404, "not_found", "No workspace with this id belongs to this key.");
  }
  return ctx;
}

/** GET /api/v1/agent/workspace/{id}/studio — the current design, revision and app specs. */
export async function readWorkspaceStudio(request: Request, workspaceId: string): Promise<Response> {
  const ctx = await sandboxFor(request, workspaceId);
  if (ctx instanceof Response) return ctx;
  const { readSandboxState } = await import("./agent-sandbox.server");
  const state = await readSandboxState(ctx);
  return agentOk({ workspace_id: ctx.workspaceId, slug: ctx.slug, path: `/w/${ctx.slug}`, visibility: "private_until_claimed", expires_at: ctx.expiresAt, draft: state?.draft ?? null, revision: state?.revision ?? null });
}

/** PATCH /api/v1/agent/workspace/{id}/studio — shallow-merge a Studio design patch. */
export async function patchWorkspaceStudio(request: Request, workspaceId: string): Promise<Response> {
  const ctx = await sandboxFor(request, workspaceId);
  if (ctx instanceof Response) return ctx;
  const { sandboxProfileInput, splitProfilePatch } = await import("./agent-sandbox");
  const rawBody: unknown = await request.json().catch(() => null);
  const parsed = sandboxProfileInput.safeParse(rawBody);
  if (!parsed.success) return agentValidationError(parsed.error, rawBody);
  try {
    const { patchSandboxProfile } = await import("./agent-sandbox.server");
    const { fields, prefs } = splitProfilePatch(parsed.data);
    return agentOk({ revision: await patchSandboxProfile(ctx, fields, prefs) });
  } catch (error) {
    if ((error as Error)?.message === "draft_conflict") {
      return agentError(409, "draft_conflict", "Another patch landed at the same time. GET the studio, re-apply your change and send patches one at a time.");
    }
    return agentError(400, "invalid_request", "The workspace is no longer editable (claimed or expired).");
  }
}

/** GET /api/v1/agent/developer/apps — the Login-with-ROUT app specs of this key's workspace. */
export async function readDeveloperApps(request: Request): Promise<Response> {
  const ctx = await sandboxFor(request, null);
  if (ctx instanceof Response) return ctx;
  const { readSandboxState } = await import("./agent-sandbox.server");
  const state = await readSandboxState(ctx);
  return agentOk({ workspace_id: ctx.workspaceId, apps: state?.apps ?? [], activation: "at_claim" });
}

/** PUT /api/v1/agent/developer/apps — replace the app specs (max 3). */
export async function putDeveloperApps(request: Request): Promise<Response> {
  const ctx = await sandboxFor(request, null);
  if (ctx instanceof Response) return ctx;
  const { sandboxAppsInput } = await import("./agent-sandbox");
  const rawBody: unknown = await request.json().catch(() => null);
  const parsed = sandboxAppsInput.safeParse(rawBody);
  if (!parsed.success) return agentValidationError(parsed.error, rawBody);
  try {
    const { setSandboxApps } = await import("./agent-sandbox.server");
    const n = await setSandboxApps(ctx, parsed.data.apps);
    return agentOk({
      apps: n,
      activation: "at_claim",
      note: "Each spec becomes a real OAuth client owned by the human who claims the workspace; client_secret is shown once to that human and stored only as a hash. An anonymous agent never holds a live client, so nobody can phish under ROUT's name with an unowned app.",
    });
  } catch {
    return agentError(400, "invalid_request", "The workspace is no longer editable (claimed or expired).");
  }
}
