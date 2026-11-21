// @vitest-environment node
import { describe, expect, it, vi } from "vitest";
import { solvePow } from "@/lib/pow/pow";

/**
 * Autonomous agent v1 flow: proof-of-work → workspace/create → studio PATCH → developer/apps PUT.
 * Part 1 always runs: each HTTP route hands the request to the right agent-v1 handler.
 * Part 2 runs the real flow against a running ROUT instance with its own database:
 *   ROUT_E2E_ORIGIN=https://staging.example bun run test src/test/autonomous-agent-e2e.test.ts
 */

const calls: string[] = [];
vi.mock("@/lib/agent/agent-v1.server", () => {
  const reply = (name: string) => async (_req: Request, id?: string) => {
    calls.push(id ? `${name}:${id}` : name);
    return Response.json({ handler: name });
  };
  return {
    createAgentWorkspace: reply("create"),
    readWorkspaceStudio: reply("readStudio"),
    patchWorkspaceStudio: reply("patchStudio"),
    readDeveloperApps: reply("readApps"),
    putDeveloperApps: reply("putApps"),
  };
});

type Handler = (ctx: { request: Request; params: Record<string, string> }) => Promise<Response>;
const handlersOf = (route: unknown) => (route as { options: { server: { handlers: Record<string, Handler> } } }).options.server.handlers;
const WS = "12345678-1234-1234-1234-123456789012";

describe("agent v1 routes", () => {
  it("wire every method to its backend handler", async () => {
    const create = handlersOf((await import("@/routes/api_.v1.agent.workspace.create")).Route);
    const studio = handlersOf((await import("@/routes/api_.v1.agent.workspace.$workspaceId.studio")).Route);
    const apps = handlersOf((await import("@/routes/api_.v1.agent.developer.apps")).Route);
    const req = new Request("https://rout.be/x", { method: "POST" });
    await create["POST"]!({ request: req, params: {} });
    await studio["GET"]!({ request: req, params: { workspaceId: WS } });
    await studio["PATCH"]!({ request: req, params: { workspaceId: WS } });
    await apps["GET"]!({ request: req, params: {} });
    await apps["PUT"]!({ request: req, params: {} });
    expect(calls).toEqual(["create", `readStudio:${WS}`, `patchStudio:${WS}`, "readApps", "putApps"]);
  });
  it("expose only the documented methods", async () => {
    expect(Object.keys(handlersOf((await import("@/routes/api_.v1.agent.workspace.create")).Route))).toEqual(["POST"]);
    expect(Object.keys(handlersOf((await import("@/routes/api_.v1.agent.workspace.$workspaceId.studio")).Route)).sort()).toEqual(["GET", "PATCH"]);
    expect(Object.keys(handlersOf((await import("@/routes/api_.v1.agent.developer.apps")).Route)).sort()).toEqual(["GET", "PUT"]);
  });
});

const origin = process.env["ROUT_E2E_ORIGIN"];

describe.skipIf(!origin)("autonomous agent flow against a live instance", () => {
  it("solves the proof, creates a workspace, designs Studio and configures an OIDC app", async () => {
    const pow = (await (await fetch(`${origin}/api/v1/pow/challenge?scope=sandbox`)).json()) as { challenge: string };
    const solution = await solvePow(pow.challenge);

    const createdRes = await fetch(`${origin}/api/v1/agent/workspace/create`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-rout-compute-proof": `${pow.challenge}:${solution}` },
      body: JSON.stringify({ agent_name: "Vitest e2e", name: "Agent e2e workspace" }),
    });
    expect(createdRes.status).toBe(201);
    const created = (await createdRes.json()) as {
      credentials: { token_type: string; agent_workspace_token: string };
      workspace: { id: string; slug: string };
    };
    expect(created.workspace.slug).toMatch(/-[0-9a-hjkmnp-tv-z]{4}$/);
    const authorization = `${created.credentials.token_type} ${created.credentials.agent_workspace_token}`;

    const studioUrl = `${origin}/api/v1/agent/workspace/${created.workspace.id}/studio`;
    const patched = await fetch(studioUrl, {
      method: "PATCH",
      headers: { authorization, "content-type": "application/json" },
      body: JSON.stringify({ displayName: "E2E Studio", tagline: "Prepared by an agent" }),
    });
    expect(patched.status).toBe(200);

    const appsUrl = `${origin}/api/v1/agent/developer/apps`;
    const put = await fetch(appsUrl, {
      method: "PUT",
      headers: { authorization, "content-type": "application/json" },
      body: JSON.stringify({ apps: [{ name: "E2E OIDC app", redirect_uris: ["https://example.test/callback"], scopes: ["openid", "profile"] }] }),
    });
    expect(put.status).toBe(200);

    const studio = (await (await fetch(studioUrl, { headers: { authorization } })).json()) as { draft?: { displayName?: string } };
    expect(studio.draft?.displayName).toBe("E2E Studio");
    const apps = (await (await fetch(appsUrl, { headers: { authorization } })).json()) as { apps?: { name: string }[] };
    expect(apps.apps?.map((a) => a.name)).toEqual(["E2E OIDC app"]);

    const foreign = await fetch(`${origin}/api/v1/agent/workspace/${WS}/studio`, { headers: { authorization } });
    expect(foreign.status).toBe(404);
  }, 120_000);
});
