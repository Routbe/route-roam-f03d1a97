import { z } from "zod";
import { AGENT_SCOPE_DESCRIPTIONS, AGENT_TOKEN_TTL_MAX_S } from "./agent-scopes";
import { AGENT_V1, agentWorkspaceCreateInput } from "./agent-v1";
import { sandboxAppsInput, sandboxProfileInput } from "./agent-sandbox";
import { SANDBOX_TTL_HOURS } from "./agent-protocol";

/** Request schema as JSON Schema, straight from the Zod validator the handler uses. */
function inputSchema(schema: z.ZodType) {
  const { $schema: _ignored, ...rest } = z.toJSONSchema(schema, { io: "input", unrepresentable: "any" }) as Record<string, unknown>;
  return rest;
}

/** Machine-readable description of the agent API (OpenAPI 3.1). Pure. */
export function agentOpenApi(origin: string) {
  const errorRef = { $ref: "#/components/schemas/Error" };
  const json = (schema: unknown) => ({ "application/json": { schema } });
  return {
    openapi: "3.1.0",
    info: {
      title: "ROUT Agent API",
      version: "1.0.0",
      description:
        `ROUT is the Sovereign Digital Identity OS. Agents act for a member who approved them via OAuth 2.1 + PKCE at ${origin}/connect. ` +
        `Access tokens carrying agent scopes live at most ${AGENT_TOKEN_TTL_MAX_S / 60} minutes. Steps only a human may take answer HTTP 202 ` +
        "with status `human_action_required` and a temporary `action_url`; plan limits answer HTTP 402 with `upgrade_url`.",
    },
    servers: [{ url: origin }],
    components: {
      securitySchemes: {
        rout_sandbox: {
          type: "http",
          scheme: "bearer",
          description: `Sandbox key (rsk_…) returned once by ${AGENT_V1.create}. Send "Authorization: Bearer rsk_…", or "Authorization: DPoP rsk_…" plus a fresh DPoP proof when the key was bound at creation. Keys and workspaces expire after ${SANDBOX_TTL_HOURS} hours unless a human claims them.`,
        },
        rout_oauth: {
          type: "oauth2",
          flows: {
            authorizationCode: {
              authorizationUrl: `${origin}/connect`,
              tokenUrl: `${origin}/api/public/oauth/token`,
              refreshUrl: `${origin}/api/public/oauth/token`,
              scopes: { openid: "Identify the member", ...AGENT_SCOPE_DESCRIPTIONS },
            },
          },
        },
      },
      schemas: {
        AgentWorkspaceCreate: inputSchema(agentWorkspaceCreateInput),
        AgentStudioPatch: inputSchema(sandboxProfileInput),
        AgentApps: inputSchema(sandboxAppsInput),
        Error: { type: "object", properties: { status: { const: "error" }, error: { type: "string" }, message: { type: "string" } } },
        HumanActionRequired: {
          type: "object",
          properties: {
            status: { const: "human_action_required" },
            action: { enum: ["publish_profile", "verify_identity", "verify_domain", "sign_in"] },
            reason: { type: "string" },
            action_url: { type: "string", format: "uri" },
            expires_at: { type: "string", format: "date-time" },
            result: { type: "object" },
          },
        },
        PaymentRequired: {
          type: "object",
          properties: { status: { const: "payment_required" }, reason: { type: "string" }, upgrade_url: { type: "string", format: "uri" }, limit: { type: "string" } },
        },
      },
    },
    paths: {
      "/api/v1/pow/challenge": {
        get: {
          summary: "Single-use proof-of-work challenge (use scope=sandbox before workspace/create)",
          parameters: [{ name: "scope", in: "query", required: true, schema: { enum: ["sandbox", "workspace", "vault"] } }],
          responses: { "200": { description: "challenge, difficulty_bits (20), expires_at; solve sha256(challenge + ':' + solution)" }, "429": { content: json(errorRef) } },
        },
      },
      [AGENT_V1.create]: {
        post: {
          summary: "Create an unowned workspace in one request (no account); a human claims it within 24 hours",
          parameters: [
            { name: "X-ROUT-Compute-Proof", in: "header", required: false, schema: { type: "string" }, description: "<challenge>:<solution> for a scope=sandbox challenge; or send challenge + solution in the body." },
            { name: "DPoP", in: "header", required: false, schema: { type: "string" }, description: "Optional RFC 9449 proof (ES256 or Ed25519, no ath); binds the returned key to this key pair." },
          ],
          requestBody: { required: true, content: json({ $ref: "#/components/schemas/AgentWorkspaceCreate" }) },
          responses: {
            "201": { description: "credentials (agent_workspace_token, token_type Bearer|DPoP), workspace slug /w/<base>-<xxxx>, claim code, claim link and QR" },
            "400": { content: json(errorRef) },
            "401": { description: "Missing, invalid or replayed proof", content: json(errorRef) },
            "429": { content: json(errorRef) },
          },
        },
      },
      [AGENT_V1.studioTemplate]: {
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
        get: {
          summary: "Read the workspace Studio draft and its revision",
          security: [{ rout_sandbox: [] }],
          responses: { "200": { description: "draft, revision" }, "401": { content: json(errorRef) }, "404": { content: json(errorRef) } },
        },
        patch: {
          summary: "Change the Studio draft (link-in-bio blocks, theme, card style, texts)",
          security: [{ rout_sandbox: [] }],
          requestBody: { required: true, content: json({ $ref: "#/components/schemas/AgentStudioPatch" }) },
          responses: { "200": { description: "Updated draft" }, "400": { content: json(errorRef) }, "404": { content: json(errorRef) }, "409": { description: "Concurrent update; read and retry", content: json(errorRef) } },
        },
      },
      [AGENT_V1.apps]: {
        get: {
          summary: "List the Login-with-ROUT app specifications of the sandbox workspace",
          security: [{ rout_sandbox: [] }],
          responses: { "200": { description: "apps" }, "401": { content: json(errorRef) }, "404": { content: json(errorRef) } },
        },
        put: {
          summary: "Replace the OIDC app specifications; they become real OAuth clients when a human claims the workspace",
          security: [{ rout_sandbox: [] }],
          requestBody: { required: true, content: json({ $ref: "#/components/schemas/AgentApps" }) },
          responses: { "200": { description: "apps, activation: at_claim" }, "400": { content: json(errorRef) }, "404": { content: json(errorRef) } },
        },
      },
      "/api/agent/identity": {
        get: {
          summary: "Public verification status of the member",
          security: [{ rout_oauth: ["identity:read_public"] }],
          responses: { "200": { description: "Verified human yes/no and public handles" }, "401": { content: json(errorRef) }, "403": { content: json(errorRef) } },
        },
      },
      "/api/agent/links": {
        post: {
          summary: "Create a QR code / short link",
          security: [{ rout_oauth: ["assets:write"] }],
          requestBody: {
            content: json({ type: "object", required: ["target_url"], properties: { target_url: { type: "string", format: "uri" }, label: { type: "string" }, kind: { enum: ["qr", "link"] } } }),
          },
          responses: {
            "201": { description: "Created; returns short_url" },
            "402": { description: "Plan limit reached", content: json({ $ref: "#/components/schemas/PaymentRequired" }) },
            "429": { content: json(errorRef) },
          },
        },
      },
      "/api/agent/profile/draft": {
        post: {
          summary: "Prepare a profile draft (never publishes)",
          security: [{ rout_oauth: ["profile:draft"] }],
          requestBody: {
            content: json({
              type: "object",
              required: ["space"],
              properties: {
                space: { enum: ["alias", "verified"] },
                displayName: { type: "string" },
                tagline: { type: "string" },
                theme: { type: "string" },
                cardStyle: { type: "string" },
                blocks: { type: "array", items: { type: "object" } },
              },
            }),
          },
          responses: { "202": { description: "Draft saved; the member must publish", content: json({ $ref: "#/components/schemas/HumanActionRequired" }) } },
        },
      },
      "/api/badge/verify": {
        get: {
          summary: "Web badge check: verified human on a domain the member registered",
          parameters: [{ name: "username", in: "query", required: true, schema: { type: "string" } }],
          responses: { "200": { description: "Badge payload (verified, verified_human, origin_match)" } },
        },
      },
      "/{handle}": {
        get: {
          summary: "Public profile as JSON-LD (send Accept: application/json)",
          parameters: [{ name: "handle", in: "path", required: true, schema: { type: "string" } }],
          responses: { "200": { description: "schema.org ProfilePage" } },
        },
      },
    },
  };
}
