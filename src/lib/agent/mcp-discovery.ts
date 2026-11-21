import { MCP_PROTOCOL_VERSION, MCP_SERVER_INFO, listTools } from "@/lib/mcp-server/protocol";
import { AGENT_V1 } from "./agent-v1";
import { SANDBOX_TTL_HOURS } from "./agent-protocol";

/**
 * Body of /.well-known/mcp.json: where ROUT's MCP server lives, which tools it really
 * exposes (read from the server's own tool list, so the two never drift) and the three
 * account-less agent tasks with their REST equivalents. Pure.
 */
export function mcpDiscovery(origin: string) {
  return {
    name: MCP_SERVER_INFO.name,
    title: MCP_SERVER_INFO.title,
    version: MCP_SERVER_INFO.version,
    protocol_version: MCP_PROTOCOL_VERSION,
    endpoint: { url: `${origin}/api/mcp`, transport: "streamable-http" },
    authentication: {
      sandbox: "None for tools/list; account-less tools use a proof-of-work and a sandbox key (rsk_…).",
      member: `OAuth 2.1 + PKCE via ${origin}/connect for tools that act for a ROUT member.`,
    },
    tools: listTools().map(({ name, title, description }) => ({ name, title, description })),
    agent_tasks: [
      { task: "create_workspace", rest: { method: "POST", url: `${origin}${AGENT_V1.create}` }, mcp_tools: ["rout_pow_challenge", "rout_sandbox_register", "rout_sandbox_create_workspace"] },
      { task: "manage_studio", rest: { methods: ["GET", "PATCH"], url: `${origin}${AGENT_V1.studioTemplate}` }, mcp_tools: ["rout_sandbox_design_profile", "rout_sandbox_status"] },
      { task: "register_oauth_app", rest: { methods: ["GET", "PUT"], url: `${origin}${AGENT_V1.apps}` }, mcp_tools: ["rout_sandbox_set_login_apps"] },
    ],
    sandbox_ttl_hours: SANDBOX_TTL_HOURS,
    docs: {
      openapi: `${origin}/.well-known/openapi.json`,
      agent_flow: `${origin}/.well-known/rout-agent.json`,
      llms: `${origin}/llms.txt`,
      llms_full: `${origin}/llms-full.txt`,
    },
  };
}
