import { describe, expect, it } from "vitest";
import { mcpDiscovery } from "./mcp-discovery";
import { listTools } from "@/lib/mcp-server/protocol";

const doc = mcpDiscovery("https://rout.be");

describe("mcp.json discovery", () => {
  it("lists exactly the tools the MCP server exposes", () => {
    expect(doc.tools.map((t) => t.name)).toEqual(listTools().map((t) => t.name));
  });
  it("maps the three agent tasks to their v1 REST endpoints", () => {
    expect(doc.agent_tasks.map((t) => t.task)).toEqual(["create_workspace", "manage_studio", "register_oauth_app"]);
    expect(doc.agent_tasks[0]?.rest.url).toBe("https://rout.be/api/v1/agent/workspace/create");
  });
  it("only names MCP tools that exist", () => {
    const names = new Set(listTools().map((t) => t.name));
    for (const task of doc.agent_tasks) for (const tool of task.mcp_tools) expect(names.has(tool)).toBe(true);
  });
  it("keeps the sandbox lifetime at 24 hours", () => expect(doc.sandbox_ttl_hours).toBe(24));
});
