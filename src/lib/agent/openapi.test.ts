import { describe, expect, it } from "vitest";
import { agentOpenApi } from "./openapi";

const spec = agentOpenApi("https://rout.be");

describe("agent OpenAPI", () => {
  it("documents the three agent v1 endpoints with their methods", () => {
    expect(Object.keys(spec.paths["/api/v1/agent/workspace/create"])).toEqual(["post"]);
    expect(Object.keys(spec.paths["/api/v1/agent/workspace/{id}/studio"]).filter((k) => k !== "parameters").sort()).toEqual(["get", "patch"]);
    expect(Object.keys(spec.paths["/api/v1/agent/developer/apps"]).sort()).toEqual(["get", "put"]);
  });
  it("derives the create body from the handler's validator", () => {
    const create = spec.components.schemas.AgentWorkspaceCreate as { required?: string[]; additionalProperties?: unknown };
    expect(create.required).toEqual(["agent_name", "name"]);
    expect(create.additionalProperties).toBe(false);
  });
  it("states the 24-hour sandbox lifetime", () => {
    expect(spec.components.securitySchemes.rout_sandbox.description).toContain("24 hours");
  });
});
