import { describe, expect, it } from "vitest";
import { WORKSPACE_STUDIO_PAGES, workspacePagePath } from "./workspace-studio-pages";

describe("workspace studio pages", () => {
  it("offers the main page and the three public workspace pages", () => {
    expect([...WORKSPACE_STUDIO_PAGES]).toEqual(["profile", "ask", "feedback", "support"]);
  });
  it("maps the main page to / and the others to their public path", () => {
    expect(workspacePagePath("profile")).toBe("/");
    expect(workspacePagePath("ask")).toBe("/ask");
    expect(workspacePagePath("feedback")).toBe("/feedback");
    expect(workspacePagePath("support")).toBe("/support");
  });
});
