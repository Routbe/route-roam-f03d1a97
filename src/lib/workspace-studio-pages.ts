/** Public pages of a workspace that Workspace Studio's page picker can switch to (/w/<slug>/…). */
export const WORKSPACE_STUDIO_PAGES = ["profile", "ask", "feedback", "support"] as const;

export type WorkspaceStudioPage = (typeof WORKSPACE_STUDIO_PAGES)[number];

/** Path shown in the picker and appended to /w/<slug>; the main page is "/". */
export function workspacePagePath(page: WorkspaceStudioPage): string {
  return page === "profile" ? "/" : `/${page}`;
}
