/**
 * Address the Studio preview loads for the page being edited. The tip page exists only on a
 * verified main profile (rout.be/<handle>/tip); the question page lives under the profile's own
 * space. null = preview the profile itself from the unsaved draft.
 */
export function studioPagePreviewSrc(i: { editMode: "profile" | "tip" | "qa"; handle: string; alias: boolean; verified: boolean }): string | null {
  const handle = i.handle.trim().replace(/^@+/, "");
  if (!handle) return null;
  if (i.editMode === "tip") return !i.alias && i.verified ? `/${encodeURIComponent(handle)}/tip` : null;
  if (i.editMode === "qa") return `${i.alias ? "/u/" : "/"}${encodeURIComponent(handle)}/ask`;
  return null;
}
