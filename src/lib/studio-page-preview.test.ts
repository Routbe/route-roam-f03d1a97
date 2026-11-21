import { describe, expect, it } from "vitest";
import { studioPagePreviewSrc } from "./studio-page-preview";

describe("studioPagePreviewSrc", () => {
  it("previews the tip page of a verified main profile, not the profile", () => {
    expect(studioPagePreviewSrc({ editMode: "tip", handle: "jdelplanche", alias: false, verified: true })).toBe("/jdelplanche/tip");
  });
  it("never offers a tip page for an alias or an unverified profile", () => {
    expect(studioPagePreviewSrc({ editMode: "tip", handle: "anna", alias: true, verified: true })).toBeNull();
    expect(studioPagePreviewSrc({ editMode: "tip", handle: "anna", alias: false, verified: false })).toBeNull();
  });
  it("previews the question page in the profile's own space", () => {
    expect(studioPagePreviewSrc({ editMode: "qa", handle: "anna", alias: true, verified: false })).toBe("/u/anna/ask");
    expect(studioPagePreviewSrc({ editMode: "qa", handle: "@anna", alias: false, verified: true })).toBe("/anna/ask");
  });
  it("keeps the draft preview on the profile page", () => {
    expect(studioPagePreviewSrc({ editMode: "profile", handle: "anna", alias: false, verified: true })).toBeNull();
  });
});
