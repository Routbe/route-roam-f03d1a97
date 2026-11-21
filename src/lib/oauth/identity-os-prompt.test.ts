import { describe, expect, it } from "vitest";
import { buildIdentityOsPrompt } from "./identity-os-prompt";

describe("buildIdentityOsPrompt", () => {
  it("requests exactly the chosen scopes with the app's age gate", () => {
    const p = buildIdentityOsPrompt({ tool: "lovable", scopes: ["sybil_proof", "age_gate"], ageMin: 16, clientId: "rout_abc" });
    expect(p).toContain("scope=openid sybil_proof age_gate?min_age=16`");
    expect(p).toContain("UNIQUE constraint");
    expect(p).toContain(`"min_age": 16`);
    expect(p).toContain("`rout_abc`");
    expect(p).not.toContain("legal_identity");
  });
  it("never names an age gate outside 13..21", () => {
    const p = buildIdentityOsPrompt({ tool: "cursor", scopes: ["age_gate"], ageMin: 25 });
    expect(p).toContain("scope=openid`");
    expect(p).not.toContain("min_age=25");
  });
  it("always demands PKCE and a server-side exchange", () => {
    const p = buildIdentityOsPrompt({ tool: "chatgpt", scopes: [] });
    expect(p).toContain("PKCE (S256)");
    expect(p).toContain("exchange the code on the server only");
  });
});
