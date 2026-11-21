/**
 * Copy-paste integration prompts for external developers (/console/docs). Pure and tested: the
 * prompt names only scopes ROUT issues, always PKCE S256 with a server-side code exchange, and the
 * rules an app must keep (unique app_nullifier, false means "not proven", no fallback login).
 */
import { DISCOVERY_URL, ROUT_ISSUER } from "./integration-templates";
import { AGE_GATE_PARAM_SCOPES } from "./identity-os-scopes";

export type PromptTool = "lovable" | "cursor" | "chatgpt";
export type PromptScope = "sybil_proof" | "real_human" | "legal_identity" | "age_gate";
export const PROMPT_SCOPES: readonly PromptScope[] = ["sybil_proof", "real_human", "age_gate", "legal_identity"];

const TOOL_LINE: Record<PromptTool, string> = {
  lovable: "You are building inside Lovable (TanStack Start, server functions for backend code).",
  cursor: "You are working in my existing codebase in Cursor. Match the project's framework and conventions.",
  chatgpt: "Give me complete, copy-ready code for my stack and explain where each file goes.",
};

export function buildIdentityOsPrompt(input: { tool: PromptTool; scopes: readonly PromptScope[]; ageMin?: number; clientId?: string }): string {
  const age = input.scopes.includes("age_gate") ? input.ageMin ?? 18 : null;
  const ageScope = age !== null && AGE_GATE_PARAM_SCOPES.includes(`age_gate?min_age=${age}`) ? `age_gate?min_age=${age}` : null;
  const scopes = ["openid", ...input.scopes.filter((s) => s !== "age_gate"), ...(ageScope ? [ageScope] : [])];
  const clientId = input.clientId?.trim() || "<YOUR_ROUT_CLIENT_ID>";
  const lines: string[] = [
    `# Add "Login with ROUT" (Sovereign Identity OS)`,
    "",
    TOOL_LINE[input.tool],
    "",
    "## Setup",
    `- OIDC issuer: ${ROUT_ISSUER} — discovery: ${DISCOVERY_URL}`,
    `- client_id: \`${clientId}\`; keep the client secret only in server-side environment variables, never in browser code.`,
    `- Authorization Code flow with PKCE (S256) and a random \`state\` and \`nonce\`; exchange the code on the server only.`,
    `- Request exactly: \`scope=${scopes.join(" ")}\``,
    "- Read the claims below from the userinfo endpoint with the access token, keyed by `sub`.",
    "",
    "## Claims and rules",
  ];
  if (input.scopes.includes("sybil_proof")) {
    lines.push(
      "- `sybil_proof` → `sybil_proof` (boolean) and `app_nullifier` (64 hex). Store `app_nullifier` in its own column with a UNIQUE constraint; refuse a second account with the same value. It is the same for this person in this app only and cannot be matched in other apps.",
    );
  }
  if (input.scopes.includes("real_human")) {
    lines.push("- `real_human` → `is_real_human` (boolean), true only after a zero-knowledge humanity proof. Treat false as \"not proven\", not as \"bot\".");
  }
  if (ageScope) {
    lines.push(`- \`${ageScope}\` → \`{ "age_verified": boolean, "min_age": ${age} }\`. No date of birth or actual age is ever sent. Block the age-restricted feature unless age_verified is true.`);
  }
  if (input.scopes.includes("legal_identity")) {
    lines.push(
      "- `legal_identity` → `has_legal_identity` (boolean) and, only if the member ticks it on the consent screen and ROUT holds it, `first_name`, `last_name`, `full_legal_name`. Most members will not share a name: never require it.",
    );
  }
  lines.push(
    "",
    "## Do not",
    "- Do not add a password, e-mail-only or anonymous fallback that skips these checks.",
    "- Do not log tokens, nullifiers or names; do not send them to analytics.",
    "- Do not request scopes you do not use; members can switch optional scopes off.",
  );
  return lines.join("\n");
}
