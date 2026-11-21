import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { ConsoleCard, ConsolePage } from "@/components/console/ConsolePage";
import { CodeBlock } from "@/components/console/CodeBlock";
import { Switch } from "@/components/ui/switch";
import { buildIdentityOsPrompt, PROMPT_SCOPES, type PromptScope, type PromptTool } from "@/lib/oauth/identity-os-prompt";

const title = "AI-integratieprompts — ROUT Developer Console";
const description = "Kant-en-klare prompts om Login met ROUT en de Identity OS-scopes in Lovable, Cursor of ChatGPT te bouwen.";

export const Route = createFileRoute("/_authenticated/console/docs")({
  head: () => ({
    meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
      { name: "robots", content: "noindex" },
    ],
  }),
  component: ConsoleDocsPage,
});

const TOOLS: { id: PromptTool; label: string }[] = [
  { id: "lovable", label: "Lovable" },
  { id: "cursor", label: "Cursor" },
  { id: "chatgpt", label: "ChatGPT" },
];

const SCOPE_TEXT: Record<PromptScope, string> = {
  sybil_proof: "Eén mens = één account in je app (app_nullifier).",
  real_human: "Enkel is_real_human, na een zero-knowledge-bewijs.",
  age_gate: "age_gate?min_age=N: enkel { age_verified, min_age }, zonder geboortedatum (13 tot 21).",
  legal_identity: "has_legal_identity, naam alleen met expliciete toestemming.",
};

function ConsoleDocsPage() {
  const [tool, setTool] = useState<PromptTool>("lovable");
  const [scopes, setScopes] = useState<PromptScope[]>(["sybil_proof"]);
  const [ageMin, setAgeMin] = useState(18);
  const [clientId, setClientId] = useState("");
  const prompt = useMemo(() => buildIdentityOsPrompt({ tool, scopes, ageMin, clientId }), [tool, scopes, ageMin, clientId]);

  return (
    <ConsolePage title="AI-integratieprompts" description="Kies je tool en scopes, kopieer de prompt en plak hem in je AI-assistent.">
      <ConsoleCard title="Tool">
        <div className="flex flex-wrap gap-2" role="radiogroup" aria-label="Tool">
          {TOOLS.map((x) => (
            <button
              key={x.id}
              type="button"
              role="radio"
              aria-checked={tool === x.id}
              onClick={() => setTool(x.id)}
              className={`min-h-11 rounded-full border px-4 text-sm ${tool === x.id ? "border-primary bg-primary text-primary-foreground" : "border-border bg-background"}`}
            >
              {x.label}
            </button>
          ))}
        </div>
      </ConsoleCard>
      <ConsoleCard title="Scopes">
        <ul className="divide-y divide-border">
          {PROMPT_SCOPES.map((s) => (
            <li key={s} className="flex items-center gap-4 py-3">
              <div className="flex-1">
                <code className="text-sm">{s}</code>
                <p className="text-xs text-muted-foreground">{SCOPE_TEXT[s]}</p>
              </div>
              {s === "age_gate" && scopes.includes("age_gate") && (
                <select
                  aria-label="Minimumleeftijd"
                  className="min-h-11 rounded-md border border-input bg-background px-3 text-sm"
                  value={ageMin}
                  onChange={(e) => setAgeMin(Number(e.target.value))}
                >
                  {[13, 14, 15, 16, 17, 18, 19, 20, 21].map((n) => (
                    <option key={n} value={n}>{n}+</option>
                  ))}
                </select>
              )}
              <Switch
                aria-label={s}
                checked={scopes.includes(s)}
                onCheckedChange={(on) => setScopes((cur) => (on ? [...cur, s] : cur.filter((x) => x !== s)))}
              />
            </li>
          ))}
        </ul>
        <label className="mt-4 block text-sm">
          <span className="text-muted-foreground">client_id (optioneel)</span>
          <input
            value={clientId}
            onChange={(e) => setClientId(e.target.value.slice(0, 120))}
            className="mt-1 block min-h-11 w-full rounded-md border border-input bg-background px-3 font-mono text-sm"
            placeholder="rout_…"
          />
        </label>
      </ConsoleCard>
      <CodeBlock code={prompt} label={`prompt · ${tool}`} />
    </ConsolePage>
  );
}
