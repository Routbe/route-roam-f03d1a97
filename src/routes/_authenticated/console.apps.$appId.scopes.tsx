import { createFileRoute } from "@tanstack/react-router";
import { ConsoleCard, ConsolePage } from "@/components/console/ConsolePage";
import { useAppPage } from "@/components/console/useAppPage";
import { HandleSyncCard } from "@/components/console/HandleSyncCard";
import { Switch } from "@/components/ui/switch";

export const Route = createFileRoute("/_authenticated/console/apps/$appId/scopes")({
  head: () => ({ meta: [{"title": "Scopes \u2014 ROUT Developer Console"}, {"name": "description", "content": "Manage scopes for your ROUT application."}, {"property": "og:title", "content": "Scopes \u2014 ROUT Developer Console"}, {"property": "og:description", "content": "Manage scopes for your ROUT application."}, {"property": "og:type", "content": "website"}, {"name": "twitter:card", "content": "summary_large_image"}] }),
  component: ScopesPage,
});

const SCOPES = [
  { id: "openid", label: "openid", text: "Verplicht. Geeft een vaste, anonieme gebruikers-ID (sub).", locked: true },
  { id: "profile", label: "profile", text: "Naam, @handle en profielfoto.", locked: false },
  { id: "email", label: "email", text: "E-mailadres en of het bevestigd is.", locked: false },
  {
    id: "accounts:merge",
    label: "accounts:merge",
    text: "Bestaande accounts herkennen zonder lijst: jij stuurt hashes, de browser van het lid vergelijkt, en alleen het account dat het lid bevestigt komt één keer in de id_token. Zie Schema-templates.",
    locked: false,
  },
  {
    id: "identity:handle_reservation",
    label: "identity:handle_reservation",
    text: "Neem de geverifieerde @handle van het lid over als gebruikersnaam, zonder eigen anti-bot- of anti-squattingcontrole. ROUT controleert of het account actief en bevestigd is en of de naam uniek is.",
    locked: false,
  },
  {
    id: "assets:write",
    label: "assets:write (agent)",
    text: "AI-agent maakt QR-codes en korte links voor het lid, binnen diens abonnement (anders HTTP 402). Token max. 1 uur geldig.",
    locked: false,
  },
  {
    id: "profile:draft",
    label: "profile:draft (agent)",
    text: "AI-agent zet profielontwerpen klaar. Live zetten blijft een menselijke stap (status human_action_required).",
    locked: false,
  },
  {
    id: "identity:read_public",
    label: "identity:read_public (agent)",
    text: "Leest enkel de publieke verificatiestatus (geverifieerde mens ja/nee). Nooit identity relays of wettelijke naam.",
    locked: false,
  },
  {
    id: "sybil_proof",
    label: "sybil_proof",
    text: "Eén mens = één account in jouw app: je krijgt een app_nullifier die ROUT met een geheime sleutel afleidt (ECVRF, RFC 9381) uit de universele nullifier en jouw app-ID. Altijd dezelfde waarde voor dezelfde persoon bij jou, onbruikbaar om leden tussen apps te koppelen.",
    locked: false,
  },
  {
    id: "real_human",
    label: "real_human",
    text: "Enkel is_real_human (true/false). True alleen na een zero-knowledge-menselijkheidsbewijs, nooit na KYC of betaling.",
    locked: false,
  },
  {
    id: "legal_identity",
    label: "legal_identity",
    text: "has_legal_identity (true/false) en de wettelijke naam alleen als ROUT die bewaart én het lid dit expliciet aanvinkt. Didit-verificaties bewaren geen naam: dan krijg je enkel de boolean.",
    locked: false,
  },
];

const AGE_MINIMA = [13, 14, 15, 16, 17, 18, 19, 20, 21];

function ScopesPage() {
  const { appId } = Route.useParams();
  const { app, persist, saving } = useAppPage(appId);
  const origin = typeof window === "undefined" ? "https://rout.be" : window.location.origin;
  const snippet = `${origin}/oauth/authorize?response_type=code
  &client_id=${app.clientId}
  &redirect_uri=${encodeURIComponent(app.redirectUris[0] ?? "")}
  &scope=${app.scopes.join("%20")}
  &state=RANDOM&nonce=RANDOM
  &code_challenge=BASE64URL(SHA256(verifier))
  &code_challenge_method=S256`;

  return (
    <ConsolePage title="Scopes" description="Vraag enkel wat je app echt nodig heeft.">
      <ConsoleCard>
        <ul className="divide-y divide-border">
          {SCOPES.map((s) => (
            <li key={s.id} className="flex items-center gap-4 py-3">
              <div className="flex-1">
                <code className="text-sm">{s.label}</code>
                <p className="text-xs text-muted-foreground">{s.text}</p>
              </div>
              <Switch
                checked={app.scopes.includes(s.id)}
                disabled={s.locked || saving}
                onCheckedChange={(on) =>
                  persist({ scopes: on ? [...app.scopes, s.id] : app.scopes.filter((x) => x !== s.id) })
                }
              />
            </li>
          ))}
        </ul>
      </ConsoleCard>
      <ConsoleCard title="age_gate" description="Leeftijdscontrole zonder geboortedatum: je app vraagt age_gate?min_age=N en krijgt enkel { age_verified, min_age } uit een KYC-verificatie. Kies één grens.">
        <label className="flex items-center gap-3 text-sm">
          <span className="flex-1">Minimumleeftijd</span>
          <select
            className="min-h-11 rounded-md border border-input bg-background px-3 text-sm"
            disabled={saving}
            value={app.scopes.find((x) => x.startsWith("age_gate:"))?.slice(9) ?? app.scopes.find((x) => x.startsWith("age_gate?min_age="))?.slice(17) ?? ""}
            onChange={(e) => {
              const rest = app.scopes.filter((x) => !x.startsWith("age_gate:") && !x.startsWith("age_gate?"));
              // Register both notations so old (age_gate:N) and new (age_gate?min_age=N) requests pass.
              persist({ scopes: e.target.value ? [...rest, `age_gate:${e.target.value}`, `age_gate?min_age=${e.target.value}`] : rest });
            }}
          >
            <option value="">Uit</option>
            {AGE_MINIMA.map((n) => (
              <option key={n} value={n}>{n}+</option>
            ))}
          </select>
        </label>
      </ConsoleCard>
      <HandleSyncCard app={app} saving={saving} persist={persist} />
      <ConsoleCard title="Autorisatie-URL (PKCE)" description="PKCE met S256 is verplicht.">
        <pre className="overflow-x-auto rounded-lg bg-muted p-4 text-xs">{snippet}</pre>
      </ConsoleCard>
    </ConsolePage>
  );
}
