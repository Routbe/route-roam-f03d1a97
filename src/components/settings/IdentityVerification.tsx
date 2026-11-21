import { useEffect, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { useQuery } from "@tanstack/react-query";
import { BadgeCheck, Fingerprint, Loader2, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { DiditVerificationModal } from "@/components/kyc/DiditVerificationModal";
import { ProviderDiscoveryHub } from "@/components/kyc/ProviderDiscoveryHub";
import type { ProviderEngine } from "@/lib/kyc/providers";
import { getMyIdentityStatus, startIdentityVerification } from "@/lib/identity/identity.functions";
import { DIDIT_LIMIT_MESSAGE } from "@/lib/identity/identity-rules";
import { i18n as trI18n } from "@/lib/i18n";

const RESULT: Record<string, string> = {
  verified: "Je identiteit is geverifieerd.",
  duplicate_human: "Deze persoon heeft al een geverifieerd ROUT-account.",
  already_verified: "Je account is al geverifieerd.",
  limit_reached: DIDIT_LIMIT_MESSAGE,
  not_configured: "Deze verificatiemethode is nog niet actief.",
  expired: "De verificatie is verlopen. Probeer opnieuw.",
  invalid_name: "We konden geen geldige naam ontvangen van de provider.",
  failed: "Verificatie mislukt. Probeer opnieuw.",
  provider_error: "De verificatiedienst reageert niet. Probeer later opnieuw.",
};

export function IdentityVerification() {
  const status = useQuery({ queryKey: ["identity-status"], queryFn: useServerFn(getMyIdentityStatus) });
  const start = useServerFn(startIdentityVerification);
  const [busy, setBusy] = useState<ProviderEngine | null>(null);
  const [diditOpen, setDiditOpen] = useState(false);

  useEffect(() => {
    const result = new URLSearchParams(window.location.search).get("identity");
    if (result && result !== "pending" && RESULT[result]) {
      toast[result === "verified" ? "success" : "error"](RESULT[result]);
    } else if (result === "pending") {
      toast.message(trI18n.t("ui.7bc79e9fcf"));
    }
  }, []);

  async function go(provider: ProviderEngine) {
    if (provider === "didit") {
      setDiditOpen(true);
      return;
    }
    setBusy(provider);
    try {
      const res = await start({ data: { provider, origin: window.location.origin } });
      if (res.ok) window.location.assign(res.url);
      else toast.error(RESULT[res.reason] ?? RESULT.failed);
    } catch {
      toast.error(RESULT.failed);
    } finally {
      setBusy(null);
    }
  }

  const s = status.data;
  const tier1 = Boolean(s?.tier1RealHuman);
  const tier2 = Boolean(s?.tier2LegalIdentity);
  const spin = <Loader2 className="h-4 w-4 animate-spin" />;
  const active = new Set<ProviderEngine>([
    ...(s?.diditConfigured && s?.diditAvailable ? (["didit"] as const) : []),
    ...(s?.wConfigured && !tier1 ? (["w_identity"] as const) : []),
  ]);
  return (
    <section className="space-y-4 rounded-2xl border border-border bg-card p-4 sm:p-5">
      <h2 className="flex items-center gap-2 text-lg font-medium">
        <Fingerprint className="h-5 w-5" aria-hidden /> Verificatie
      </h2>
      {status.isLoading ? (
        <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
      ) : (
        <>
          {s?.isPioneer && !tier2 && (
            <div role="note" className="rounded-xl border border-primary/30 bg-primary/10 p-3 text-sm">
              <p className="font-semibold">🚀 Pioneer / Early Supporter</p>
              <p className="mt-0.5 text-muted-foreground">
                Als Early Supporter is je paspoortscan via Didit gratis. Verifieer eenmalig om het blauwe schildje "KYC Attested" te behouden.
              </p>
            </div>
          )}

          <div className="space-y-2 rounded-xl border border-border p-3">
            <h3 className="text-sm font-semibold">1. KYC Attested (blauw schildje)</h3>
            {tier2 ? (
              <>
                <p role="status" className="flex items-center gap-2 text-sm font-medium text-primary">
                  <BadgeCheck className="h-4 w-4" aria-hidden /> [✓] Geverifieerde Wettelijke Identiteit
                </p>
                {s?.verifiedRealName ? (
                  <>
                    <label className="block text-xs text-muted-foreground" htmlFor="verified-real-name">Officiële naam</label>
                    <Input id="verified-real-name" value={s.verifiedRealName} readOnly disabled aria-readonly />
                    <p className="text-xs text-muted-foreground">Deze naam komt van je identiteitsbewijs en kan niet gewijzigd worden.</p>
                  </>
                ) : (
                  <p className="text-xs text-muted-foreground">ROUT bewaart geen naam of documentnummer, alleen een onomkeerbare vingerafdruk.</p>
                )}
              </>
            ) : (
              <ProviderDiscoveryHub active={active} busy={busy} onStart={(engine) => void go(engine)} />
            )}
          </div>

          <div className="space-y-2 rounded-xl border border-border p-3">
            <h3 className="text-sm font-semibold">2. Echt mens (pseudoniem)</h3>
            <p className="text-xs text-muted-foreground">
              Het groene schildje "Real Human" komt uitsluitend van een zero-knowledge-bewijs. Een paspoortscan, W Identity of betaling geeft het nooit; die koppeling volgt nog.
            </p>
            {tier1 ? (
              <p role="status" className="flex items-center gap-2 text-sm font-medium text-primary">
                <ShieldCheck className="h-4 w-4" aria-hidden /> [🛡️] Geverifieerd Uniek Mens
              </p>
            ) : (
              <>
                <p className="text-sm text-muted-foreground">
                  Bewijs met W Identity dat je een uniek mens bent zonder je naam vrij te geven. Dat telt binnen ROUT, maar geeft geen groen schildje.
                </p>
                <Button type="button" variant="outline" onClick={() => go("w_identity")} disabled={busy !== null || !s?.wConfigured} className="w-full gap-2 sm:w-auto">
                  {busy === "w_identity" ? spin : <Fingerprint className="h-4 w-4" aria-hidden />} Via W Identity
                </Button>
                {s && !s.wConfigured && <p className="text-xs text-muted-foreground">W Identity is nog niet actief.</p>}
              </>
            )}
          </div>
        </>
      )}
      <DiditVerificationModal open={diditOpen} onOpenChange={setDiditOpen} />
    </section>
  );
}
