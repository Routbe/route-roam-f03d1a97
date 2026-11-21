import { useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { useQuery } from "@tanstack/react-query";
import { Check, Crown, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { Link, useNavigate } from "@/lib/router-compat";
import { AppLayout } from "@/components/layout/AppLayout";
import { VerifiedIdentityIcon } from "@/components/profile/VerifiedIdentityIcon";
import { DiditVerificationModal } from "@/components/kyc/DiditVerificationModal";
import { ProviderDiscoveryHub } from "@/components/kyc/ProviderDiscoveryHub";
import { useAuth } from "@/hooks/useAuth";
import { useI18n } from "@/lib/i18n";
import { hubCopy } from "@/lib/kyc/hub-copy";
import type { ProviderEngine } from "@/lib/kyc/providers";
import { getMyIdentityStatus, startIdentityVerification } from "@/lib/identity/identity.functions";

const PRIMARY =
  "inline-flex min-h-12 w-full items-center justify-center gap-2 rounded-full bg-foreground px-6 text-sm font-semibold text-background transition-opacity hover:opacity-90 disabled:opacity-40 sm:w-auto";

/**
 * /verify — "Geverifieerd profiel": one primary action (Didit KYC), the integrated engines as
 * active cards and every other provider folded away. Signed-out visitors see the same page; the
 * action sends them to sign-in first. Badge rules: blue = KYC, green = zero-knowledge only, crown = support.
 */
export default function VerifyGuide() {
  const { t, locale } = useI18n();
  const c = hubCopy(locale);
  const { user, loading } = useAuth();
  const status = useQuery({
    queryKey: ["identity-status"],
    queryFn: useServerFn(getMyIdentityStatus),
    enabled: Boolean(user),
  });
  const start = useServerFn(startIdentityVerification);
  const [diditOpen, setDiditOpen] = useState(false);
  const [busy, setBusy] = useState<ProviderEngine | null>(null);
  const navigate = useNavigate();

  const s = status.data;
  const verified = Boolean(s?.tier2LegalIdentity);
  const active = new Set<ProviderEngine>(
    user
      ? [
          ...(s?.diditConfigured && s?.diditAvailable && !verified ? (["didit"] as const) : []),
          ...(s?.wConfigured && !s?.tier1RealHuman ? (["w_identity"] as const) : []),
        ]
      : [],
  );

  async function go(engine: ProviderEngine) {
    if (!user) return void navigate("/auth/sign-in");
    if (engine === "didit") return setDiditOpen(true);
    setBusy(engine);
    try {
      const res = await start({ data: { provider: engine, origin: window.location.origin } });
      if (res.ok) window.location.assign(res.url);
      else toast.error(c.errors.provider_error);
    } catch {
      toast.error(c.errors.provider_error);
    } finally {
      setBusy(null);
    }
  }

  const marks = [
    { key: "blue", icon: <VerifiedIdentityIcon className="h-5 w-5" />, title: c.page.blue, body: c.page.blueBody },
    { key: "green", icon: <ShieldCheck className="h-5 w-5 text-identity-human" aria-hidden />, title: c.page.green, body: c.page.greenBody },
    { key: "crown", icon: <Crown className="h-5 w-5 text-identity-supporter" strokeWidth={1.75} aria-hidden />, title: c.page.crown, body: c.page.crownBody },
  ];

  return (
    <AppLayout crumbs={[{ label: t("verify.crumb") }]}>
      <div className="mx-auto max-w-2xl px-4 pb-16 pt-6 sm:px-6 sm:pt-12">
        <header className="space-y-3">
          <h1 className="font-serif text-3xl font-medium tracking-tight sm:text-4xl">{c.page.title}</h1>
          <p className="text-[15px] leading-relaxed text-muted-foreground">{c.page.subtitle}</p>
          {/* Fixed-height slot: the button never moves when the session resolves (no layout shift). */}
          <div className="min-h-12 pt-1">
            {loading ? (
              <span className={`${PRIMARY} pointer-events-none opacity-40`} aria-hidden>{c.page.cta}</span>
            ) : !user ? (
              <Link to="/auth/sign-in" className={PRIMARY}>{c.page.cta}</Link>
            ) : verified ? (
              <span role="status" className={`${PRIMARY} bg-transparent text-foreground ring-1 ring-border`}>
                <Check className="h-4 w-4" aria-hidden /> {c.page.ctaDone}
              </span>
            ) : (
              <button type="button" className={PRIMARY} onClick={() => setDiditOpen(true)} disabled={status.isLoading || !active.has("didit")}>
                {c.page.cta}
              </button>
            )}
          </div>
          {!loading && !user && <p className="text-xs text-muted-foreground">{c.page.signIn}</p>}
          {user && s && !verified && !active.has("didit") && <p className="text-xs text-muted-foreground">{c.errors.not_configured}</p>}
        </header>

        <div className="mt-8">
          <ProviderDiscoveryHub active={active} signedOut={!loading && !user} busy={busy} onStart={(e) => void go(e)} />
        </div>

        <section aria-label={c.page.badgesTitle} className="mt-10 border-t border-border pt-6">
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{c.page.badgesTitle}</h2>
          <ul className="mt-3 divide-y divide-border">
            {marks.map((m) => (
              <li key={m.key} className="flex items-center gap-3 py-3">
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-border bg-background">{m.icon}</span>
                <div className="min-w-0">
                  <p className="text-sm font-semibold">{m.title}</p>
                  <p className="text-xs text-muted-foreground">{m.body}</p>
                </div>
              </li>
            ))}
          </ul>
        </section>
      </div>
      <DiditVerificationModal open={diditOpen} onOpenChange={setDiditOpen} />
    </AppLayout>
  );
}
