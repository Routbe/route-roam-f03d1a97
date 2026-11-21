import { useEffect, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { Building2, GraduationCap, Landmark, Loader2, ShieldCheck, ShieldOff, ShieldQuestion } from "lucide-react";
import { useI18n } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { getPartnerChecks } from "@/lib/support/support.functions";
import { partnersIn, type Partner, type PartnerGroup } from "@/lib/support/partners";
import type { DnssecState } from "@/lib/support/dnssec.server";
import { SupportNav } from "./SupportNav";

const K = "pages.supportfund.";
const card = "rounded-xl border border-border/60 bg-card p-5 shadow-sm";

function DnssecChip({ state }: { state: DnssecState | undefined }) {
  const { t } = useI18n();
  const Icon = state === undefined ? Loader2 : state === "valid" ? ShieldCheck : state === "unsigned" ? ShieldOff : ShieldQuestion;
  return (
    <span className={cn("inline-flex items-center gap-1 self-start rounded-full border px-2 py-0.5 text-[11px]", state === "valid" ? "border-foreground/30 text-foreground" : "border-border/60 text-muted-foreground")}>
      <Icon className={cn("size-3", state === undefined && "animate-spin")} aria-hidden />
      {t(K + (state === undefined ? "dnssec.checking" : `dnssec.${state}`))}
    </span>
  );
}

function PartnerCard({ p, dnssec }: { p: Partner; dnssec: DnssecState | undefined }) {
  const { t, locale } = useI18n();
  const country = new Intl.DisplayNames([locale], { type: "region" }).of(p.country) ?? p.country;
  return (
    <li className="flex flex-col gap-2 rounded-lg border border-border/60 p-4">
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="font-medium">{p.name}</p>
          <p className="font-mono text-xs text-muted-foreground">{p.domain}</p>
        </div>
        {p.relationship === "supplier" && <span className="rounded-full bg-muted px-2 py-0.5 text-[11px] text-muted-foreground">{t(K + "partners.supplier")}</span>}
      </div>
      <p className="text-sm text-muted-foreground">{t(K + `partners.role.${p.role}`)} · {t(K + "partners.seat", { country })}</p>
      <DnssecChip state={dnssec} />
    </li>
  );
}

const GROUPS: { id: PartnerGroup; icon: typeof Landmark; empty?: string; note?: string }[] = [
  { id: "funds", icon: Landmark, empty: "partners.fundsEmpty" },
  { id: "infrastructure", icon: Building2, note: "partners.infraNote" },
  { id: "academic", icon: GraduationCap, empty: "partners.academicEmpty" },
];
const TITLES: Record<PartnerGroup, string> = { funds: "partners.funds", infrastructure: "partners.infra", academic: "partners.academic" };

export function SupportPartnersPage() {
  const { t } = useI18n();
  const checks = useServerFn(getPartnerChecks);
  const [dnssec, setDnssec] = useState<Record<string, DnssecState> | null>(null);
  useEffect(() => {
    checks().then(setDnssec).catch(() => setDnssec({}));
  }, [checks]);
  return (
    <main className="mx-auto w-full max-w-3xl space-y-6 px-4 py-10 sm:py-14">
      <header className="space-y-4">
        <SupportNav active="partners" />
        <h1 className="font-serif text-3xl font-semibold tracking-tight sm:text-4xl">{t(K + "partners.title")}</h1>
        <p className="max-w-prose text-base text-muted-foreground">{t(K + "partners.lead")}</p>
      </header>
      {GROUPS.map(({ id, icon: Icon, empty, note }) => {
        const list = partnersIn(id);
        return (
          <section key={id} className={card} aria-labelledby={`g-${id}`}>
            <h2 id={`g-${id}`} className="flex items-center gap-2 font-serif text-xl font-semibold">
              <Icon className="size-5 text-muted-foreground" aria-hidden /> {t(K + TITLES[id])}
            </h2>
            {note && <p className="mt-1 text-sm text-muted-foreground">{t(K + note)}</p>}
            {list.length === 0 ? (
              <p className="mt-3 text-sm text-muted-foreground">{empty ? t(K + empty) : null}</p>
            ) : (
              <ul className="mt-4 grid gap-3 sm:grid-cols-2">
                {list.map((p) => <PartnerCard key={p.id} p={p} dnssec={dnssec ? (dnssec[p.id] ?? "unknown") : undefined} />)}
              </ul>
            )}
          </section>
        );
      })}
      <p className="text-xs text-muted-foreground">{t(K + "dnssec.note")}</p>
    </main>
  );
}
