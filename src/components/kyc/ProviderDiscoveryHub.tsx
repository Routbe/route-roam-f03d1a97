import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { ChevronDown, Loader2, Search } from "lucide-react";
import { ProviderLogo } from "@/components/icons/providers/ProviderLogo";
import { hubCopy } from "@/lib/kyc/hub-copy";
import { cn } from "@/lib/utils";
import {
  discoverProviders,
  regionFromLocale,
  type IdentityProviderEntry,
  type ProviderEngine,
  type ProviderFilter,
} from "@/lib/kyc/providers";

const FILTERS: ProviderFilter[] = ["all", "national_eid", "passport_nfc", "zero_knowledge"];

/**
 * Provider Discovery Hub: one compact sticky control bar (search + snap-scrolling chips), the
 * integrated engines as active cards, and every other provider folded into a compact
 * "upcoming" grid. Only providers with an active engine can be started. Logos come from
 * ProviderLogo: official marks stored in this repository (no third-party image requests), with a
 * neutral Building2 icon when a provider has no mark.
 */
export function ProviderDiscoveryHub({
  active,
  busy,
  onStart,
  signedOut = false,
}: {
  active: ReadonlySet<ProviderEngine>;
  busy: ProviderEngine | null;
  onStart: (engine: ProviderEngine) => void;
  /** Visitor without a session: engine cards lead to sign-in instead of claiming a status. */
  signedOut?: boolean;
}) {
  const { i18n } = useTranslation();
  const c = hubCopy(i18n.language);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<ProviderFilter>("all");
  const region = useMemo(() => {
    if (typeof navigator === "undefined") return null;
    for (const tag of navigator.languages ?? [navigator.language]) {
      const r = regionFromLocale(tag);
      if (r) return r;
    }
    return null;
  }, []);

  const list = useMemo(() => discoverProviders({ query, filter, region, active, docLabels: c.docs }), [query, filter, region, active, c.docs]);
  const engines = list.filter((p) => p.engine !== null);
  const upcoming = list.filter((p) => p.engine === null);
  const searching = query.trim() !== "";

  return (
    <div className="space-y-5">
      <div className="sticky top-0 z-10 -mx-1 space-y-1 bg-background/95 px-1 py-2 backdrop-blur supports-[backdrop-filter]:bg-background/80">
        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value.slice(0, 80))}
            placeholder={c.search}
            aria-label={c.searchLabel}
            className="h-11 w-full rounded-full border border-border bg-card pl-9 pr-4 text-sm outline-none placeholder:text-muted-foreground focus-visible:ring-2 focus-visible:ring-ring"
          />
        </div>
        <div role="group" aria-label={c.searchLabel} className="chip-rail pr-6">
          {FILTERS.map((f) => (
            <button
              key={f}
              type="button"
              aria-pressed={filter === f}
              onClick={() => setFilter(f)}
              className="group inline-flex min-h-11 items-center !border-0 !bg-transparent !bg-none p-0 !shadow-none"
            >
              <span
                className={cn(
                  "rounded-full border px-3 py-1.5 text-xs font-medium transition-colors",
                  filter === f ? "border-foreground bg-foreground text-background" : "border-border bg-card text-foreground group-hover:bg-accent",
                )}
              >
                {c.filters[f]}
              </span>
            </button>
          ))}
        </div>
      </div>

      {engines.length > 0 && (
        <section aria-label={c.active} className="space-y-2">
          <h3 className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{c.active}</h3>
          <ul className="grid gap-2 sm:grid-cols-2">
            {engines.map((p) => (
              <li key={p.id}>
                <ActiveCard provider={p} live={p.engine !== null && active.has(p.engine)} signedOut={signedOut} busy={busy} onStart={onStart} />
              </li>
            ))}
          </ul>
        </section>
      )}

      {upcoming.length > 0 && (
        <details className="group rounded-2xl border border-border" open={searching || filter !== "all" || undefined}>
          <summary className="flex min-h-11 cursor-pointer list-none items-center justify-between gap-2 px-4 text-sm font-medium [&::-webkit-details-marker]:hidden">
            <span>
              {c.upcoming} <span className="text-muted-foreground">· {upcoming.length}</span>
            </span>
            <ChevronDown className="h-4 w-4 text-muted-foreground transition-transform group-open:rotate-180" aria-hidden />
          </summary>
          <section aria-label={c.upcoming}>
            <ul className="grid grid-cols-2 gap-px border-t border-border bg-border">
              {upcoming.map((p) => (
                <li key={p.id}>
                  <article aria-label={p.name} className="flex h-full items-center gap-2 bg-background p-3">
                    <ProviderLogo name={p.id} size="sm" />
                    <div className="min-w-0">
                      <p className="truncate text-xs font-semibold">{p.name}</p>
                      <p className="truncate text-[11px] text-muted-foreground">{c.ratings[p.ratings[0]!]}</p>
                    </div>
                  </article>
                </li>
              ))}
            </ul>
          </section>
        </details>
      )}

      {list.length === 0 && (
        <p role="status" className="text-sm text-muted-foreground">{c.empty}</p>
      )}

      <p className="text-xs text-muted-foreground">{c.privacy}</p>
    </div>
  );
}

function ActiveCard({
  provider: p,
  live,
  signedOut,
  busy,
  onStart,
}: {
  provider: IdentityProviderEntry;
  live: boolean;
  signedOut: boolean;
  busy: ProviderEngine | null;
  onStart: (engine: ProviderEngine) => void;
}) {
  const { i18n } = useTranslation();
  const c = hubCopy(i18n.language);
  return (
    <article aria-label={p.name} className="flex h-full flex-col gap-3 rounded-2xl border border-foreground/15 bg-card p-4">
      <div className="flex items-center gap-3">
        <ProviderLogo name={p.id} size="lg" />
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold">{p.name}</p>
          <p className="truncate text-xs text-muted-foreground">
            {p.ratings.map((r) => c.ratings[r]).join(" · ")} · {p.documents.map((d) => c.docs[d]).join(", ")}
          </p>
        </div>
        {!signedOut && (
          <span className="inline-flex shrink-0 items-center gap-1.5 text-[11px] font-medium text-muted-foreground">
            <span aria-hidden className={cn("h-2 w-2 rounded-full", live ? "bg-identity-human" : "bg-muted-foreground/40")} />
            {live ? c.live : c.offline}
          </span>
        )}
      </div>
      <button
        type="button"
        disabled={(!live && !signedOut) || busy !== null}
        onClick={() => p.engine && onStart(p.engine)}
        className="inline-flex min-h-11 items-center justify-center gap-2 rounded-full bg-foreground px-4 text-sm font-medium text-background transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
      >
        {busy === p.engine && <Loader2 className="h-4 w-4 animate-spin" aria-hidden />}
        {signedOut ? c.signInToStart : live ? c.start : c.inactive}
      </button>
    </article>
  );
}

/** Inline vector marks drawn by ROUT for the integrated engines; never fetched from a vendor CDN. */
