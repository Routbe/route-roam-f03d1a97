import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";
import { claimVerifiedHandle, getVerifiedHandleOptions } from "@/lib/verified-handle.functions";

const TITLE = "Kies je geverifieerde handle | ROUT";
const DESC = "Kies na je identiteitsverificatie je officiële adres op rout.be.";

export const Route = createFileRoute("/_authenticated/verify_/handle-select")({
  head: () => ({
    meta: [
      { title: TITLE },
      { name: "description", content: DESC },
      { name: "robots", content: "noindex, nofollow" },
      { property: "og:title", content: TITLE },
      { property: "og:description", content: DESC },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: HandleSelectPage,
});

const ERRORS: Record<string, string> = {
  identity_required: "Je verificatie is nog niet afgerond. Probeer het over een minuut opnieuw.",
  name_unavailable: "We konden je geverifieerde naam niet lezen.",
  not_ready: "Deze stap is nog niet beschikbaar.",
  HANDLE_TAKEN: "Deze handle is net bezet. Kies een andere.",
  HANDLE_RESERVED: "Deze handle is gereserveerd.",
  HANDLE_INVALID: "Deze handle is ongeldig.",
  HANDLE_NOT_LEGALLY_TRACEABLE: "Deze handle hoort niet bij je geverifieerde naam.",
  HANDLE_FALLBACK_NOT_ALLOWED: "Er is nog een gewone variant vrij. Kies die eerst.",
  cooldown: "Je kunt je handle nu nog niet wijzigen.",
  failed: "Opslaan is mislukt. Probeer opnieuw.",
};

function HandleSelectPage() {
  const fetchOptions = useServerFn(getVerifiedHandleOptions);
  const claim = useServerFn(claimVerifiedHandle);
  const q = useQuery({ queryKey: ["verified-handle-options"], queryFn: () => fetchOptions(), retry: false });
  const [choice, setChoice] = useState("");
  const [copyLinks, setCopyLinks] = useState(false);
  const [hideAlias, setHideAlias] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  const submit = async () => {
    if (!choice || busy) return;
    setBusy(true);
    setError(null);
    try {
      const r = await claim({ data: { handle: choice, copyLinks, hideAlias } });
      if (r.ok) setDone(r.handle);
      else {
        setError(ERRORS[r.reason] ?? ERRORS["failed"]!);
        void q.refetch();
      }
    } catch {
      setError(ERRORS["failed"]!);
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="mx-auto max-w-xl px-4 py-12">
      <h1 className="text-2xl font-semibold text-foreground">Kies je geverifieerde handle</h1>
      <p className="mt-2 text-sm text-muted-foreground">
        Je geverifieerde profiel staat los van je /u/-profiel. Niemand kan zien dat ze bij elkaar horen.
      </p>

      {done ? (
        <section className="mt-8 rounded-lg border border-border bg-card p-6">
          <p className="text-foreground">Je profiel staat nu op <strong>rout.be/{done}</strong>.</p>
          <Button asChild className="mt-4"><Link to="/dashboard">Naar je dashboard</Link></Button>
        </section>
      ) : q.isLoading ? (
        <p className="mt-8 text-muted-foreground">Varianten laden…</p>
      ) : !q.data || !q.data.ok ? (
        <section className="mt-8 space-y-4">
          <p role="alert" className="text-destructive">{ERRORS[q.data?.reason ?? "failed"] ?? ERRORS["failed"]}</p>
          <Button variant="outline" onClick={() => void q.refetch()}>Opnieuw proberen</Button>
        </section>
      ) : q.data.currentRootHandle ? (
        <p className="mt-8 text-foreground">Je hebt al een geverifieerde handle: <strong>rout.be/{q.data.currentRootHandle}</strong>.</p>
      ) : q.data.options.length === 0 ? (
        <p className="mt-8 text-foreground">Er is geen vrije variant van je naam. Neem contact op met support.</p>
      ) : (
        <section className="mt-8 space-y-6">
          <RadioGroup value={choice} onValueChange={setChoice} className="space-y-2">
            {q.data.options.map((o) => (
              <Label key={o.handle} htmlFor={`h-${o.handle}`} className="flex min-h-11 cursor-pointer items-center gap-3 rounded-md border border-border px-3 py-2">
                <RadioGroupItem id={`h-${o.handle}`} value={o.handle} />
                <span className="font-mono text-foreground">rout.be/{o.handle}</span>
              </Label>
            ))}
          </RadioGroup>

          {q.data.offerCopyLinks && (
            <fieldset className="space-y-2 rounded-md border border-border p-4">
              <legend className="px-1 text-sm font-medium text-foreground">Startpunt (eenmalig)</legend>
              <RadioGroup value={copyLinks ? "copy" : "blank"} onValueChange={(v) => setCopyLinks(v === "copy")}>
                <Label className="flex items-center gap-3"><RadioGroupItem value="blank" /> Start blanco (100% gescheiden)</Label>
                <Label className="flex items-center gap-3"><RadioGroupItem value="copy" /> Kopieer mijn huidige links eenmalig</Label>
              </RadioGroup>
            </fieldset>
          )}
          {q.data.hasAlias && (
            <Label className="flex items-center gap-3 text-sm">
              <Checkbox checked={hideAlias} onCheckedChange={(v) => setHideAlias(v === true)} />
              Zet mijn /u/-profiel tijdelijk op verborgen (privé)
            </Label>
          )}

          {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
          <Button onClick={() => void submit()} disabled={!choice || busy}>{busy ? "Bezig…" : "Bevestigen"}</Button>
        </section>
      )}
    </main>
  );
}
