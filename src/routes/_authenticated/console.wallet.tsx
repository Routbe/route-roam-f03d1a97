import { createFileRoute } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import { CheckCircle2, Copy, Loader2, ShieldAlert, ShieldCheck, Wallet, XCircle } from "lucide-react";
import { toast } from "sonner";
import { ConsoleCard, ConsolePage } from "@/components/console/ConsolePage";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import {
  createVpRequestFn,
  createWalletOfferFn,
  listMyWalletCredentialsFn,
  readVpRequestFn,
  revokeWalletCredentialFn,
} from "@/lib/eudi/eudi.functions";

const title = "EUDI Wallet | ROUT Console";
const description = "Issue ROUT credentials to EUDI wallets (OpenID4VCI) and verify wallet presentations (OpenID4VP).";

export const Route = createFileRoute("/_authenticated/console/wallet")({
  head: () => ({
    meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
      { name: "robots", content: "noindex,nofollow" },
    ],
  }),
  component: WalletConsole,
});

const CLAIMS = [
  { id: "verified_human", label: "Verified human" },
  { id: "age_over_16", label: "Age 16 or over" },
  { id: "age_over_18", label: "Age 18 or over" },
  { id: "age_over_21", label: "Age 21 or over" },
] as const;
type ClaimId = (typeof CLAIMS)[number]["id"];

const WALLET_KEY = ["eudi", "wallet-credentials"] as const;

function copy(text: string) {
  void navigator.clipboard.writeText(text);
  toast.success("Copied");
}

function WalletConsole() {
  return (
    <ConsolePage title="EUDI Wallet" description={description}>
      <div className="grid gap-4 lg:grid-cols-2">
        <IssueCard />
        <VerifyCard />
      </div>
      <CredentialsCard />
      <ConsoleCard title="Endpoints" description="Everything a wallet or verifier discovers on its own.">
        <ul className="space-y-1 break-all font-mono text-xs text-muted-foreground">
          <li>/.well-known/openid-credential-issuer</li>
          <li>/.well-known/oauth-authorization-server/oid4vci</li>
          <li>/.well-known/jwt-vc-issuer</li>
          <li>/.well-known/rout-pq-keys.json</li>
          <li>/api/public/status/rout-1</li>
        </ul>
      </ConsoleCard>
    </ConsolePage>
  );
}

function IssueCard() {
  const create = useServerFn(createWalletOfferFn);
  const qc = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [offer, setOffer] = useState<{ uri: string; txCode: string; expiresAt: string } | null>(null);

  async function start() {
    setBusy(true);
    try {
      const r = await create();
      if (r.ok) {
        setOffer({ uri: r.uri, txCode: r.txCode, expiresAt: r.expiresAt });
        void qc.invalidateQueries({ queryKey: WALLET_KEY });
      } else {
        toast.error(r.reason === "not_ready" ? "Wallet issuance is not switched on yet." : "Only verified members can get this credential (max 5 offers per 10 minutes).");
      }
    } catch {
      toast.error("The offer could not be created.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <ConsoleCard title="Issue to your wallet (OpenID4VCI)" description="Scan with an EUDI-compatible wallet, then enter the 6-digit code.">
      {offer ? (
        <div className="space-y-4">
          <div className="inline-block rounded-lg bg-background p-3 ring-1 ring-border">
            <QRCodeSVG value={offer.uri} size={208} level="M" aria-label="Credential offer QR code" />
          </div>
          <p className="text-sm">
            Transaction code: <span className="font-mono text-lg tracking-widest" data-testid="tx-code">{offer.txCode}</span>
          </p>
          <p className="text-xs text-muted-foreground">Valid until {new Date(offer.expiresAt).toLocaleTimeString()}. One credential per offer.</p>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" className="min-h-11" onClick={() => copy(offer.uri)}><Copy className="mr-2 h-4 w-4" aria-hidden />Copy offer link</Button>
            <Button variant="ghost" className="min-h-11" onClick={() => setOffer(null)}>Done</Button>
          </div>
        </div>
      ) : (
        <div className="space-y-3 text-sm text-muted-foreground">
          <p>Credential: <span className="text-foreground">ROUT verified human</span> (SD-JWT VC, ES256, holder-bound, with a status list index and an Ed25519 + ML-DSA-65 signature).</p>
          <p>Contains only "verified human" and, when your age was checked, age-over flags. No name, no date of birth, no nationality.</p>
          <Button className="min-h-11" disabled={busy} onClick={() => void start()}>
            {busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden /> : <Wallet className="mr-2 h-4 w-4" aria-hidden />}Create offer
          </Button>
        </div>
      )}
    </ConsoleCard>
  );
}

function VerifyCard() {
  const create = useServerFn(createVpRequestFn);
  const read = useServerFn(readVpRequestFn);
  const [label, setLabel] = useState("Age check");
  const [claims, setClaims] = useState<ClaimId[]>(["verified_human", "age_over_18"]);
  const [req, setReq] = useState<{ id: string; url: string; expiresAt: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const result = useQuery({
    queryKey: ["eudi", "vp", req?.id],
    queryFn: () => read({ data: { id: req!.id } }),
    enabled: !!req,
    refetchInterval: (q) => (q.state.data && q.state.data.status !== "pending" ? false : 3000),
  });

  useEffect(() => {
    if (result.data && result.data.status !== "pending") toast.message(result.data.status === "verified" ? "Presentation verified" : "Presentation rejected");
  }, [result.data?.status]); // eslint-disable-line react-hooks/exhaustive-deps

  async function start() {
    setBusy(true);
    try {
      const r = await create({ data: { label, claims } });
      if (r.ok) setReq({ id: r.id, url: r.url, expiresAt: r.expiresAt });
      else toast.error(r.reason === "not_ready" ? "Wallet verification is not switched on yet." : "The request could not be created.");
    } catch {
      toast.error("The request could not be created.");
    } finally {
      setBusy(false);
    }
  }

  const view = result.data;
  return (
    <ConsoleCard title="Verify a wallet (OpenID4VP)" description="Ask a wallet for selected claims; ROUT checks issuer, holder binding, status and the PQ signature.">
      {!req ? (
        <div className="space-y-4">
          <label className="block space-y-1 text-sm">
            <span>Label</span>
            <Input value={label} maxLength={80} onChange={(e) => setLabel(e.target.value)} />
          </label>
          <fieldset className="space-y-2">
            <legend className="text-sm">Requested claims</legend>
            {CLAIMS.map((c) => (
              <label key={c.id} className="flex min-h-11 items-center gap-3 text-sm">
                <Checkbox
                  checked={claims.includes(c.id)}
                  onCheckedChange={(v) => setClaims((prev) => (v ? [...new Set([...prev, c.id])] : prev.filter((x) => x !== c.id)))}
                />
                {c.label}
              </label>
            ))}
          </fieldset>
          <Button className="min-h-11" disabled={busy || claims.length === 0 || !label.trim()} onClick={() => void start()}>
            {busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden /> : <ShieldCheck className="mr-2 h-4 w-4" aria-hidden />}Create request
          </Button>
        </div>
      ) : (
        <div className="space-y-4">
          {(!view || view.status === "pending") && (
            <>
              <div className="inline-block rounded-lg bg-background p-3 ring-1 ring-border">
                <QRCodeSVG value={req.url} size={208} level="M" aria-label="Presentation request QR code" />
              </div>
              <p className="flex items-center gap-2 text-xs text-muted-foreground" aria-live="polite"><Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />Waiting for the wallet…</p>
              <Button variant="outline" className="min-h-11" onClick={() => copy(req.url)}><Copy className="mr-2 h-4 w-4" aria-hidden />Copy request link</Button>
            </>
          )}
          {view && view.status !== "pending" && <Inspector view={view} />}
          <Button variant="ghost" className="min-h-11" onClick={() => setReq(null)}>New request</Button>
        </div>
      )}
    </ConsoleCard>
  );
}

function Inspector({ view }: { view: NonNullable<Awaited<ReturnType<typeof readVpRequestFn>>> }) {
  const r = view.result;
  const ok = view.status === "verified";
  const row = (label: string, good: boolean, text: string) => (
    <li className="flex items-center gap-2">
      {good ? <CheckCircle2 className="h-4 w-4 text-primary" aria-hidden /> : <XCircle className="h-4 w-4 text-destructive" aria-hidden />}
      <span className="w-36 text-muted-foreground">{label}</span>
      <span>{text}</span>
    </li>
  );
  return (
    <div className="space-y-3 text-sm" data-testid="vp-inspector">
      <p className={`flex items-center gap-2 font-medium ${ok ? "text-primary" : "text-destructive"}`}>
        {ok ? <ShieldCheck className="h-5 w-5" aria-hidden /> : <ShieldAlert className="h-5 w-5" aria-hidden />}
        {ok ? "Verified" : `Rejected${r?.reason ? ` (${r.reason})` : ""}`}
      </p>
      {r && (
        <>
          <ul className="space-y-1.5">
            {row("Issuer signature", r.reason !== "signature" && r.reason !== "malformed", r.issuer)}
            {row("Holder binding", r.holderBinding, r.holderBinding ? "KB-JWT valid" : "missing or invalid")}
            {row("Status list", r.status === "valid", r.status)}
            {row("Post-quantum", r.pq, r.pq ? "Ed25519 + ML-DSA-65 valid" : "not verified")}
          </ul>
          <pre className="overflow-x-auto border border-border bg-background p-3 text-xs">{JSON.stringify(r.claims, null, 2)}</pre>
          {r.missing.length > 0 && <p className="text-xs text-destructive">Missing: {r.missing.join(", ")}</p>}
        </>
      )}
    </div>
  );
}

function CredentialsCard() {
  const list = useServerFn(listMyWalletCredentialsFn);
  const revoke = useServerFn(revokeWalletCredentialFn);
  const qc = useQueryClient();
  const q = useQuery({ queryKey: WALLET_KEY, queryFn: () => list() });
  const rows = q.data ?? [];

  async function onRevoke(statusIdx: number) {
    const r = await revoke({ data: { statusIdx } }).catch(() => ({ ok: false }));
    if (r.ok) toast.success("Revoked. Verifiers see it within a few minutes.");
    else toast.error("Could not revoke.");
    void qc.invalidateQueries({ queryKey: WALLET_KEY });
  }

  return (
    <ConsoleCard title="Your wallet credentials" description="Revoking flips the credential's bit in the public status list.">
      {q.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">No wallet credentials issued yet.</p>
      ) : (
        <ul className="divide-y divide-border text-sm">
          {rows.map((c) => {
            const expired = new Date(c.expiresAt).getTime() <= Date.now();
            const state = c.revokedAt ? "revoked" : expired ? "expired" : "valid";
            return (
              <li key={c.statusIdx} className="flex flex-wrap items-center justify-between gap-3 py-3">
                <span>
                  <span className="font-mono text-xs text-muted-foreground">#{c.statusIdx}</span> ROUT verified human · issued {new Date(c.issuedAt).toLocaleDateString()} · <span data-state={state}>{state}</span>
                </span>
                {state === "valid" && (
                  <Button variant="outline" size="sm" className="min-h-11" onClick={() => void onRevoke(c.statusIdx)}>Revoke</Button>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </ConsoleCard>
  );
}
