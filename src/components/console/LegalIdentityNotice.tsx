import { Link } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useEffect, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { consoleAccess } from "@/lib/oauth/console.functions";

/** null while loading; false when new apps and API keys are locked (no KYC legal identity). */
export function useDeveloperLegalIdentity(): boolean | null {
  const access = useServerFn(consoleAccess);
  const [legal, setLegal] = useState<boolean | null>(null);
  useEffect(() => {
    let live = true;
    access()
      .then((r) => live && setLegal((r as { legalIdentity?: boolean }).legalIdentity === true))
      .catch(() => live && setLegal(false));
    return () => {
      live = false;
    };
  }, [access]);
  return legal;
}

/** Shown where new credentials are created; the server refuses them anyway. */
export function LegalIdentityNotice() {
  return (
    <div role="status" className="flex items-start gap-3 rounded-2xl border border-border bg-muted/50 p-4 text-sm">
      <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-primary" aria-hidden />
      <div className="space-y-1">
        <p className="font-medium">Verifieer eerst je wettelijke identiteit</p>
        <p className="text-muted-foreground">
          Nieuwe apps en API-sleutels maken kan alleen met een KYC-verificatie (blauw schildje). Bestaande apps en sleutels blijven werken.
        </p>
        <Link to="/dashboard/identity" className="inline-flex min-h-11 items-center font-medium text-primary underline-offset-4 hover:underline">
          Naar identiteitsverificatie
        </Link>
      </div>
    </div>
  );
}
