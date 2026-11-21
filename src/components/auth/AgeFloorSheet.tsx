import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { getMyAgeStatus, submitMyAge } from "@/lib/parent.functions";
import { isMinorDob } from "@/lib/minor-safety";

const AGE_STATUS_KEY = ["my-age-status"] as const;

/**
 * Post-sign-in age sheet (GDPR Art. 8, db/0291). Shown once to a member whose age the database does
 * not know. The date leaves this form only in the submit request; the server keeps only the
 * whole-year age, and the field is cleared as soon as the request is sent.
 */
export function AgeFloorSheet() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const status = useQuery({ queryKey: AGE_STATUS_KEY, queryFn: () => getMyAgeStatus(), staleTime: Infinity, retry: false });
  const [dob, setDob] = useState("");
  const [parentEmail, setParentEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const minor = isMinorDob(dob);

  if (status.data?.needsAge !== true) return null;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    const value = dob;
    setDob("");
    try {
      const { outcome } = await submitMyAge({ data: { dob: value, parentEmail: minor ? parentEmail.trim() : undefined } });
      if (outcome === "ok" || outcome === "already_set") {
        toast.success(t(minor ? "auth.age.savedMinor" : "auth.age.saved"));
        qc.setQueryData(AGE_STATUS_KEY, { needsAge: false });
        return;
      }
      setDob(value);
      toast.error(t(outcome === "parent_required" || outcome === "parent_email_same" ? "auth.pk.parentInvalid" : outcome === "dob_invalid" ? "auth.pk.dobInvalid" : "auth.age.failed"));
    } catch {
      setDob(value);
      toast.error(t("auth.age.failed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AlertDialog open>
      <AlertDialogContent className="max-w-md">
        <AlertDialogHeader>
          <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-full bg-primary/10 text-primary sm:mx-0">
            <ShieldCheck className="h-5 w-5" aria-hidden />
          </div>
          <AlertDialogTitle>{t("auth.age.title")}</AlertDialogTitle>
          <AlertDialogDescription>{t("auth.age.body")}</AlertDialogDescription>
        </AlertDialogHeader>
        <form onSubmit={submit} className="space-y-3.5">
          <div className="space-y-1.5">
            <Label htmlFor="age-sheet-dob" className="text-sm">{t("auth.pk.dob")}</Label>
            <input
              id="age-sheet-dob"
              type="date"
              required
              autoComplete="off"
              value={dob}
              max={new Date().toISOString().slice(0, 10)}
              min="1900-01-01"
              onChange={(e) => setDob(e.target.value)}
              className="h-11 w-full rounded-lg border border-input bg-background px-3 text-sm text-foreground"
            />
          </div>
          {minor && (
            <div className="space-y-1.5 rounded-lg border border-border bg-muted/40 p-3">
              <Label htmlFor="age-sheet-parent" className="text-sm">{t("auth.pk.parentEmail")}</Label>
              <input
                id="age-sheet-parent"
                type="email"
                required
                autoComplete="off"
                value={parentEmail}
                onChange={(e) => setParentEmail(e.target.value)}
                className="h-11 w-full rounded-lg border border-input bg-background px-3 text-sm text-foreground"
              />
              <p className="text-[11px] leading-relaxed text-muted-foreground">
                {t("auth.pk.parentNote")} <Link to="/info/parental-consent" target="_blank" className="underline">{t("auth.pk.parentHow")}</Link>
              </p>
            </div>
          )}
          <p className="text-xs leading-relaxed text-muted-foreground">{t("auth.age.privacy")}</p>
          <Button type="submit" className="h-11 w-full" disabled={busy || !dob}>
            {busy ? t("auth.age.saving") : t("auth.age.cta")}
          </Button>
        </form>
      </AlertDialogContent>
    </AlertDialog>
  );
}
