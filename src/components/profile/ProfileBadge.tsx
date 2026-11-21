import { useEffect, useRef, useState } from "react";
import { KeyRound, Loader2, ShieldAlert, ShieldCheck } from "lucide-react";
import { VerifiedIdentityIcon } from "./VerifiedIdentityIcon";
import { CreatorBadgeIcon } from "@/components/profile/CreatorBadgeIcon";
import { BadgeBackdrop } from "@/components/profile/BadgeBackdrop";
import { DomainBadgeIcon } from "@/components/profile/DomainBadgeIcon";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { monthYear } from "@/components/profile/VerifiedBadgePopover";
import { useI18n } from "@/lib/i18n";
import {
  formatBadgeName,
  type BadgeBackdrop as BadgeBackdropStyle,
  type BadgeNameFormat,
  type BadgeType,
} from "@/lib/profile-display";
import type { BadgeAttestation } from "@/lib/identity/badge-attestation";
import type { BadgeSignatureState } from "@/lib/identity/badge-verify";

/**
 * Eén badge, drie betekenissen — vrij te kiezen (of weg te laten):
 *
 *  • `verified` — blauw schild "KYC Attested": uitsluitend na een KYC-attestatie (Didit/eIDAS)
 *  • `human`    — groen schild "Real Human": uitsluitend na een zero-knowledge-bewijs
 *  • `domain`   — zwarte domeinbadge: domeinnaam geclaimd via de DNS-zone
 *  • `none`     — geen badge
 *
 * Het achterzetsel (gloed, sticker, randje) houdt het vinkje zichtbaar op elke
 * achtergrond, ook een zwarte.
 */
export function ProfileBadge({
  type,
  method,
  verifiedAt,
  legalName,
  country,
  domain,
  nameFormat = "full",
  backdrop = "none",
  backdropColor,
  size = "md",
  cardBg,
  cardBorder,
  textColor,
  mutedColor,
  attestation,
  handle,
}: {
  /** `linked`: wit vinkje op een privé-alias — geverifieerde mens, zonder naam of land. */
  type: BadgeType | "linked";
  /** How the blue mark was earned: ROUT team review or Didit KYC; picks the card's validation text. */
  method?: "team" | "didit" | null;
  verifiedAt?: string | null;
  legalName?: string | null;
  /** Landcode bij het blauwe vinkje, bv. "BE". */
  country?: string | null;
  /** Geclaimde domeinnaam bij de zwarte domeinbadge. */
  domain?: string | null;
  nameFormat?: BadgeNameFormat;
  backdrop?: BadgeBackdropStyle;
  backdropColor?: string | null;
  size?: "sm" | "md";
  cardBg?: string;
  cardBorder?: string;
  textColor?: string;
  mutedColor?: string;
  /** Ed25519 attestation over this card (blue mark only); checked in the crypto worker on open. */
  attestation?: BadgeAttestation | null;
  /** Profile handle the attestation is bound to. */
  handle?: string | null;
}) {
  const { t, locale } = useI18n();
  const [open, setOpen] = useState(false);
  const [sig, setSig] = useState<BadgeSignatureState | null>(null);
  const checked = useRef<string | null>(null);
  const signed = type === "verified" && !!attestation;

  // The signature is checked once per attestation, the first time the card opens.
  useEffect(() => {
    if (!open || !signed || !attestation || checked.current === attestation.sig) return;
    checked.current = attestation.sig;
    let live = true;
    setSig("checking");
    void import("@/lib/identity/badge-verify")
      .then(({ verifyBadgeAttestation }) =>
        verifyBadgeAttestation(attestation, { handle, method: method ?? null, name: legalName, country, verifiedAt }),
      )
      .catch(() => "unavailable" as const)
      .then((state) => {
        if (live) setSig(state);
      });
    return () => {
      live = false;
      if (checked.current === attestation.sig) checked.current = null;
    };
  }, [open, signed, attestation, handle, method, legalName, country, verifiedAt]);

  if (type === "none") return null;

  const on = monthYear(verifiedAt, locale || "nl");
  // Micro-badge in de kop: 18 px, met een tikzone van 44 px (tap-wide).
  const iconSize = size === "md" ? "h-6 w-6" : "h-[1.125rem] w-[1.125rem]";

  const title =
    type === "linked"
      ? t("badges.linkedCardTitle")
      : type === "human"
      ? t("badges.humanCardTitle")
      : type === "domain"
        ? t("badges.businessTitle", { domain: domain ? ` — ${domain}` : "" })
        : type === "influencer"
          ? t("badges.creatorTitle")
          : t("badges.officialMemberTitle");

  const body =
    type === "linked"
      ? t("badges.linkedExplanation")
      : type === "human"
      ? t("badges.humanExplanation")
      : type === "domain"
        ? t("badges.businessExplanation")
        : type === "influencer"
          ? t("badges.creatorExplanation")
          : // One validation sentence for every blue mark; the method line above says how it was earned.
            t("badges.officialMemberBody");

  // Method line under the name: how this mark was earned.
  const methodLine =
    type === "linked"
      ? t("badges.methodLinked")
      : type === "human"
        ? t("badges.methodZk")
        : type === "verified" && method === "team"
          ? t("badges.methodTeam")
          : type === "verified" && method === "didit"
            ? t("badges.methodDidit")
            : "";
  const privacyLine = type === "linked" ? t("badges.linkedAnonymous") : type === "human" ? t("badges.zkNoData") : "";

  const icon = (extra = "") =>
    type === "linked" ? (
      <VerifiedIdentityIcon className={`${iconSize} !text-identity-linked drop-shadow-[0_0_1px_var(--identity-linked-edge)] ${extra}`} />
    ) : type === "domain" ? (
      <DomainBadgeIcon className={`${iconSize} ${extra}`} />
    ) : type === "human" ? (
      <ShieldCheck className={`${iconSize} text-identity-human ${extra}`} aria-hidden />
    ) : type === "influencer" ? (
      <CreatorBadgeIcon className={`${iconSize} ${extra}`} />
    ) : (
      <VerifiedIdentityIcon className={`${iconSize} ${extra}`} />
    );

  // Het blauwe vinkje toont bij het openklikken altijd de echte, volledige naam
  // en het land: de weergavenaam mag vrij zijn, de identiteit erachter niet.
  const shownName =
    type === "verified"
      ? (legalName ?? "").trim()
        ? formatBadgeName((legalName ?? "").trim(), nameFormat)
        : ""
      : "";
  const shownCountry = type === "verified" ? (country ?? "").trim().toUpperCase() : "";

  const muted = mutedColor ? { color: mutedColor } : undefined;

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          type="button"
          aria-label={title}
          title={title}
          aria-haspopup="dialog"
          className="tap-badge inline-flex items-center rounded-full transition-[opacity,transform] duration-150 hover:opacity-70 active:scale-90 focus:outline-none focus-visible:ring-2 focus-visible:ring-current focus-visible:ring-offset-2 motion-reduce:transition-none"
        >
          <BadgeBackdrop variant={backdrop} color={backdropColor} size={size}>
            {icon()}
          </BadgeBackdrop>
        </button>
      </PopoverTrigger>
      <PopoverContent
        align="center"
        aria-label={title}
        className="w-72 max-w-[calc(100vw-1.5rem)] rounded-xl border p-4 text-left duration-200 ease-out data-[state=closed]:duration-150 motion-reduce:animate-none"
        style={
          cardBg ? { background: cardBg, borderColor: cardBorder, color: textColor } : undefined
        }
      >
        <div className="flex items-start gap-2">
          {type === "verified" ? (
            <span className="relative mt-0.5 inline-flex shrink-0" data-testid="badge-card-shield">
              <span
                aria-hidden
                className="absolute inset-0 rounded-full bg-identity-verified/40 motion-safe:animate-badge-shield-ring motion-reduce:hidden"
              />
              <VerifiedIdentityIcon className="relative h-6 w-6 motion-safe:animate-badge-shield-pop" />
            </span>
          ) : (
            <span className="mt-0.5 shrink-0">{icon()}</span>
          )}
          <div className="space-y-1">
            <p className="text-sm font-semibold leading-tight">{title}</p>
            {(shownName || shownCountry) && (
              <p
                className="text-xs font-medium"
                style={mutedColor ? { color: mutedColor } : undefined}
              >
                {[shownName, shownCountry].filter(Boolean).join(" · ")}
              </p>
            )}
            {methodLine && (
              <p className="text-xs font-medium" style={mutedColor ? { color: mutedColor } : undefined}>
                {methodLine}
              </p>
            )}
            {type === "verified" && on && (
              <p className="text-xs" style={mutedColor ? { color: mutedColor } : undefined}>
                {t("profile.verified_on")} {on}
              </p>
            )}
            <p
              className="text-xs leading-relaxed"
              style={mutedColor ? { color: mutedColor } : undefined}
            >
              {body}
            </p>
            {privacyLine && (
              <p className="text-xs leading-relaxed" style={mutedColor ? { color: mutedColor } : undefined}>
                {privacyLine}
              </p>
            )}
            {signed && sig && (
              <p
                className="mt-1 inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-medium"
                style={cardBorder ? { borderColor: cardBorder } : undefined}
                role="status"
                aria-live="polite"
                data-signature={sig}
              >
                {sig === "checking" ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
                ) : sig === "valid" || sig === "valid_pq" ? (
                  <KeyRound className="h-3.5 w-3.5 text-identity-verified" aria-hidden />
                ) : (
                  <ShieldAlert className={`h-3.5 w-3.5 ${sig === "invalid" ? "text-destructive" : ""}`} aria-hidden />
                )}
                <span style={sig === "valid" || sig === "valid_pq" ? undefined : muted}>
                  {sig === "checking"
                    ? t("badges.signatureChecking")
                    : sig === "valid_pq"
                      ? t("badges.signatureValidPq")
                      : sig === "valid"
                      ? t("badges.signatureValid")
                      : sig === "invalid"
                        ? t("badges.signatureInvalid")
                        : t("badges.signatureUnavailable")}
                </span>
              </p>
            )}
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
}
