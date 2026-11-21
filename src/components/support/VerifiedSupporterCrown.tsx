import { useEffect, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { getSupporterPresentation } from "@/lib/support/support.functions";
import { SupporterCrownBadge } from "@/components/profile/SupporterCrownBadge";

/**
 * Supporter crown for a level-1 donor: shown only after the crypto worker verified the
 * member's SD-JWT supporter credential (issuer signature, disclosures, expiry, handle match).
 * A missing, expired or tampered credential renders nothing.
 */
export function VerifiedSupporterCrown({ handle, className, ...card }: { handle: string; className?: string; cardBg?: string; cardBorder?: string; textColor?: string; mutedColor?: string }) {
  const fetchPresentation = useServerFn(getSupporterPresentation);
  const [valid, setValid] = useState(false);

  useEffect(() => {
    let live = true;
    setValid(false);
    void (async () => {
      try {
        const { presentation, publicKey } = await fetchPresentation({ data: { handle } });
        if (!presentation || !publicKey) return;
        const [{ enclave }, { b64uDecode }] = await Promise.all([import("@/lib/crypto-enclave/client"), import("@/lib/support/hybrid-signature")]);
        const r = await enclave.support.verifyVc(presentation, b64uDecode(publicKey.ed25519), publicKey.kid);
        const claimed = typeof r.claims?.["handle"] === "string" ? String(r.claims["handle"]).replace(/^@/, "").toLowerCase() : null;
        if (live && r.valid && claimed === handle.replace(/^@/, "").toLowerCase()) setValid(true);
      } catch {
        /* no crown */
      }
    })();
    return () => {
      live = false;
    };
  }, [handle, fetchPresentation]);

  return valid ? <SupporterCrownBadge color="var(--supporter-gold)" className={className} {...card} /> : null;
}
