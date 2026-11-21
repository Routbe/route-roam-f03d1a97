/**
 * Official provider marks stored in this repository (public/logos), taken from each provider's
 * own website or app listing. Paths are same-origin only: the hub never loads an image from a
 * third-party server. Providers without an entry (no single official mark, e.g. eID / eIDAS)
 * get the neutral Building2 fallback.
 */
export const PROVIDER_LOGO_FILES: Readonly<Record<string, string>> = {
  itsme: "/logos/itsme.png",
  digid: "/logos/digid.svg",
  france_identite: "/logos/france-identite.svg",
  mitid: "/logos/mitid.png",
  cie: "/logos/cie.svg",
  idnow: "/logos/idnow.png",
  shufti_pro: "/logos/shufti-pro.svg",
  trulioo: "/logos/trulioo.svg",
  world_id: "/logos/world-id.svg",
};

/** Providers drawn as inline vector components instead of a file. */
export const INLINE_PROVIDER_LOGOS = ["didit", "w_identity"] as const;
