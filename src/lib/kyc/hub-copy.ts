/** Copy for the Provider Discovery Hub and the Didit modal, in the four UI languages (kept in sync by hub-copy.test.ts). */
import type { DocumentKind, PrivacyRating, ProviderFilter } from "./providers";

export type HubCopy = {
  title: string;
  intro: string;
  search: string;
  searchLabel: string;
  filters: Record<ProviderFilter, string>;
  recommended: string;
  all: string;
  empty: string;
  start: string;
  planned: string;
  inactive: string;
  documents: string;
  docs: Record<DocumentKind, string>;
  ratings: Record<PrivacyRating, string>;
  privacy: string;
  active: string;
  upcoming: string;
  live: string;
  offline: string;
  signInToStart: string;
  page: {
    title: string;
    subtitle: string;
    cta: string;
    ctaDone: string;
    signIn: string;
    badgesTitle: string;
    blue: string;
    blueBody: string;
    green: string;
    greenBody: string;
    crown: string;
    crownBody: string;
  };
  modalTitle: string;
  modalIntro: string;
  modalStart: string;
  modalOpen: string;
  modalWaiting: string;
  modalVerified: string;
  modalFailed: string;
  modalRetry: string;
  modalClose: string;
  modalPopupBlocked: string;
  errors: Record<"not_configured" | "already_verified" | "limit_reached" | "provider_error" | "unauthorized" | "network" | "timeout", string>;
};

export const HUB_COPY: Record<"nl" | "en" | "fr" | "de", HubCopy> = {
  nl: {
    title: "Kies je identiteitsprovider",
    intro: "Verifieer één keer. ROUT bewaart alleen een onomkeerbare vingerafdruk van je document, nooit je naam of nummer.",
    search: "Zoek provider, land of documenttype (bijv. itsme, DigiD, IDnow)...",
    searchLabel: "Zoek een provider",
    filters: { all: "Alle", national_eid: "⚡ Nationale eID", passport_nfc: "🛂 ID-kaart, paspoort & NFC", zero_knowledge: "🛡️ Zero-Knowledge" },
    recommended: "Aanbevolen voor jouw regio",
    all: "Alle providers",
    empty: "Geen provider gevonden. Probeer een andere zoekterm.",
    start: "Start verificatie",
    planned: "Binnenkort",
    inactive: "Nog niet actief",
    documents: "Documenten",
    docs: { passport: "Paspoort", id_card: "Identiteitskaart", residence_permit: "Verblijfsvergunning", driving_licence: "Rijbewijs", eid_app: "eID-app", selfie: "Selfie-check", zk_proof: "Zero-knowledge bewijs" },
    ratings: { eidas_high: "EU eIDAS Hoog", eidas_substantial: "EU eIDAS Substantieel", zk_enclave: "Zero-Knowledge Enclave", biometric: "Biometrisch" },
    privacy: "Eén document geeft één identiteit op heel ROUT, ook via een andere provider.",
    active: "Actieve providers",
    upcoming: "Toekomstige integraties",
    live: "Actief",
    offline: "Nog niet actief",
    signInToStart: "Log in om te starten",
    page: {
      title: "Geverifieerd profiel",
      subtitle: "Verifieer je identiteit om je officiële profiel op rout.be/:handle te bewerken.",
      cta: "Verifieer je",
      ctaDone: "Je bent geverifieerd",
      signIn: "Log eerst in om te verifiëren.",
      badgesTitle: "Drie tekens, strikt gescheiden",
      blue: "Blauw schild — KYC Attested",
      blueBody: "Na een KYC-controle via Didit of eIDAS.",
      green: "Groen schild — Real Human",
      greenBody: "Alleen na een zero-knowledge-bewijs.",
      crown: "Gouden kroon — Supporter",
      crownBody: "Steun aan ROUT, nooit een identiteitsbewijs.",
    },
    modalTitle: "Verifiëren met Didit",
    modalIntro: "Je scant je identiteitskaart, paspoort of verblijfsvergunning (bij voorkeur de chip) en doet een korte selfie-check bij Didit. ROUT ontvangt geen foto's en bewaart geen naam of documentnummer.",
    modalStart: "Start documentscan",
    modalOpen: "Open Didit opnieuw",
    modalWaiting: "We wachten op het resultaat van Didit. Je mag dit venster openlaten.",
    modalVerified: "Je identiteit is geverifieerd. Het blauwe schildje staat nu op je profiel.",
    modalFailed: "De verificatie is niet gelukt of afgebroken.",
    modalRetry: "Opnieuw proberen",
    modalClose: "Sluiten",
    modalPopupBlocked: "Je browser blokkeerde het nieuwe venster. Gebruik de knop hieronder.",
    errors: {
      not_configured: "Documentscan is nog niet actief.",
      already_verified: "Je account is al geverifieerd.",
      limit_reached: "De maandelijkse limiet voor documentscans is bereikt. Probeer volgende maand opnieuw.",
      provider_error: "Didit reageert niet. Probeer later opnieuw.",
      unauthorized: "Log opnieuw in om verder te gaan.",
      network: "Geen verbinding. Controleer je internet en probeer opnieuw.",
      timeout: "We hebben nog geen resultaat. Kom later terug; je status wordt automatisch bijgewerkt.",
    },
  },
  en: {
    title: "Choose your identity provider",
    intro: "Verify once. ROUT keeps only an irreversible fingerprint of your document, never your name or number.",
    search: "Search provider, country or document type (e.g. itsme, DigiD, IDnow)...",
    searchLabel: "Search a provider",
    filters: { all: "All", national_eid: "⚡ National eID", passport_nfc: "🛂 ID card, passport & NFC", zero_knowledge: "🛡️ Zero-Knowledge" },
    recommended: "Recommended for your region",
    all: "All providers",
    empty: "No provider found. Try another search.",
    start: "Start verification",
    planned: "Coming soon",
    inactive: "Not active yet",
    documents: "Documents",
    docs: { passport: "Passport", id_card: "Identity card", residence_permit: "Residence permit", driving_licence: "Driving licence", eid_app: "eID app", selfie: "Selfie check", zk_proof: "Zero-knowledge proof" },
    ratings: { eidas_high: "EU eIDAS High", eidas_substantial: "EU eIDAS Substantial", zk_enclave: "Zero-Knowledge Enclave", biometric: "Biometric" },
    privacy: "One document gives one identity across ROUT, also through another provider.",
    active: "Active providers",
    upcoming: "Upcoming integrations",
    live: "Active",
    offline: "Not active yet",
    signInToStart: "Sign in to start",
    page: {
      title: "Verified profile",
      subtitle: "Verify your identity to edit your official profile at rout.be/:handle.",
      cta: "Verify now",
      ctaDone: "You are verified",
      signIn: "Sign in first to verify.",
      badgesTitle: "Three marks, strictly separate",
      blue: "Blue shield — KYC Attested",
      blueBody: "After a KYC check via Didit or eIDAS.",
      green: "Green shield — Real Human",
      greenBody: "Only after a zero-knowledge proof.",
      crown: "Gold crown — Supporter",
      crownBody: "Support for ROUT, never proof of identity.",
    },
    modalTitle: "Verify with Didit",
    modalIntro: "You scan your identity card, passport or residence permit (the chip if possible) and take a short selfie check at Didit. ROUT receives no photos and stores no name or document number.",
    modalStart: "Start ID scan",
    modalOpen: "Open Didit again",
    modalWaiting: "Waiting for Didit's result. You can keep this window open.",
    modalVerified: "Your identity is verified. The blue shield now shows on your profile.",
    modalFailed: "The verification did not succeed or was cancelled.",
    modalRetry: "Try again",
    modalClose: "Close",
    modalPopupBlocked: "Your browser blocked the new window. Use the button below.",
    errors: {
      not_configured: "ID scan is not active yet.",
      already_verified: "Your account is already verified.",
      limit_reached: "This month's ID scan limit has been reached. Try again next month.",
      provider_error: "Didit is not responding. Try again later.",
      unauthorized: "Sign in again to continue.",
      network: "No connection. Check your internet and try again.",
      timeout: "No result yet. Come back later; your status updates automatically.",
    },
  },
  fr: {
    title: "Choisissez votre fournisseur d'identité",
    intro: "Vérifiez une seule fois. ROUT ne garde qu'une empreinte irréversible de votre document, jamais votre nom ni votre numéro.",
    search: "Cherchez un fournisseur, un pays ou un type de document (p. ex. itsme, DigiD, IDnow)...",
    searchLabel: "Chercher un fournisseur",
    filters: { all: "Tous", national_eid: "⚡ eID nationale", passport_nfc: "🛂 Carte d'identité, passeport & NFC", zero_knowledge: "🛡️ Zero-Knowledge" },
    recommended: "Recommandé pour votre région",
    all: "Tous les fournisseurs",
    empty: "Aucun fournisseur trouvé. Essayez une autre recherche.",
    start: "Commencer la vérification",
    planned: "Bientôt",
    inactive: "Pas encore actif",
    documents: "Documents",
    docs: { passport: "Passeport", id_card: "Carte d'identité", residence_permit: "Titre de séjour", driving_licence: "Permis de conduire", eid_app: "App eID", selfie: "Contrôle selfie", zk_proof: "Preuve à divulgation nulle" },
    ratings: { eidas_high: "EU eIDAS Élevé", eidas_substantial: "EU eIDAS Substantiel", zk_enclave: "Enclave Zero-Knowledge", biometric: "Biométrique" },
    privacy: "Un document donne une seule identité sur ROUT, même via un autre fournisseur.",
    active: "Fournisseurs actifs",
    upcoming: "Intégrations à venir",
    live: "Actif",
    offline: "Pas encore actif",
    signInToStart: "Connectez-vous pour commencer",
    page: {
      title: "Profil vérifié",
      subtitle: "Vérifiez votre identité pour modifier votre profil officiel sur rout.be/:handle.",
      cta: "Vérifiez-vous",
      ctaDone: "Vous êtes vérifié",
      signIn: "Connectez-vous d'abord pour vérifier.",
      badgesTitle: "Trois marques, strictement séparées",
      blue: "Bouclier bleu — KYC Attested",
      blueBody: "Après un contrôle KYC via Didit ou eIDAS.",
      green: "Bouclier vert — Real Human",
      greenBody: "Uniquement après une preuve à divulgation nulle.",
      crown: "Couronne dorée — Supporter",
      crownBody: "Un soutien à ROUT, jamais une preuve d'identité.",
    },
    modalTitle: "Vérifier avec Didit",
    modalIntro: "Vous scannez votre carte d'identité, passeport ou titre de séjour (la puce si possible) et faites un court contrôle selfie chez Didit. ROUT ne reçoit aucune photo et ne garde ni nom ni numéro de document.",
    modalStart: "Commencer le scan",
    modalOpen: "Rouvrir Didit",
    modalWaiting: "Nous attendons le résultat de Didit. Vous pouvez laisser cette fenêtre ouverte.",
    modalVerified: "Votre identité est vérifiée. Le bouclier bleu s'affiche sur votre profil.",
    modalFailed: "La vérification a échoué ou a été interrompue.",
    modalRetry: "Réessayer",
    modalClose: "Fermer",
    modalPopupBlocked: "Votre navigateur a bloqué la nouvelle fenêtre. Utilisez le bouton ci-dessous.",
    errors: {
      not_configured: "Le scan de document n'est pas encore actif.",
      already_verified: "Votre compte est déjà vérifié.",
      limit_reached: "La limite mensuelle de scans est atteinte. Réessayez le mois prochain.",
      provider_error: "Didit ne répond pas. Réessayez plus tard.",
      unauthorized: "Reconnectez-vous pour continuer.",
      network: "Pas de connexion. Vérifiez votre internet et réessayez.",
      timeout: "Pas encore de résultat. Revenez plus tard ; votre statut se met à jour automatiquement.",
    },
  },
  de: {
    title: "Wähle deinen Identitätsanbieter",
    intro: "Einmal verifizieren. ROUT speichert nur einen unumkehrbaren Fingerabdruck deines Dokuments, nie deinen Namen oder deine Nummer.",
    search: "Anbieter, Land oder Dokumenttyp suchen (z. B. itsme, DigiD, IDnow)...",
    searchLabel: "Anbieter suchen",
    filters: { all: "Alle", national_eid: "⚡ Nationale eID", passport_nfc: "🛂 Ausweis, Reisepass & NFC", zero_knowledge: "🛡️ Zero-Knowledge" },
    recommended: "Empfohlen für deine Region",
    all: "Alle Anbieter",
    empty: "Kein Anbieter gefunden. Versuche einen anderen Suchbegriff.",
    start: "Verifizierung starten",
    planned: "Demnächst",
    inactive: "Noch nicht aktiv",
    documents: "Dokumente",
    docs: { passport: "Reisepass", id_card: "Personalausweis", residence_permit: "Aufenthaltstitel", driving_licence: "Führerschein", eid_app: "eID-App", selfie: "Selfie-Prüfung", zk_proof: "Zero-Knowledge-Beweis" },
    ratings: { eidas_high: "EU eIDAS Hoch", eidas_substantial: "EU eIDAS Substanziell", zk_enclave: "Zero-Knowledge-Enklave", biometric: "Biometrisch" },
    privacy: "Ein Dokument ergibt eine Identität auf ganz ROUT, auch über einen anderen Anbieter.",
    active: "Aktive Anbieter",
    upcoming: "Kommende Integrationen",
    live: "Aktiv",
    offline: "Noch nicht aktiv",
    signInToStart: "Zum Starten anmelden",
    page: {
      title: "Verifiziertes Profil",
      subtitle: "Verifiziere deine Identität, um dein offizielles Profil auf rout.be/:handle zu bearbeiten.",
      cta: "Jetzt verifizieren",
      ctaDone: "Du bist verifiziert",
      signIn: "Melde dich zuerst an, um zu verifizieren.",
      badgesTitle: "Drei Zeichen, strikt getrennt",
      blue: "Blaues Schild — KYC Attested",
      blueBody: "Nach einer KYC-Prüfung über Didit oder eIDAS.",
      green: "Grünes Schild — Real Human",
      greenBody: "Nur nach einem Zero-Knowledge-Beweis.",
      crown: "Goldene Krone — Supporter",
      crownBody: "Unterstützung für ROUT, nie ein Identitätsnachweis.",
    },
    modalTitle: "Mit Didit verifizieren",
    modalIntro: "Du scannst deinen Ausweis, Reisepass oder Aufenthaltstitel (wenn möglich den Chip) und machst eine kurze Selfie-Prüfung bei Didit. ROUT erhält keine Fotos und speichert weder Namen noch Dokumentnummer.",
    modalStart: "Ausweis-Scan starten",
    modalOpen: "Didit erneut öffnen",
    modalWaiting: "Wir warten auf das Ergebnis von Didit. Du kannst dieses Fenster offen lassen.",
    modalVerified: "Deine Identität ist verifiziert. Das blaue Schild ist jetzt auf deinem Profil.",
    modalFailed: "Die Verifizierung ist fehlgeschlagen oder wurde abgebrochen.",
    modalRetry: "Erneut versuchen",
    modalClose: "Schließen",
    modalPopupBlocked: "Dein Browser hat das neue Fenster blockiert. Nutze die Schaltfläche unten.",
    errors: {
      not_configured: "Der Ausweis-Scan ist noch nicht aktiv.",
      already_verified: "Dein Konto ist bereits verifiziert.",
      limit_reached: "Das Monatslimit für Ausweis-Scans ist erreicht. Versuche es nächsten Monat erneut.",
      provider_error: "Didit antwortet nicht. Versuche es später erneut.",
      unauthorized: "Melde dich erneut an, um fortzufahren.",
      network: "Keine Verbindung. Prüfe dein Internet und versuche es erneut.",
      timeout: "Noch kein Ergebnis. Komm später zurück; dein Status aktualisiert sich automatisch.",
    },
  },
};

export function hubCopy(language: string | null | undefined): HubCopy {
  const l = (language ?? "nl").slice(0, 2) as keyof typeof HUB_COPY;
  return HUB_COPY[l] ?? HUB_COPY.nl;
}
