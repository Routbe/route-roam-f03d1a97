import type { Locale } from "@/lib/i18n";

/** Per-locale titles/descriptions for the support pages' head(); copy mirrors supportfund.<locale>.json. */
const META: Record<"donations" | "partners", Record<Locale, { title: string; description: string }>> = {
  donations: {
    nl: { title: "Steun ROUT · Doneren", description: "Steun ROUT zonder trackers: bankoverschrijving zonder kosten of kaart via Stripe, met een openbaar, ondertekend register van alle bijdragen." },
    en: { title: "Support ROUT · Donate", description: "Support ROUT without trackers: fee-free bank transfer or card via Stripe, with a public, signed ledger of every contribution." },
    fr: { title: "Soutenir ROUT · Faire un don", description: "Soutenez ROUT sans traceurs : virement sans frais ou carte via Stripe, avec un registre public et signé de chaque contribution." },
    de: { title: "ROUT unterstützen · Spenden", description: "Unterstütze ROUT ohne Tracker: gebührenfreie Überweisung oder Karte über Stripe, mit einem öffentlichen, signierten Register aller Beiträge." },
  },
  partners: {
    nl: { title: "ROUT · Partners en infrastructuur", description: "Wie ROUT steunt en welke Europese diensten we gebruiken, met de DNSSEC-status van elk domein." },
    en: { title: "ROUT · Partners and infrastructure", description: "Who supports ROUT and which services we use, with the DNSSEC status of each domain." },
    fr: { title: "ROUT · Partenaires et infrastructure", description: "Qui soutient ROUT et quels services nous utilisons, avec le statut DNSSEC de chaque domaine." },
    de: { title: "ROUT · Partner und Infrastruktur", description: "Wer ROUT unterstützt und welche Dienste wir nutzen, mit dem DNSSEC-Status jeder Domain." },
  },
};

export function supportMeta(page: "donations" | "partners", locale: Locale = "en") {
  const m = META[page][locale] ?? META[page].en;
  return [
    { title: m.title },
    { name: "description", content: m.description },
    { property: "og:title", content: m.title },
    { property: "og:description", content: m.description },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary" },
  ];
}
