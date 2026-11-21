import i18next from "i18next";
import { createFileRoute } from "@tanstack/react-router";

import AuthNeon from "@/components/imported-pages/AuthNeon";
import { getAuthProviders } from "@/lib/auth-providers.functions";

/** `/register`: the same auth card as `/login`, opened on the "create account" tab. */
export const Route = createFileRoute("/register")({
  head: () => ({
    meta: [
      { title: i18next.t("auth.card.registerTitle") },
      { name: "description", content: i18next.t("auth.card.registerDescription") },
      { property: "og:title", content: i18next.t("auth.card.registerTitle") },
      { property: "og:description", content: i18next.t("auth.card.registerDescription") },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
    links: [{ rel: "canonical", href: "https://rout.be/register" }],
  }),
  loader: () => getAuthProviders().catch(() => null),
  component: RegisterPage,
});

function RegisterPage() {
  return <AuthNeon initialMode="signup" initialProviders={Route.useLoaderData()} />;
}
