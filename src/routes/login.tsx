import i18next from "i18next";
import { createFileRoute } from "@tanstack/react-router";

import AuthNeon from "@/components/imported-pages/AuthNeon";
import { getAuthProviders } from "@/lib/auth-providers.functions";

/**
 * `/login`: one auth card for signing in and creating an account (tabs), with the configured social
 * providers and the passkey button up front and the password route as an inline fold-out.
 */
export const Route = createFileRoute("/login")({
  head: () => ({
    meta: [
      { title: i18next.t("auth.meta.signin") },
      { name: "description", content: i18next.t("auth.meta.description") },
      { property: "og:title", content: i18next.t("auth.meta.signin") },
      { property: "og:description", content: i18next.t("auth.meta.description") },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
    links: [{ rel: "canonical", href: "https://rout.be/login" }],
  }),
  loader: () => getAuthProviders().catch(() => null),
  component: LoginPage,
});

function LoginPage() {
  return <AuthNeon initialMode="signin" initialProviders={Route.useLoaderData()} />;
}
