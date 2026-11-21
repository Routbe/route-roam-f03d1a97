# Plan: 2027 Sovereign Auth Card (/login en /register)

Dit plan gaat over Taak 1 uit het overdrachtsdossier. Taak 2 (voorbeeld van de donatiepagina in Studio) en Taak 3 (acties voor de eigenaar) volgen in een apart plan, nadat deze stap af is.

## Wat de bezoeker ziet (van boven naar beneden)

```text
+------------------------------------------+
| [ Inloggen | Account aanmaken ]          |  compacte keuzeknop
|                                          |
| Welkom terug   /   Account aanmaken      |  één titel per tab
|                                          |
| [ (vingerafdruk) Inloggen met passkey ]  |  grote knop, volle breedte, zachte glow
|                                          |
| ---------- of met je account ----------  |
| (G) (GitHub) (GitLab) (Mastodon) (Bsky)  |  één rij iconen, elk min. 44x44 px
|      (ROUT ID) (Infomaniak)              |  loopt netjes door op 375 px
|                                          |
| E-mailadres [_____________________]      |  autocomplete="username webauthn"
| [ Verder met e-mail ]                    |
|                                          |
| Geen toegang meer tot je e-mail?         |  enige link onderaan
+------------------------------------------+
```

- **Keuzeknop:** het label "Welkom bij ROUT" verdwijnt uit de keuzeknop. Die toont alleen nog "Inloggen" en "Account aanmaken".
- **Passkey:** de passkey staat alleen nog als grote knop bovenaan. Het passkey-icoon verdwijnt uit de rij met providers.
- **Providers:** de andere providers staan rustig en gedempt in één rij. Google houdt zijn originele kleuren, omdat Google dat verplicht stelt. De rest is in één kleur.
- **Onderaan:** de dubbele link "Account aanmaken" verdwijnt. Alleen "Geen toegang meer tot je e-mail?" blijft staan.
- **Tab "Account aanmaken":** dezelfde opbouw. Na "Verder met e-mail" volgen de bestaande velden (naam, geboortedatum, ouder-e-mail, toestemming) en daarna het aanmaken van de passkey. De bestaande regels voor aanmelden blijven precies zoals ze zijn.
- **Andere schermen blijven ongewijzigd:** herstel, reset, het adminportaal, de sociale onboarding (leeftijd en passkey) en de tweede inlogstap.

## Nieuwe pagina /register

`/register` opent dezelfde inlogkaart, maar direct op de tab "Account aanmaken", met een eigen paginatitel en omschrijving. `/signup` (de uitnodigingslink met `?ref=`) blijft werken zoals nu.

## Vertalingen

Nieuwe en aangepaste teksten komen in NL, EN, FR en DE:
- "Welkom terug"
- "Inloggen met passkey"
- "of met je account"
- "Verder met e-mail"
- "Geen toegang meer tot je e-mail?"

## Controle

- **Tests:** nieuwe tests controleren dat:
  - de passkey niet meer in de providerrij staat;
  - de keuzeknop alleen de twee labels toont;
  - de titel wisselt per tab;
  - het e-mailveld `username webauthn` heeft;
  - er onderaan geen "Account aanmaken"-link meer staat;
  - `/register` op de tab "Account aanmaken" opent.
- **Bestaande tests:** de hele bestaande testsuite moet groen blijven.
- **Browser:** /login en /register bekijken op 375 px en op desktop, op beide tabs. Daarbij controleren dat er niets overloopt of wegvalt en dat elke knop minstens 44x44 px is.

## Technische details

- **Kaart:** `src/components/imported-pages/AuthNeon.tsx`.
  - Keuzeknop: tablabel van `auth.ui.title` naar een nieuwe sleutel `auth.ui.tab.signin`.
  - Titel: `auth.ui.title` wordt "Welkom terug".
  - Volgorde in de kaart: passkey-knop, scheidingslijn, providers, e-mail, knop, footer.
  - De prop `passkey={...}` wordt weggehaald bij `PublicProviderSignIn`.
  - De footerlink "Account aanmaken" wordt verwijderd.
  - Bestaande logica blijft ongewijzigd: conditional UI, Altcha, signup-ticket en `?onboard=social`.
- **Providerrij:** `src/components/auth/PublicProviderSignIn.tsx` krijgt een compacte icoonvariant (een rij met `h-11 w-11`, gedempte stijl). De optionele `passkey`-prop blijft bestaan, zodat andere plekken niet breken.
- **Nieuwe route:** `src/routes/register.tsx` met `AuthNeon initialMode="signup"`, dezelfde loader (`getAuthProviders`), een eigen `head()` en canonical `https://rout.be/register`.
- **Vertalingen:** sleutels in `src/locales/{nl,en,fr,de}.json` en/of `src/locales/auth/`, zodat ze in alle vier de talen gelijk staan.
- **Tests:** naast de bestaande auth-tests in `src/test/`, met Vitest.
- **Niet aangeraakt:** database, migraties, server-auth en geheimen. Er komt niets bij Lovable Cloud.
