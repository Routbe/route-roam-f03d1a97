# Blauw vinkje, verificatiekaart en donatiepagina perfect maken

De code uit de overdracht (vinkje-herstel, verificatiekaart, voorbeeldknop) staat al in het project. Dit plan controleert eerst of die echt werkt, en repareert daarna wat nog fout loopt.

## 1. Waarom het blauwe vinkje bij @jdelplanche weg is
- In Neon alleen lezen welke verificatiegegevens @jdelplanche heeft (verified, naam, datum, land, weergave-instellingen). Ik lees geen andere profielen en wijzig niets in de database.
- Die gegevens naast de regel leggen die bepaalt of het vinkje getoond wordt, en de echte oorzaak vastpinnen.
- Regel: een geverifieerd hoofdprofiel (rout.be/handle) toont altijd het blauwe vinkje, zowel na verificatie door het ROUT-team als via Didit. Daarvoor komt er een test.

## 2. Verificatiekaart (popover)
- Blauw vinkje van 18px naast de naam, met een groot genoeg tikvlak.
- Een tik of klik opent de kaart:
  - kop "Officieel geverifieerd lid"
  - naam en land (bv. "Jona Delplanche · BE")
  - "Geverifieerd in oktober 2026"
  - de methodetekst: door het ROUT-team, of via Didit
- Groen schild: "Geverifieerd mens", zonder naam of land.
- Wit vinkje op een privé-alias: "Gekoppeld aan geverifieerd hoofdaccount", zonder naam of land. Het verschijnt alleen als het profiel dat zelf aanzet (show_verification_on_alias).
- Teksten in alle 4 talen. De kaart moet met het toetsenbord en met Escape te sluiten zijn.

## 3. Donatiepagina in Studio
- Bij wisselen naar de donatiepagina toont "Voorbeeld bekijken" de donatiepagina zelf, op mobiel en op desktop, en niet het hoofdprofiel.
- Controleren dat aanmaken en inschakelen echt een werkende pagina oplevert op /handle/tip en /u/alias/tip. Zonder IBAN krijg je een duidelijke melding: "Voer eerst een geldig IBAN in om je fooienpagina te activeren."
- Controleren dat een anonieme bezoeker de pagina ziet in plaats van "Geen steunpagina".
- De andere extra pagina's (vragen, feedback) nalopen op dezelfde fouten.

## 4. Controle
- De bestaande tests draaien voor het vinkje, de kaart, het voorbeeld en de donatieregels, plus nieuwe tests per regel hierboven.
- De volledige testsuite draaien.
- In de browser op mobiel (390px) en desktop: het vinkje, de kaart openen en sluiten, en het voorbeeld van de donatiepagina.

## Beperkingen
- **Zonder databasesleutels in deze preview laadt een echt profiel hier niet.** Dan test ik met nagebootste profielgegevens, en de echte controle doe jij op je eigen hosting. Een tijdelijke alleen-lezen koppeling kan ook, als je dat wilt.
- Er komen geen wijzigingen aan de database (geen migraties) zonder jouw expliciete GO per bestand.

## Technisch
- Bestanden: legacy-mark.ts, public-identity.server.ts, studio-profile.server.ts, profile-display.ts, ProfileBadge.tsx, ProfileView.tsx, ProfileEditor.tsx, studio-page-preview.ts, tip-page.server.ts, tip-rules.ts, TipPagePanel/ExtraPagesPanel, locales.
- Neon alleen lezen via een catalogusquery op één profiel, met de rechten van rout_app waar mogelijk.
