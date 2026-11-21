# Plan: ROUT verder bouwen volgens het overdrachtsdossier

Alles blijft op je eigen infrastructuur (Neon, Scaleway, eigen host). Geen Lovable Cloud. Antwoorden in het Nederlands.

## Wat ik al gecontroleerd heb
- De "bouwfout" uit het dossier is al opgelost: de import van `ageFloorFromVector` staat in de code (regel 23).
- Neon staat op 0289. 0290 staat klaar in `db-pending/`, met `age_floor` (een geheel getal tot 21). Er zitten geen DNSSEC-kolommen in en geen bitvector `age_threshold_vector`.
- `getProfileShareUrl` bestaat nog niet. De schakelaar `show_verification_on_alias` ook niet.
- De dossiers spreken elkaar op een paar punten tegen. Zie "Keuzes" hieronder.

## Stap 1: Nulmeting (niets wijzigen)
- Volledige testsuite en typecheck draaien en de resultaten noteren.

## Stap 2: Migratie 0290 op Neon (je GO 0290 staat in je bericht)
- Eerst de replaytest van 0290 lokaal laten slagen.
- Dan het bestand exact zoals het is uitrollen: controle op checksum, 0289 moet eerst geregistreerd zijn, en het wordt in dezelfde transactie vastgelegd in `schema_migrations`.
- Daarna de geschiedenis- en structuurcontrole opnieuw draaien en `CODE_SCHEMA_LEVEL` op 0290 zetten.
- Ik rol 0290 uit zoals het nu geschreven is (`age_floor`). DNSSEC-kolommen of een bitvector vallen daarbuiten: die vragen een nieuwe migratie 0291 en dus een nieuwe GO.

## Stap 3: Canonieke deellinks
- `getProfileShareUrl` in `src/lib/profile-url.ts`:
  - geverifieerd hoofdprofiel: `https://rout.be/<handle>`
  - alias: `https://rout.be/u/<alias>`
  - workspace: `https://rout.be/w/<slug>`
- De knoppen "Kopieer link" (met bevestiging) en "Delen" (met kopiëren als terugval) gebruiken deze functie in Studio, Dashboard en de voorbeeldkaarten.
- Tests per regel.

## Stap 4: Badges
- Kleine badges naast de naam: blauw schild, groen schild, kroon, Early Believer.
- Het blauwe schild is verplicht zichtbaar op het geverifieerde hoofdprofiel.
- Op een alias toont het schild alleen als de nieuwe instelling "Verificatiebadge op je aliasprofiel" aan staat. Standaard staat die uit. Ik bewaar ze in de bestaande `display_prefs`, dus zonder databasewijziging.
- Openbare profielen tonen alleen behaalde badges: geen slotjes of lege houders.
- Grote stempels en diploma's verschijnen alleen bij Widgets en in `BadgeEmblem`.
- Tests per regel.

## Stap 5: Leeftijdscope en firewall voor minderjarigen
- `age_gate?min_age=N` (13 tot 21, standaard 18). Het antwoord bevat alleen `{ age_verified, min_age }`.
- Toestemmingsscherm en `/console/docs` krijgen een keuzemenu voor de leeftijd.
- Firewall voor wie jonger is dan 18: `legal_identity` en alle persoonsgegevens worden altijd geschrapt.
- Dit draait op `age_floor` uit 0290.

## Stap 6: Inloggen
- Fix voor touchtoestellen bij "Extra voorzichtig typen": een gewoon wachtwoordveld, zodat het toetsenbord meteen opent.
- Eén inlogkaart voor aanmelden en registreren, met Google-, GitHub- en passkeyknoppen. Het wachtwoord klapt binnen dezelfde kaart open.

## Stap 7: Afronden
- Testsuite en typecheck opnieuw draaien.
- Deellinks en badges controleren in de voorbeeldweergave.
- `roadmap.md` en de appendix van `docs/HANDOVER.md` bijwerken.

## Niet in dit plan (wacht op jou)
- **Leeftijdsvraag na Google/GitHub met verzegelde geboortedatum (`dob_sealed`):** dat botst met je regel "geboortedatum nooit opslaan" en vraagt een databasewijziging. Ik wacht op jouw keuze.
- **PAdES-LTA via een gekwalificeerde dienst (CSC):** pas als je een dienst kiest en sleutels hebt.
- **A1-backfill, uitrol naar productie en het eigenaarswachtwoord vervangen:** dat zijn acties op je eigen server.

## Technisch
- Neon-wijzigingen lopen alleen via de koppeling voor dit gesprek, met de inhoud van het bestand ongewijzigd. Er worden geen sleutels in het project gezet.
- Elke nieuwe definer gebruikt `search_path = pg_catalog, pg_temp` en REVOKE, en de vier talen blijven gelijk.
