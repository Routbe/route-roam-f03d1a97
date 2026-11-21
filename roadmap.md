# Roadmap

## ROUT Card tap (NTAG 424 DNA) — Batch 1
- [x] db/0245_sdm_tap.sql (EXPAND): fleet MetaRead key, batches, cards by uid_hash, tap attempts, tap grants, RPCs for rout_app only
- [x] sdm-verifier.ts: AN10922 diversification, PICCData decrypt, uid index, constant-time compares + NXP vectors
- [x] sdm-tap.server.ts + vault port methods; PGlite tests as rout_app
- [x] /t public tap page (PICCData only, no card id), "Authentic ROUT Card" badge, replaceState clears query
- [x] schema level 0245, snapshot + db types
## ROUT Card tap — later batches
- [x] Card tap step-up: "ROUT Card" method in the step-up dialog (Web NFC on Android, /t fallback for iPhone and other devices), accepted for card_reveal, card_lifecycle and general sensitive actions
- [x] db/0253 card revoke + 0250 audit fix (EXPAND, live on Neon)
- [x] Blocking or replacing the ROUT card revokes the member's physical cards (db/0253)
- [x] Test on real hardware: Android Chrome NFC scan, iPhone tap via /t, desktop + signed-in phone (owner-tested)
- [x] /t asks "Ja, ik bevestig" before a tap completes an open card step-up (an unrelated tap can no longer approve a request from another session)
- [x] Re-test the /t confirm button on iPhone (changed after the owner's hardware test; owner-confirmed 2026-11-13)
- [x] Admin batch screen (/admin/cards): create, station config export, manifest import; member activation (db/0246, live on Neon)

## Developer console
- [x] Billing page: plan without billing account, live limits from the enforced rules, fair use + link to API terms (nl/en/fr/de)

## Auth
- [x] Passkey-only registration enforced server-side (user.create hook + bridge refuses members without a passkey)

## Workspace Studio
- [x] New profile photo does not save in Workspace Studio: Studio uploads as workspace-logo, /api/public/avatar reads via rout_public_avatar (db/0251 live on Neon, public read verified)
- [x] Workspace logos: prune keeps every photo still in use (db/0252 rout_prune_avatar_uploads, live on Neon)
- [x] Workspace conversion: workspaces.avatar_url set from the live design's photo (conversionWorkspaceLogo)
- [ ] Converted workspace logo stored in the Neon fallback still belongs to the retired login (cascade on a hard user delete); copy it into the workspace owner's uploads if hard deletes are ever enabled
- [x] "ROUT OS v2.5 Alle systemen operationeel" overlaps bottom preview buttons on phone; check similar overlaps

- [x] 0247 hardening (live on Neon, verified): constant-time activation-hash compare, SERIALIZABLE + retry for consume/activate, deny-all RLS on vault_enclave (review before apply)
- [x] Station file v2: correct NDEF offsets, encrypted UID+counter, ChangeFileSettings payload
- [x] Key delivery to the personalisation station: HPKE P-256 sealed bundle (0248 live)
- [x] Station registry (0248) + HPKE-wrapped batch key export on /admin/cards, logged via mark_sdm_batch_exported
- [x] db/0249 (drop station-less export marker) moved into db/ after production reported 0248
- [x] db/0250 card tap as step-up factor (EXPAND, live on Neon)

## Beveiligingsmelding agenda's
- [x] Agenda toevoegen/verversen: max 20 per lid per uur (gedeelde teller, faalt dicht), melding in nl/en/fr/de + test

## Admin portal and Studio routing
- [x] Admin portal refuses non-admins in the UI itself (adminAccessDecision + AdminForbidden screen, nl/en/fr/de); server checks unchanged
- [x] /studio/booking lands on the bookings page: /studio accepts page=booking (src/lib/studio-page-param.ts) and Studio opens bookings from that routed value
- [ ] Signed-in click-through of the admin refusal screen and the bookings page: owner verifies on the Vercel deploy (no DATABASE_URL requested for the preview)

## Migratie-synchronisatie (2026-11-13)
- [x] Stap 1a: alleen-lezen analyse van 95/0169/0209/91 (verslag aan eigenaar)
- [x] Stap 1b: archief in db-archive/, erkende vingerafdrukken in scripts/migration-history-allowlist.ts, controle scripts/migration-history-check.ts (Neon: 251 rijen, 0 afwijkingen)
- [x] 0254: rout_pairwise_register op search_path = pg_catalog (live op Neon, gecontroleerd)
- [x] Afdwinging SECURITY DEFINER search_path: krimpende overgangslijst, lint + bewaking in beide runners vanaf 0255, test op snapshot, live controle (scripts/security-definer-check.ts)
- [x] Batch 1 — kaarten, kluis, inloggen: 21 functies (db/0255, live op Neon, 0 afwijkingen)
- [x] Batch 2 — werkruimtes, ouders, agent-sandbox: 36 functies (db/0256, live op Neon, 0 afwijkingen; 79 over)
- [x] Batch 3 — boekingen: 31 functies (db/0257, live op Neon, 48 over)
- [x] pg_temp-beleid: pg_catalog, pg_temp voor elke SECURITY DEFINER-functie (besluit eigenaar)
- [x] Batch 4 — de laatste 48 functies + pg_temp op alle 348 (db/0258, live op Neon, 0 open)
- [x] Rechtencorrectie interne hulpfuncties (db/0259, live op Neon, per functie nagekeken)
- [x] Herbouw uit db/ gelijk aan Neon voor alle functierechten (db/0260, op Neon aantoonbaar zonder effect)
- [x] db/0261 — drie ongebruikte SECURITY DEFINER-functies weg bij rout_app + samenvoegen met de handle van het tweede account herstellen (live op Neon 2026-11-13, per functie nagekeken)
- [x] 17 tabellen/reeksen: onderzoek per tabel klaar (bijlage J); voorstel db-pending/0262 getest
- [x] 0262 — overbodige tabelrechten van rout_app ingetrokken (live op Neon 2026-11-13, nagekeken), bestand in db/, schemaniveau 0262, volledige suite groen
- [x] auth_recovery_requests: besluit eigenaar — aparte SECURITY DEFINER-ingangen, geen policies
- [x] db/0263 (EXPAND) — ingangsfuncties voor herstelaanvragen geschreven en getest (bijlage K)
- [x] db/0263 live op Neon (2026-11-13, checksum gelijk, per functie nagekeken)
- [x] quarantine.server.ts gebruikt alleen nog de rout_recovery_*-functies (test tegen db/ + 0264, bijlage L)
- [x] Deze code op Vercel gezet door de eigenaar (health-probe meldde 0263, 2026-11-13 18:05 UTC)
- [x] 0264 (CONTRACT) in db/ en live op Neon (2026-11-13): rout_app heeft geen tabelrechten meer op auth_recovery_requests, schemaniveau 0264
- [ ] Productie opnieuw deployen zodat de health-probe 0264 meldt — eigenaar (geen haast: 0264 verandert alleen databaserechten)
- [x] Briefing in appendix van docs/HANDOVER.md (bijlage B letterlijk, bijlage C controle)
- [x] QA-testdraaiboek: docs/ROUT-QA-draaiboek.md (kopie in Files)
- [x] /t-schermen en knoppen in nl/en/fr/de (cardTap.* in interface-bundels); zegel "Authentic ROUT Card" blijft bewust Engels
- [ ] QA-draaiboek uitvoeren op het Vercel-deploy — eigenaar, met fysieke kaarten en toestellen

## Boekingssysteem topniveau (plan 2026-11-13)
- [x] Fase A: hoofdpagina/ontdek/about/info op alle formaten
  - [x] 12 formaten + liggend, geen overflow/afsnijding/CLS, contrast AAA, tikdoelen 44px, animaties alleen transform/opacity
  - [x] Per pagina titels/omschrijvingen NL/EN/FR/DE + eigen deelafbeelding
- [ ] Fase B: database (grootboek, agendakoppelingen, routering, locaties, annuleringsbeleid) — Neon pas na GO
  - [x] B1: booking_events — onveranderlijk grootboek, hash-keten + server-ondertekening, overzicht ↔ grootboek-controle (db/0284 live op Neon 2026-11-16 12:15 UTC, nagekeken)
    - [x] B1-bewijzen: fast-check (3 × 10.000 + 1.000 runs) en uitputtende modelcontrole tot diepte 3 tegen de SQL
  - [ ] B2: agendakoppelingen Google/Microsoft/CalDAV — sleutels alleen als RVE1-envelop in vault_enclave (alleen test)
  - [ ] B3: publieke kant alleen anonieme tijdvakken/bitmasker (bevestigen + test)
  - [ ] B4: MCP-hulpmiddelen: vrije tijden lezen, reservering voorbereiden; bevestigen alleen na passkey/step-up van een mens
- [ ] Fase C: Google/Microsoft/CalDAV sync — wacht op OAuth-apps van eigenaar + host voor Omni-werker
- [ ] Fase D: gewogen beurtrol, routeringsvragen
- [ ] Fase E: vergaderruimtes, betalingen, annuleringsbeleid
- [ ] Fase F: boekings-, beheer- en hostpagina's, mails NL/EN/FR/DE
- [ ] Fase G: intake-versleuteling, ROUT ID, Wallet, MCP-hulpmiddelen

## Vervolg 2026-11-13 (goedgekeurd plan)
- [x] Stap 0: 0265 greatest/least hersteld, naar db-pending tot GO
- [x] Stap 0: volledige testsuite groen (2805/2805)
- [x] Fase A: 12 formaten + liggend — geen overloop; 9-delige reeks en omgevingsknop op gsm opgelost
- [x] Fase A: taal al juist vanaf de server (geen Engels→Nederlands-wissel meer), lege flits bij laden weg; verspringen (CLS) overal < 0,07
- [x] Fase A: alle knoppen en links op de gemeten openbare pagina's ≥ 44×44 px (AAA), grijze tekst ≥ 7:1 contrast
- [x] Fase A: titel, omschrijving en deelafbeelding 1200×630 per pagina in NL/EN/FR/DE nagekeken (6 hoofdpagina's × 4 talen)
- [x] Fase A: brede meting op alle 47 overige about-, info- en ontdekpagina's (3 formaten): 0 fouten
- [x] Fase A: voor/na-overzichtsbladen per pagina op 11 formaten (Files: fase-a/)
- [x] Testsuite 2854/2854 groen (2 klokafhankelijke/trage tests robuust gemaakt)
- [ ] Fase B: zero-knowledge (client-side E2EE, blinde indexen, grootboek-invarianten) vanaf de eerste migratie
- [ ] Fase G: W3C Verifiable Credentials / selectief-onthullend bewijs voor gastverificatie
- [x] Fase B: herstel 2-van-4 (passkey, ROUT-kaart, server, papier) — cryptokern + werker + tests; kaartgeheim alleen in URL-fragment
- [x] Fase B: db-pending/0266 kaartdeel herstel — getest in testdatabase (wacht op GO)
- [x] Fase B: herstel aangesloten op scherm, opslag en herstel-login — nu als 3-van-4 (kaart tikken, 3 stukken kiezen)
- [ ] Fase B: kaarten (her)personaliseren met #rk1-fragment (fabrieksstation) — fysieke kaarten nodig
- [x] Fase B: versleutelde boekingsinhoud (bkh/bkg, ML-KEM-1024 + X25519, vaste emmers) — kern + tests
- [x] Fase B: 0284 grootboek aanpassen: vingerafdruk = BLAKE3(versleutelde tekst || zout), geen platte velden (PGlite + fast-check + begrensde modelcontrole groen)
- [ ] Fase B: migratie boekingsenveloppen + host-boekingssleutel (zaad onder werkruimtesleutel) + werker-ops
- [ ] Fase B: gastcontact (e-mail) als kluisverwijzing + blinde index voor limieten per gast
- [ ] Fase B+: vaste byte-lengtes (padding) en constante responstijden voor boekings- en bitmasker-API's
- [ ] Fase B+: Omni-werker als blinde doorgeefluik, nooit toegang tot persoonlijke sleutels

## Stap 0 + Fase A (GO 2026-11-13)
- [x] Vier migratie-afwijkingen alleen-lezen vastgelegd (HANDOVER-bijlage)
- [x] db-pending/README en QA-draaiboek op stand 0266 gezet
- [x] Volledige testronde: 1 rood (verouderde telling kaarttap-teksten) hersteld
- [x] /t vaste Engelse tekst vertaald; inzoomen op telefoon toegestaan; taalkeuze metadata = root
- [x] Fase A meetronde (11 formaten: home, discover, about, info, bookings-info): geen overloop/afsnijding, CLS ≤ 0,1; te kleine tikdoelen (footer-credit, kruimelpad SEO-pagina's) hersteld
- [x] Fase A: onthul-animaties: inhoud zichtbaar vóór en zonder de pagina-code; alleen blokken onder de vouw vervagen in
- [x] Fase A: CLS kwam van de lettertypewissel; reserve-lettertypes met dezelfde maten + voorladen → max 0,0007 op 66 metingen
- [x] Fase A: contrast AAA: axe (7:1) + pixelmeting onder de letters; lichtkrant, privélijst, voorbeeldkaart en gekozen tab hersteld; 0 fouten
- [ ] Boekingspagina's meten (geblokkeerd: preview heeft geen database)

## Fase B–G extra veiligheidslagen (eis eigenaar 2026-11-13)
- [ ] Hardwarebinding: apparaatsleutels alleen te openen met een passkey-PRF van een geattesteerde hardware-authenticator (TPM 2.0 / Secure Enclave)
- [ ] Geheugen-wiping: één vooraf toegewezen werkergeheugen voor sleutel- en klare bytes, nulgezet na elke bewerking + test
- [ ] Property-based tests (fast-check) + begrensde modelcontrole voor grootboek, hash-ketens, reserveringssloten en statusovergangen — vereist vóór GO per migratie
- [ ] BBS+ (BLS12-381) blinde credentials + zero-knowledge-bewijs bij aankomst; server bewaart alleen een nullifier per tijdslot
- [x] Besluit eigenaar: herstel 3-van-4 (vervangt 2-van-4 uit bijlage O)
- [x] Fase B: recovery-mpc versie 3 (drempel 3 van 4), werker, server, /t-doorgifte, schermen; modelcontrole 16 deelverzamelingen + fast-check
- [x] GO eigenaar: 0267 (kaarttik "dit is mijn kaart") live op Neon 2026-11-14 12:12 UTC, in db/
- [ ] GO eigenaar: db-pending/0268 (opslag 3-van-4) op Neon — tot dan weigert de app elke nieuwe kluis
- [ ] Na deploy met niveau ≥ 0268: db-pending/0269 (oude 2-van-3/2-van-4-opslag weg, alleen versie 3) — GO eigenaar
- [ ] Doorkliktest 3-van-4 op echte telefoon met een kaart mét #rk1-fragment
- [x] Besluit eigenaar: pseudoniem per host — limieten per host, niet te volgen tussen hosts, mail via kluisverwijzing

## Ronde J (plan 2026-11-14, GO plan)
- [x] Bindende regels F, H en I in src/lib/booking-engine/AGENTS.md
- [x] 0267 + rollback gecorrigeerd: doel 'activation' (db/0246) bleef weg → elke kaartactivatie zou falen; nu behouden + bewaking in het DO-blok + test die activatie na 0267 en na rollback doet
- [x] Testsuite: 3 bestanden faalden op het laden van een font-bestand (`?url`) buiten de projectmap; vitest-config staat de echte node_modules-map toe
- [x] Alleen-lezen controles 0267 op Neon (geen tap-rijen, constraint met activation, functie = db/0245+0258, rechten in orde, 0267 nog niet toegepast)
- [x] 0267 toegepast (één transactie), checksum/rechten/constraint nagekeken, CODE_SCHEMA_LEVEL 0267
- [x] Stap 2: TLA+-model herstel v4 (formal/recovery-v4) + TLC in CI (.github/workflows/tla-recovery-v4.yml): 3 hoofdmodellen groen, 5 mutanten breken, 10 getuigen bereikt
- [ ] Stap 2 nazorg: eerste CI-run op GitHub bekijken zodra de code daar staat
- [x] Stap 3 code: OPAQUE + Argon2id (Wasm, vast geheugen) + Hashcash-PoW aangesloten: plugin in Better Auth, gewone wachtwoorden uit, /secure/password (inloggen), /secure/password/new (aanmelden), /secure/password/set (instellen/verwijderen met passkey-step-up), extra voorzichtig typen, wissen na 30 s weg
- [x] Stap 3 live: 0270 toegepast op Neon (GO eigenaar 2026-11-14 15:55 UTC), bestand in db/, CODE_SCHEMA_LEVEL 0270
- [ ] Stap 3 eerste inlogtest: wacht op deploy van deze code naar Vercel met ROUT_VAULT_KEK gezet (eerste wachtwoord maakt de server-sleutel en OPAQUE-setup)
- [ ] Stap 6: 0268/0269 bij herschrijven voor v4 hernummeren boven 0270 (anders kan de health-probe de EXPAND niet bewijzen)
- [ ] Stap 3 nazorg: /secure/* krijgt bij hosting op Vercel dezelfde headers (nu via src/server.ts); de algemene securityHeaders() worden nergens toegepast (bevinding, niet gewijzigd)
- [x] Stap 4: Veiligheidsschild (3 niveaus) in topbalk, NL/EN/FR/DE (GO eigenaar 2026-11-14, geen migratie)
  - [x] Berekening getSovereigntyHealthScore + tests (besluit A: niveau 3 = kaart + passkey; besluit B: bevroren kaart schort 3 op)
  - [x] Serverfunctie (alleen lezen: passkeys, pake_registered, member_card_factor, kaartstatus)
  - [x] Knop in topbalk (44×44, geen verspringen) + paneel/lade, 3 kleurtokens met contrasttest ≥ 7:1
  - [x] Teksten NL/EN/FR/DE + vertaaltest
  - [x] Opnieuw controleren na passkey/kaart-wijzigingen; geen timers/luisteraars die blijven hangen (geheugentest)
  - [x] AGENTS.md bijwerken; volledige tests + typecheck
  - [ ] Doorkliktest met een echt ingelogd account (wacht op deploy naar Vercel)
- [ ] Stap 5: FIDO MDS3-attestatie (Level 9)
  - [x] MDS3 BLOB ophalen, JWS + x5c naar gepinde GlobalSign R3, CRL, serienummer, cache; attestatie-engine (packed/tpm/apple), status- en certificatiecontrole; niveau 3 = kaart + gecertificeerde sleutel; RVE1 pak; db-pending/0271 + rollback; tests
  - [x] 0271 live op Neon (GO eigenaar 2026-11-14)
  - [ ] Android Key: KeyDescription-niveaus en RootOfTrust parsen (telt nu nooit als geattesteerd)
  - [ ] Eerste echte registratie met een beveiligingssleutel na deploy (vereist ROUT_VAULT_KEK)
- [x] Stap 7: anonieme boekingsmotor — kern 7a–7f af, 0273 live op Neon (GO eigenaar 2026-11-15); open punten hieronder zijn nazorg en 7g (besluiten eigenaar 2026-11-14: pseudoniem per boeking, eigen allocatorvrije Rust-Wasm op zkcrypto bls12_381)
  - [x] 7a: wasm/rout-zk (no_std, geen allocator, geen memory.grow, vaste geïmporteerde memory, volatile wissen, subgroepcontrole G1/G2, `subtle`)
  - [x] 7a: BBS (KeyGen/Sign/Verify/ProofGen/ProofVerify) + Blind BBS (Commit/BlindSign/VerifyBlindSign/BlindProofGen/BlindProofVerify met COMMIT-onthulling); alle 49 officiële fixtures byte-gelijk (cargo test)
  - [x] build.sh + SHA-384-pin + loader voor rout-zk: officiële rustup 1.95.0 (LLVM 22.1.2), 2× uit verse mappen gelijk, pin a4a02c5f…540c, CI-job rout-zk in wasm-reproducible.yml (7f)
  - [ ] Timingmeting (dudect) van de gegenereerde Wasm
  - [x] 7d: forward-secure hostsleutels — HKDF-SHA256-ratchet per epoch (SK_0 uit vers random seed), oude staat in place gewist, ondertekende epoch-links vanaf anker PK_0, credentials (ook blind) gebonden aan sleutel-id + epoch; worker-ops host_key.init / advance_epoch / sign_credential / chain / verify_epoch_credential
  - [x] 7d vervolg: besluit bewaren SK_t (eigenaar 2026-11-14): alleen de actuele staat, als RVE1-envelop (kind 9 hsk) onder de Master KEK in vault_enclave; tabel staat in db/0273
  - [x] 7f: SK_t onder de Host Device Key — hsk (kind 9, holder member_device) in pqc-envelope.ts, verzegeld/geopend alleen in de worker (host_key.init/advance geven sealedState, host_key.restore controleert tegen de publieke keten + high-water mark); 0273 eist holder 2, 1703 bytes
  - [x] 7d vervolg: PK_0 gebonden aan het hostrecord bij init (anon_host_keys, db/0273), handtekening + ondertekenaar opgeslagen; keten publiek leesbaar via anon_host_chain
  - [x] 7f: ankerhandtekening = BBS van een device-seed-sleutel over [sleutel-id, PK_0, boom-id] (host_key.sign_anchor / verify_anchor)
  - [x] Besluit (eigenaar 2026-11-15): PK_0 op het publieke hostprofiel (`/@host/zkp-anchor.json`), ondertekend met de MDS3-geattesteerde hardwaresleutel van de host; epoch = 24 uur, overgang om 00:00 UTC
  - [x] 7b: Pedersen-commitments (homomorf optellen/aftrekken) + Bulletproofs-range-proofs v ∈ [0, 2^64−1] in rout-zk; worker-ops pedersen.commit / bulletproofs.prove_range / bulletproofs.verify_range
  - [x] 7f: a ≤ t ≤ b — slot als RAW-bericht in het credential, bij aankomst COMMIT-onthulling + twee range proofs (generatoren Y_1, Y_0) gebonden aan challenge/venster/C; capaciteitspools (C_rem,i = C_rem,i−1 − C_take,i, bewijs take ≥ 1 en rest ≥ 0) in rout-zk ABI 5 + 0273
  - [ ] Externe audit van de eigen BBS-, Bulletproofs-, Poseidon- en SMT-code (regel 'audited libraries' in booking-engine/AGENTS.md)
  - [x] 7c: Poseidon (referentie x5_255_3, constanten via Grain herberekend en gelijk) + 256-diepe nullifier-SMT met NonExist/Exist, hergebruik geweigerd; ondertekende root (BBS, eigen sleutel uit device-seed) per epoch; worker-ops smt.genesis / smt.insert_nullifier / smt.verify_non_membership / smt.verify_signed_root
  - [ ] 7c vervolg: blijvende bescherming tegen terugdraaien van een oude ondertekende root (nu alleen high-water mark in het werkgeheugen) via externe verankering
  - [x] 7c vervolg: meerdere toestellen van één host — elk toestel eigen keten, boom en rootsleutel (0274, live op Neon)
  - [x] 7a: pseudonyms.ts + worker-op `pseudonym.derive` (HKDF-Expand + HMAC-SHA256, gedeelde vector met Rust)
  - [x] 7f: gast-adapters in de worker (anon_guest.begin/accept/present/discard, anon_host.verify_presentation, capacity.*), geheimen alleen in de worker
  - [x] 7f: eigen anonieme ledger (anon_ledger_events, hash-keten per boom, client-verifier anon-ledger.ts byte-gelijk aan SQL); 0265 ongemoeid
  - [x] 7f: end-to-end test (worker + 0273 op PGlite): twee anonieme gasten, dubbel uitgeven geweigerd, derde plaats onmogelijk, herladen via verzegelde staat
  - [x] Gast-credential bewaren tussen boeking en aankomst: versleuteld in vault_guest_storage (7g)
  - [x] Besluit (eigenaar 2026-11-15): master_seed van de gast uit de WebAuthn-`prf`-extensie (zonder PRF: HKDF over de assertion-handtekening); lopende bewijzen en SK_guest in IndexedDB `vault_guest_storage`, versleuteld onder die lokale sleutel
  - [x] 7e: db-pending/0273 + idempotente rollback (deny_all, definers, 7 audit-acties) + PGlite-test (replay → 0273 → rollback → 0273, schema-vingerafdruk gelijk, fast-check-model + 2×70 interleavings)
  - [x] Volledige suite + typecheck
  - [x] 7f: account purge (rout_anon_booking_purge, alleen als de verwijdering vervallen is) en merge (rout_anon_booking_merge in execute_account_merge); alle anon-FK's ON DELETE RESTRICT; ENCLAVE_MERGE_TABLES
  - [x] 0273 naar db/, CODE_SCHEMA_LEVEL 0273, schema-snapshot uit de replay (geen rijtypes voor vault_enclave), alle tests en dry-run van het uitrolscript groen
  - [x] Besluit (eigenaar 2026-11-15): elk hosttoestel een eigen keten SK_t,dev, geregistreerd als toegestaan toestel onder de Host Root Identity
  - [x] 0273 live op Neon (GO eigenaar 2026-11-15, 07:39 UTC) via scripts/migration-rollout.ts: één transactie, checksum c0d26bd1…b458 in de transactie gecontroleerd, alle vingerafdrukken gelijk aan de replay
  - [ ] Productie meldt 0273 pas na een deploy naar Vercel (health meldt nu 0272)
- [x] Stap 7g: besluiten eigenaar 2026-11-15 gebouwd (GO eigenaar 2026-11-15; goedgekeurd)
  - [x] guest-vault.ts: seed uit WebAuthn PRF (fallback HKDF over de handtekening, alleen als twee assertions byte-gelijk zijn), SK_guest + boekingen als AES-256-GCM in IndexedDB vault_guest_storage (emmers van 4096 bytes), worker-ops guest_vault.unlock/lock, herladen getest
  - [x] guest-passkey.ts: PRF-assertion en gast-passkey aanmaken in de browser (nog geen scherm)
  - [x] /@host/zkp-anchor.json: route + document per toestel (PK_0, links, passkey-assertion, MDS3-oordeel); verifier voor gasten (ES256/EdDSA/RS256); geeft 404 not_available tot 0274 live is
  - [x] Dagelijkse ratchet 00:00 UTC (epoch = UTC-dag): DailyEpochRatchet, inhaalsprong, single-flight, opnieuw versturen; Wasm-geheugen na de stap nul, oude SK in place overschreven, nieuwe envelop in de eigen vault_enclave-rij
  - [x] 0274 + rollback: anon_host_devices, anon_anchor_endorsements, één live keten per toestel (max 16), register/revoke/list/passkey/publiek anker, purge en merge uitgebreid; PGlite 0267→0273→0274→rollback→0274 groen
  - [x] Volledige suite 3124 groen (9 overgeslagen), tsgo 0 fouten, HANDOVER-bijlage
  - [x] 0274 op Neon (GO eigenaar, 2026-11-15 08:35 UTC, migration-rollout.ts in één transactie; 7 vingerafdrukken gelijk aan de replay), naar db/, CODE_SCHEMA_LEVEL 0274, snapshot
  - [ ] Productie meldt 0274 pas na de volgende deploy
  - [ ] Serverfuncties + schermen: host registreert toestel en start de ratchet; gast opent kluis en boekt (nu alleen bouwstenen + tests)
  - [ ] Keten vol na 1024 links (≈ 2,8 jaar dagelijks): oude keten intrekken en een nieuwe op hetzelfde toestel registreren (0274 laat dat toe), nog geen scherm
- [ ] Stap 8: hybride PQ-ratchet + RVE2 (GO eigenaar 2026-11-15; geen SQL)
  - [x] wasm/rout-zk pq_ratchet.rs: ML-KEM-1024 + X25519 root-stap (HKDF, X-Wing-binding), HMAC-keten met volatile wipe, AES-256-GCM + HMAC in RVE2, out-of-order (max 64 per gat, 64 sleutels), atomisch (state alleen bij succes)
  - [x] ABI 6, reproduceerbare build (officiële 1.95.0, 2x gelijk), nieuwe pin; 10 nieuwe Rust-tests (68 totaal)
  - [x] Worker-ops pq_ratchet.init_session / ratchet_encrypt / ratchet_decrypt / close_session + client; secure.wipe wist sessies; worker-test
  - [x] Prekey-bundle (1646 B) ondertekend met MDS3-geattesteerde passkey; worker weigert elke initiator-handshake zonder geldige handtekening, MDS3-pass of binnen 30 UTC-dagen (`bundle_rejected`)
  - [x] Publicatie zonder SQL: serverfunctie `publishMyPrekeyBundle` controleert passkey + MDS3 en schrijft naar Scaleway `users/<uid>/prekey-bundle.json`; publiek op `/@handle/prekey-bundle.json`
  - [x] Sessies bewaren over herladen: versleutelde IndexedDB `vault_ratchet_sessions` (AES-256-GCM, 12 KiB-buckets, schrijven vóór resultaat, nullen + verwijderen bij sluiten); worker-ops create_prekey_bundle / unlock_vault / lock_vault / load_session_vault
  - [x] Tests: prekey-bundle, pq-session-vault, integratie (4 verplichte gevallen + E2E met nagebootste Scaleway); Wasm-pin onveranderd
  - [ ] Echte test op rout.be met hardware-passkey en Scaleway-sleutels
  - [ ] Schermen/transport voor berichten en status-updates
  - [ ] Externe audit + dudect voor de ratchet en de gebruikte RustCrypto-crates
- [ ] Stap 9: RLS non-interference-model (Z3) vergeleken met de snapshot in CI (GO eigenaar 2026-11-15; Neon niet aangeraakt)
  - [x] scripts/formal-rls-verifier.ts: parser voor alle policy-expressies, Z3-bewijs per tabel/commando/fase (1210 verplichtingen, 519 Z3-checks), vault_enclave deny-all, search_path van 415 definers, views, unieke-sleutel-orakels
  - [x] src/test/rls-non-interference.test.ts: bewijs op de snapshot, mutaties worden gevangen, PGlite-aanvallen (cross-tenant, vervalste rijen, injectie op elke rout_app-definer, vault_enclave)
  - [x] db-pending/0275 + rollback: F4/F5 (schrijfbare/eigenaarsviews), F7 (zelf lid/eigenaar worden van elke workspace), F8a (rij planten in vreemde workspace); getest op PGlite
  - [ ] GO eigenaar voor 0275 op Neon
  - [ ] F1 profiles volledig leesbaar (EXPAND/CONTRACT), F2 social_links, F3 workspaces.legacy_user_id, F6 orakels, F8b UPDATE naar vreemde workspace, F9 rout_resolve_account geeft e-mail
  - [ ] neon_auth (Better Auth) buiten het RLS-model: eigen rol voor de auth-adapter
- [x] /secure/*-documenten met COOP/COEP (wachtwoordpagina's)
- [x] Wasm SRI (SHA-384) en reproduceerbare build van de wachtwoordmotor: officiële rustup 1.95.0 (LLVM 22.1.2) vastgezet, pin opnieuw gezet, CI .github/workflows/wasm-reproducible.yml (lokaal 2x uit twee mappen gelijk)
- [ ] Wasm-CI nazorg: eerste run op GitHub bekijken zodra de code daar staat
- [ ] Kluis- en herstelschermen ook naar /secure/*
- [ ] Stap 6: dynamisch herstel v4 (2-van-3 → 3-van-4, TLA+-gevolgd)
  - [x] Shamir GF(2^8) constant-time in de gepinde Wasm-engine (officiële toolchain), herbouw + pin
  - [x] recovery-v4.ts: verse generatiesleutel per ceremonie, beleid 2of3/3of4, commitments, uitsluiting gecompromitteerd deel, commit-laag
  - [x] TLA+: gecompromitteerd deel (CompromiseContained + mutant + getuigen), TLC groen
  - [x] db-pending/0272 + rollback (vault_enclave, deny-all, definers, audit-acties, TTL 10 min)
  - [x] Server-stappen (RecoveryV4Store) + PGlite-scenariotest per modelactie
  - [x] Tests: 3-uit-4, 2-uit-4 faalt, foute hash, rotatie, nul-geheugen, PGlite 0272 + rollback; typecheck
  - [ ] Server-functies + schermen die RecoveryV4Store aanroepen (crypto in de enclave-worker); cron voor recovery_v4_expire_due
  - [x] 0268/0269 naar db-archive/ (eigenaar 2026-11-14)
  - [x] 0272 live op Neon (GO eigenaar 2026-11-14), byte-gelijk met de replay

## Stap 10
- [x] Rollout 0276 op Neon + CODE_SCHEMA_LEVEL 0276
- [x] Wesolowski VDF: RSA-2048 + class groups (8/8 unit + 2048-bit test groen)
- [x] Hybride PQ-Noise tunnel (ML-KEM-1024 + X25519, IKpsk2-basis)
- [x] Dudect-script (`bun run test:dudect`) gebouwd en verkort gedraaid
- [x] Dudect 1M-run: alle vijf operaties |t| < 4.5 (ML-KEM 3,68)
- [ ] Dudect voor OPAQUE, ratchet en VDF (wacht op gepinde Wasm uit CI)
- [x] Pre-check 0276 -> 0277 (`scripts/tenant-backfill.ts`, offline 0 afwijkingen) en Z3-certificering 0277 (CERTIFIED)
- [x] Live pre-check 0 afwijkingen, 0277 live op Neon (incl. herstel accountsamenvoeging), CODE_SCHEMA_LEVEL 0277
- [x] Live codeversie bevestigd: https://rout.be/api/public/health meldt operational, schema 0277 (2026-11-15 14:05 UTC); geen deployment vanuit deze chat uitgevoerd

## Finale Vercel-releasecontrole (2026-11-15)
- [ ] Herstel publieke root/alias/OG-projecties na 0277; regressietest onder rout_app
- [ ] Hardwarepublicatie vanuit Developer Console, opslagdiagnostiek en veilige ankerregistratie
- [ ] scripts/verify-live-merge.ts: zes helpers aanroepen in alleen-lezen transactie
- [ ] Volledige Vitest-validatie en einddocumentatie; production hertest na nieuwe deploy
- [ ] Exacte nieuwste stand naar Vercel production deployen en build zonder waarschuwingen/typefouten bevestigen — wacht op Vercel-toegang; geen token, projectkoppeling of deploy-hook beschikbaar
- [ ] Publieke profielweergaven volledig groen — @jdelplanche toont een voorbeeldprofiel; @routtestkaart23 toont een profiel-lookupfout ondanks HTTP 200
- [ ] Echte accountsamenvoeging na deploy controleren — wacht op een geautoriseerde productie-testsessie en aangewezen testaccounts; geen echte accounts samengevoegd
- [ ] Scaleway prekey-bundle succesvol ophalen — alle 11 @handles uit de publieke profielsitemap antwoorden 404 not_available; geen succesvolle object-read bevestigd
- [ ] Gepubliceerd ZKP-anker ophalen en verifiëren — dezelfde 11 @handles antwoorden 404 no_anchor; geen gepubliceerd anker beschikbaar voor verificatie
- [x] Live bevindingen vastgelegd in de overdrachtsbijlage; 100% completion niet bevestigd

## Zero-trust hardening (2026-11-15, zonder Neon-wijziging)
- [x] Server-guard-test voor alle serverfuncties (93 bewust openbaar, geen ongeguarde ingelogde functie)
- [x] `/dev/emails` en `sendTestEmail` dicht buiten development
- [x] ENVIRONMENT.md aangevuld; `vercel.json` + `build:vercel` toegevoegd (Vercel-build niet bevestigd)
- [x] Migratiedocumentatie 0265/0277-rollback gecorrigeerd zonder `db/0277` te wijzigen
- [x] Gastnaam, e-mail, notitie en intake versleuteld bij boeken (RVE1 bkh in de crypto-worker); server weigert plaintext; hostsleutel als Scaleway-document; Studio opent op het toestel van de host (alleen tests, geen live boeking)
- [ ] Live boeking end-to-end bevestigen — wacht op een omgeving met Neon (DATABASE_URL) en Scaleway-clientopslag
- [ ] Gastkopie (bkg, beheerlink-fragment) leesbaar maken voor de gast — vraagt een EXPAND-migratie: `rout_booking_guest_view` geeft intake_answers niet terug
- [ ] Limiet per gast werkt niet meer voor versleutelde boekingen (willekeurig pseudoniem per boeking) — wacht op BBS+-gastbewijzen of eigenaarsbesluit
- [ ] Hostsleutel aan hardware-passkey (PRF) binden — wacht op de hardware-PRF-test

## Documentatie- en publieke tekst-audit (2026-11-15, geen Neon-wijziging)
- [x] /info/bookings in nl/en/fr/de: versleutelde gastgegevens, geen bevestigingsmail, limiet per bezoeker, grenzen
- [x] Privacyverklaring: nieuw onderdeel "Afspraken via een boekingspagina" in nl/en/fr/de
- [x] Trust Center (/security): statusoverzicht boekingen en cryptografie in nl/en/fr/de + test
- [x] Studio: uitleg bij "Max. per gast" vermeldt dat de limiet niet geldt voor versleutelde boekingen (nl/en/fr/de)
- [x] README, ENVIRONMENT.md, safety/cryptography (alleen nl, zoals de pagina al bestond) bijgewerkt
- [ ] Privacyverklaring juridisch laten nalezen (grondslagen, bewaartermijnen, verwerkers) — eigenaar
- [x] Kort aanvraagformulier op profielkaarten versleutelen — zie sectie hieronder
- [x] Trust Center (/security) en /safety/cryptography volledig in fr/de — zie sectie hieronder
- [ ] Overige safety-pagina's (architecture, zero-knowledge, compliance, …) bestaan alleen in nl — vertaling wacht op GO eigenaar

## Profielkaart-aanvragen versleuteld + fr/de-pariteit (2026-11-15, geen Neon-wijziging, schemaniveau 0277)
- [x] Kort aanvraagformulier: naam, e-mail en bericht als RVE1 bkh-envelop in de crypto-worker; `requestBooking` weigert plaintext (`plaintext_refused`); envelop in Scaleway `users/<uid>/inquiries/<pid>.json`, Neon krijgt alleen plaatshouders
- [x] Hostmail zonder gastgegevens; geen mails meer naar de gast voor versleutelde aanvragen; host leest, aanvaardt/weigert en antwoordt zelf (mailto) in Studio → Afspraken
- [x] Tests: `src/lib/booking-engine/inquiry-sealed.test.ts` (15) + `src/test/security-translations.test.ts` (8)
- [x] Trust Center-teksten naar `src/locales/pages/trust.{nl,en,fr,de}.json`; privacypijlers in fr/de; `cryptography.{en,fr,de}.mdx`
- [ ] Live aanvraag end-to-end bevestigen — wacht op een omgeving met Neon (DATABASE_URL) en Scaleway-clientopslag
- [ ] Oude, onversleuteld bewaarde aanvragen opruimen of verzegelen — vraagt een besluit van de eigenaar (en eventueel een migratie)
- [ ] Beheerlink voor de gast (status van de aanvraag) — vraagt een EXPAND-migratie; nu bevestigt alleen het scherm in de browser

## Nul-drift (2026-11-15)
- [x] 0280: rout_pow_spend + sync_social_grid_draft gelijk aan replay, Neon Auth-kolom gespiegeld (live op Neon, schemaniveau 0280)
- [x] Vals alarm schema-grants (volgorde) opgelost in de vergelijking
- [x] tenant-backfill: openstaande uitnodiging telt niet als afwijking (51 controles, 0 live)
- [x] Live: schema-snapshot 0 verschillen, certify-0280 CERTIFIED op de live catalogus, ANALYZE op de drie verzegelde tabellen
- [x] End-to-end keten verzegelde aanvraag + boeking op 0280 (src/test/e2e-sealed-chain.test.ts, offline replay)
- [ ] Productie (Vercel) uitrollen met de code op schemaniveau 0280 (eigenaar)
- [ ] Verdere intrekking van rout_app-tabelrechten: alleen per tabel na nalezen van de code (wacht op keuze eigenaar)
- [ ] OWNER_DATABASE_URL verwijderen (wacht op eigenaar)

## Vervolgdirectief 2026-11-15 (schema 0280)
- [x] F1.1 Studio-keuzelijsten: "Openbaar profiel" → "Hoofdprofiel" (nl/en/fr/de)
- [x] F1.2 Studio: tabblad Boekingen verbergen als het actieve profiel geen boekingen ondersteunt
- [ ] F1.3 (geblokkeerd, zie hieronder) /w/<werkruimte>/support en /w/<werkruimte>/ask tonen wanneer ingeschakeld
- [x] F1.4 Studio Boekingen = formulier ontwerpen (keuze bij meerdere afspraaktypes); /studio/agenda = kalender; knop "Afspraaktypes & beschikbaarheid" → Studio
- [x] F1.5 /settings in drie delen: Profiel & Account, Beveiliging & Enclave, Sessie & Activiteit
- [x] F2.2 "Zet eerst je hoofdsleutel op dit toestel": nette kaart met Primair toestel / 3-van-4 herstel
- [x] F2.3 Logboek via bestaande audit_logs-controle (geen BLAKE3)
- [x] F2.4 "Geverifieerd" gekoppeld aan Didit-resultaat uit de database (geen nieuwe rekenmodule)
- [x] db/0281 (Didit-resultaat voor het vinkje) live op Neon (GO 2026-11-15, één transactie, checksum 8622ddfb…)
- [x] F1.3 beslissingen eigenaar ontvangen (zie executive directief hieronder)
- [ ] "Synchroniseer via primair toestel": wacht op een goedgekeurd protocol voor sleuteloverdracht

## Executive directief 2026-11-15 (0281 GO, werkruimte, badges)
- [x] 0281 live op Neon via migration-rollout (rout_app EXECUTE, PUBLIC geen)
- [x] Blauw vinkje uitsluitend uit Didit-attestatie (db/0282 live); betaald/Pro krijgt een aparte kroon-badge (Supporter/Pro)
- [ ] /w/<werkruimte>/ask: versleuteld voor eigenaar + beheerders, per vraag openbaar of privé antwoorden — volgende stap (nieuwe worker-bewerkingen + migratie)
- [x] /w/<werkruimte>/support: gebouwd (IBAN + eigen Stripe/Mollie van de werkruimte; Didit-eigenaar of geverifieerd domein)
- [ ] db/0283 (steunpagina werkruimte) live op Neon: wacht op GO van de eigenaar

## Stap 2 — groepsversleuteling werkruimte + vragenpagina (GO 2026-11-16)
- [x] Fase 1: 0284 live op Neon (één transactie, checksum gelijk, keten/rechten/triggers/snapshot nagekeken)
- [x] Fase 1: volledige testsuite groen (544 bestanden, 3343 tests; 1 trage test robuust gemaakt)
- [ ] Fase 1: productie opnieuw deployen zodat de health-probe 0284 meldt — eigenaar
- [x] Fase 2: db-pending/0285_workspace_group_encryption.sql — zes tabellen, enveloppen alleen voor eigenaar/beheerder, epoch-rotatie, omzetten van beheerder wist hun enveloppen, allemaal SECURITY DEFINER op pg_catalog, pg_temp (nog niet toegepast)
- [x] Fase 2: PGlite + fast-check tests voor 0285 (src/test/workspace-group-0285.test.ts, 24 tests: rechten, RBAC, rotatie, vloedplafond, modelcheck tot diepte 3, rollback)
- [ ] Fase 2: /w/:slug/ask (anoniem, RVE1 in de browser, #token=) + inbox met privé/FAQ-antwoord

## Owner directive 2026-11-16 23:20 — after live Neon audit (HANDOVER appendix)
- [x] A3 + A2: db/0286 written + offline tested (47 FK indexes, trigger-only definers closed, rollback in db-pending), schema level 0286
- [x] 0286 live on Neon (owner GO 2026-11-17 09:05 UTC, checksum verified in-transaction, 0 unindexed FKs left)
- [ ] Redeploy production on the owner's host so the health probe reports 0286 — owner
- [x] Workspace manager inbox on workspace settings: key init/rotate (atomic), list, decrypt in worker, private reply, publish to FAQ, decline (nl/en/fr/de, offline SQL test)
- [ ] Inbox: share the workspace key with other owners/admins — needs a published device public key per member (no such registry yet; owner decision)
- [ ] Inbox live click-through — needs DATABASE_URL in an environment
- [ ] A1 profile privacy: EXPAND (definers for moderation/Stripe/VAT reads, code moved) then CONTRACT in db-pending revoking those columns from rout_app

## Owner directive 2026-11-17 12:09 UTC — A1 field encryption + multi-admin device keys
- [x] A1: application-level AEAD encryption (RPF1, XChaCha20-Poly1305) + blind HMAC-BLAKE3 indexes; keys wrapped under ROUT_VAULT_KEK
- [ ] A1 round 2 (owner chose: all private fields now): move readers/writers of email, forwarding email + token, legal names, last city/country, then add them to BACKFILL_FIELDS; admin email search becomes exact match
- [x] A1: read/write paths for VAT, Stripe account, payment method, moderation reason/moderator, export and referral moved; fast-check suites green
- [x] A1: EXPAND 0287 live on Neon (2026-11-17 14:48 UTC, owner GO); rollback stays in db-pending
- [ ] Device key register (workspace_member_device_keys) + per-device HPKE envelopes (workspace_member_envelopes) — owner chose RFC 9180 HPKE with X-Wing (ML-KEM-768 + X25519) as KEM
- [ ] Automatic epoch rotation when a manager role is revoked
- [ ] /w/:slug/ask seals against the active epoch key; managers decrypt only through their registered device envelopes
- [ ] Device key migration prepared, not applied — wait for owner GO

## Owner directive 2026-11-17 — Sovereign Identity OS, multi-provider engine, Didit KYC
- [x] 0281: already live on Neon since 2026-11-15, nothing to run
- [x] Provider Discovery Hub on the verification page (search, chips, region-aware, privacy ratings; nl/en/fr/de)
- [x] Universal nullifier pipeline (canonical ICAO/eIDAS anchors, Poseidon256 + BLAKE3 + pepper) with fast-check tests
- [x] Didit v3 engine: session, signed webhook, status endpoint, verification modal; no names or numbers stored
- [x] db-pending/0288 (cross-provider nullifier table + rout_kyc_attest) written and tested offline
- [x] 0288 live on Neon (2026-11-17 14:49 UTC, owner GO)
- [ ] Set DIDIT_API_KEY, DIDIT_WEBHOOK_SECRET, DIDIT_WORKFLOW_ID, IDENTITY_HASH_PEPPER or PEPPER_SECRET on the owner's host and register the webhook URL at Didit — owner
- [ ] Other providers in the hub (itsme, DigiD, eID, France Identité, MitID, CIE, IDnow, Shufti Pro, Trulioo, World ID) — each needs a contract and keys from the owner
- [x] Green "Real Human" shield only from zero-knowledge proofs; blue "KYC Attested" shield for Didit/eIDAS (owner decision 2026-11-17 13:45)
- [ ] Workspace IBAN for Didit-only owners: name match no longer possible without a stored name — owner decision (domain path works)

## Owner directive 2026-11-17 13:45 UTC — 0287 + 0288 rollout, badge split, zeroization
- [x] 0287 + 0288 prepared on an offline replay; checksums pinned in db-pending/ROLLOUT-0287-0288.md; Neon history verified read-only (0 deviations)
- [x] 0287 then 0288 applied on Neon (owner GO, one transaction each)
- [x] Blue "KYC Attested" shield, green "Real Human" only from zero-knowledge proofs, supporter crown separate
- [x] Webhook/decision bytes and anchors in Node.js Buffers, fill(0) right after the nullifier; PEPPER_SECRET accepted
- [ ] Zero-knowledge humanity verifier that writes `zk_proof` rows — needs a chosen proof system/provider (owner)
- [x] Full test suite green, including the load-sensitive tests

## Verificatie & uitrol (2026-11-17)
- [x] /verify herontworpen: "Geverifieerd profiel", zwarte knop, compacte zoekbalk + scrollbare chips, alleen Didit/W Identity als actieve kaarten, overige providers in "Toekomstige integraties"
- [x] 0287 + 0288 live op Neon (17-11-2026 14:48 en 14:49 UTC) via migration-rollout.ts --apply
- [x] Alleen-lezen gecontroleerd: 282 rijen, 0288 laatste, controlegetallen gelijk, geschiedenis- en definer-controle 0 afwijkingen, schema-snapshot gelijk aan Neon
- [x] Sessies 90 dagen glijdend gedaan; passkey-bevestiging en Studio-time-out staan hieronder bij de open besluiten

## Opdracht eigenaar 2026-11-17 14:47 UTC — live 0288, logo's, sessies
- [x] 0287 + 0288 live, CODE_SCHEMA_LEVEL 0288, tests volgen de vrijgegeven bestanden
- [ ] Wachtwoord van neondb_owner in Neon vernieuwen (stond in de chat) — eigenaar
- [ ] Productie opnieuw uitrollen zodat de health-probe 0288 meldt — eigenaar
- [x] A1-backfill uitgevoerd (2026-11-19 22:2x UTC, GO eigenaar): 3 velden in 3 profielen verzegeld, 0 rijen met platte tekst over, alle 3 openen correct onder ROUT_VAULT_KEK
- [x] Merklogo's in de verificatiehub: lokaal opgeslagen (public/logos + inline Didit/W Identity), 0 externe verzoeken, `<ProviderLogo>` met Building2-terugval (eID / eIDAS heeft geen eigen merk)
- [x] Time-outbewaking 6000 ms in requireAuth (`warming_up`, Studio probeert één keer opnieuw) — eigenaar koos 6000 ms i.p.v. 3000 ms
- [x] Sessies 90 dagen, glijdend na 24 uur (src/lib/auth/session-policy.ts)
- [x] SameSite: sessiecookie blijft Lax (besluit eigenaar)
- [ ] Vernieuwingstokens met familie-intrekking — Better Auth gebruikt geen vernieuwingstokens; vraagt ontwerp + migratie (GO)
- [x] 0289 live op Neon (15:59 UTC): accountfusie werkt weer, identiteitsrijen worden bij fusie bewaakt
- [ ] A1-privacybevinding: rout_app leest versleutelde velden en blinde indexen van alle profielen (OPENED_BY_0287) — sluiten via eigen-rij/admin-functies vóór de A1-CONTRACT
- [x] Rechtencontrole uitgebreid naar CHECK-constraints (check-function-grants.test.ts)


## Opdracht eigenaar 2026-11-17 15:58 UTC — GO 0289, Studio-time-out
- [x] 0289 live, alleen-lezen gecontroleerd (283 rijen, 0289 laatste), CODE_SCHEMA_LEVEL 0289
- [x] Oorzaak "Profiel niet beschikbaar": Vercel-functies in iad1 (VS), Neon in Frankfurt; ~70 trans-Atlantische rondes per Studio-lading
- [x] Vercel-functies vastgezet op fra1 (Frankfurt) — werkt na de volgende uitrol
- [x] Foutmelding noemt geen onjuiste "15 seconden" meer
- [ ] Productie opnieuw uitrollen en in Vercel controleren dat de functieregio fra1 is — eigenaar
- [ ] Wachtwoord van neondb_owner vernieuwen (opnieuw in de chat gedeeld) — eigenaar
- [ ] HTTP-driver van @neondatabase/serverless — niet gedaan: botst met de regel "alleen postgres-driver"; wacht op besluit eigenaar
- [x] Minder rondes per query en last_sign_in_at hooguit eens per uur — GO eigenaar 2026-11-17, zie hieronder

## Opdracht eigenaar 2026-11-17 16:45 UTC — GO query-optimalisatie profiel
- [x] Elke databasevraag gaat als één gebundeld pakket (één heen-en-terug in plaats van ~8); lokaal gemeten bij 80 ms vertraging: 670 ms → 86 ms
- [x] Profielstudio openen: profiel, aliasnaam, blauw schild en concept in één databaseronde (88 ms bij 80 ms vertraging); alleen de allereerste keer maakt het concept twee extra rondes
- [x] last_sign_in_at hooguit eens per uur, op de klok van de database (geen geheugen of cookie nodig)
- [x] JSON-waarden komen niet meer dubbel verpakt in de database (gevonden tijdens de meting)
- [ ] Sessiecontrole van Better Auth zelf (sessie + gebruiker) blijft aparte rondes — niet in deze opdracht

## Opdracht eigenaar 2026-11-17 — Sudo Mode + A1-backfill
- [x] /api/v1/auth/sudo: passkey-bevestiging opent een ondertekende sudo-sessie van precies 300 s, gebonden aan lid en inlogsessie
- [x] requireSudo op accountfusie, herstelkluis, hardware-identiteit, OAuth-secret, presence-sleutel, ingest-token en workspace-inboxsleutel
- [x] useSudoMode() + minimaal passkey-venster (nl/en/de/fr), tests in src/lib/auth/sudo.test.ts
- [x] A1-backfill alleen-lezen gecontroleerd op Neon: 3 profielen met oude payment_method, overige velden 0, profile_field_keys en verified_identity_nullifiers leeg
- [ ] A1-backfill echt draaien: ROUT_VAULT_KEK + DATABASE_URL op de eigen server, eerste veldsleutel laten registreren, dan `bun scripts/a1-backfill.ts` en `--apply` — eigenaar, met GO-nummer
- [ ] Sudo Mode live doorklikken met een echte passkey — vraagt DATABASE_URL en BETTER_AUTH_SECRET in een omgeving

## Opdracht eigenaar 2026-11-17 — Sovereign Identity OS, ROUT Sign, Developer Platform
- [x] 0281 stond al live op Neon (2026-11-15); providerhub, cross-provider nullifier, workspace-vragen en badges bestonden al
- [x] Vier scopes: sybil_proof (app_nullifier per app), real_human, age_gate:13–21 (app kiest één drempel), legal_identity (naam alleen na toestemming)
- [x] Nieuwe apps en API-sleutels (ook via AI-agent) alleen met KYC-identiteit; bestaande apps blijven werken
- [x] /console/docs: AI-prompts voor Lovable, Cursor en ChatGPT
- [x] DNSSEC verplicht voor elke domeinverificatie (eigen domein, werkruimtedomein, domeinclaim)
- [x] IBAN op steunpagina: Didit volstaat zonder naamcontrole; domeinroute houdt de naamcontrole (in 0290)
- [x] ROUT Sign fase 1 (/sign, /sign/<id>): PDF-schoonmaker, versleuteld in de browser, verplichte inzage, ondertekenen met passkey — geen PAdES
- [ ] 0290 op Neon zetten (klaar in db-pending/, getest op replay) — wacht op letterlijk "GO 0290"
- [ ] PAdES-LTA via een gekwalificeerde dienst (QTSP) — later, eigenaar kiest de dienst
- [ ] Leestijd wordt nu in de browser afgedwongen; server-side afdwingen vraagt een extra kolom (volgende migratie)


## Overdrachtsdossier 2026-11-17 (open)
- [x] Build fix: ageFloorFromVector import in src/lib/kyc/kyc-engine.server.ts
- [ ] Testsuite draaien; deellinks (getProfileShareUrl) en badge-rendering verifiëren
- [ ] 0290 op Neon — wacht op letterlijke "GO 0290"
- [ ] age_gate?min_age=N scope (13–21, standaard 18), consent + console docs
- [ ] PAdES-LTA via CSC API — wacht op keuze QTSP + credentials
- [ ] getProfileShareUrl + Studio "Kopieer link"/"Delen"
- [ ] Badges: alleen ontgrendelde publiek, blauw schild verplicht op hoofdprofiel, alias-schakelaar, heraldiek alleen in BadgeEmblem

## Identity OS follow-up (2026-11-17)
- [x] getProfileShareUrl + Studio/dashboard Copy/Share wired
- [x] Blue shield mandatory on KYC root; alias badge toggle default off
- [x] age_gate?min_age=N with minimal { age_verified, min_age } claims
- [x] Minor firewall (< 18) on userinfo
- [x] Touch fallback for careful typing
- [x] 0290 on Neon (applied 2026-11-17, checksum verified)
- [x] ECVRF (RFC 9381) app nullifiers
- [x] Minor firewall at token issuance
- [x] /login unified card with social, passkey and password fold-out
- [ ] Post-OAuth age modal (needs decision: no DOB storage)
- [ ] PAdES-LTA via CSC (waits for QTSP choice)

## Opdracht eigenaar 2026-11-18
- [ ] Blauw vinkje altijd naast naam op geverifieerd hoofdprofiel (@jdelplanche mist het)
- [ ] Popover-kaart bij blauw vinkje: naam · land, "Geverifieerd in <maand jaar>", validatietekst; alias alleen met show_verification_on_alias
- [ ] Wit vinkje op privé-alias (echt mens met geverifieerd profiel)
- [ ] Studio: wisselen naar donatiepagina + "Voorbeeld bekijken" werkt niet; pagina's niet correct aangemaakt
- [ ] Smart Entry aanmeldkaart op /login afmaken (vertalingen, koppelen, telefooncontrole)
- [ ] Volledige testreeks + typecheck, HANDOVER/roadmap bijwerken met 0291

## Copy into this Lovable project (GitHub import 2026-11-18)
- [x] Copy source code from Routbe/route-roam-d3a95b17@main
- [x] Restore managed build config with MDX + docs catalog; public pages render in preview
- [x] Keep Neon + passkeys (owner choice)
- [x] DATABASE_URL, BETTER_AUTH_SECRET, ROUT_VAULT_KEK added; database reachable (schema 0291)
- [ ] Owner tests a real passkey sign-in in the preview; add optional service keys (storage, Stripe, email) as needed

## Support treasury (/support/donations, /support/partners)
- [x] db/0293 support treasury: applied on Neon 2026-11-18 (owner GO, checksum 9bdffdc2…7d4a), snapshot + db types, schema level 0293
- [x] Donation flow: SEPA with Belgian structured communication + EPC QR, Stripe Checkout, bunq/Stripe webhooks, Merkle leaf + hybrid-signed root, signed receipt (PDF in browser), supporter SD-JWT VC, inclusion proof
- [x] Crypto-worker checks for credential, proof and signatures; donor crown on profiles only after the worker verifies the credential
- [x] Partner wall: suppliers listed as suppliers, live DNSSEC status
- [x] Treasury name defaults to "ROUT Sovereign Identity OS"; IBAN from ROUT_TREASURY_IBAN, else bunq main EUR account; BIC from ROUT_TREASURY_BIC
- [ ] Owner: set ROUT_TREASURY_IBAN (or the BUNQ_* keys) in the hosting environment; until then SEPA stays off
- [x] Monthly server costs: 15,090 cents (Infomaniak 4850, Scaleway 2840, Neon 2900, Didit 4500)
- [ ] Owner: bunq callback on the treasury account (BUNQ_SERVER_PUBLIC_KEY) and Stripe webhook secret (STRIPE_SUPPORT_WEBHOOK_SECRET or the existing endpoint)
- [ ] PQ hybrid signatures beyond treasury, OID4VCI/OID4VP, revocation: phased plan proposed, waits for owner approval

## PQ + EUDI wallet (approved plan 2026-11-18)
- [ ] A: shared hybrid signer, Sign/Didit/identity attestations, /.well-known/rout-pq-keys.json, worker op pq.verify
- [ ] B: OID4VCI issuer (metadata, pre-authorized code, token/nonce/credential), console tab
- [ ] C: OID4VP verifier (request object, direct_post, verification), console tools
- [x] D: Token Status List (JWT, compressed), migration replay-tested, live on Neon via 0294 (2026-11-19)

## EUDI Wallet / Post-Quantum overdracht (0294)
- [x] 0294 PGlite-replay + rollout dry run groen
- [x] 0294 live op Neon (2026-11-19 21:24 UTC, GO eigenaar, rollout-batch via Neon-connector)
- [x] NIST ACVP ML-DSA-65 fixture + hybride handtekeningtests
- [x] OID4VCI / OID4VP / Status List / zeroization tests
- [x] HANDOVER-appendix bijwerken na groene suite (enclave.test.ts groen sinds sign.envelope_sha256)
- [x] Verplichte DPoP (RFC 9449) op OID4VCI token + credential, 60 s jti-replaycache, metadata ES256/Ed25519
- [x] Test: status-list-JWT verankerd aan gepubliceerde sleutel (kid)

## ROUT-import in Lovable (2026-11-19)
- [x] Code uit github.com/Routbe/route-roam-31160c5a overgenomen: TanStack-routes, providers, assets, MDX-catalogus en db/ blijven ongewijzigd
- [x] Besluit eigenaar: gegevens blijven in Neon, geen Lovable Cloud
- [x] DATABASE_URL en BETTER_AUTH_SECRET veilig ingesteld (nooit via de chat): health-probe `operational`, schema 0294, aanmeldscherm biedt nu passkey, e-maillink en wachtwoord zonder waarschuwing
- [ ] Bevestigen: draait deze preview op productie-Neon of op een aparte kopie (eigenaar)
- [ ] E-mailbezorging (SMTP_PASS_AUTH / SMTP_PASS_SYSTEM), bestandsopslag (S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY, emmers) en betalingen (STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET) nog niet ingesteld
- [x] Account aanmaken met passkey end-to-end getest op de preview (2026-11-19); opnieuw inloggen met een bestaande passkey nog niet getest
- [ ] Dagelijkse cleanup (`/api/public/cron/cleanup-assets`) en de Omni-worker in `worker/` hebben op deze hosting nog geen uitvoerder

- [x] Sign page: envelope hash via crypto worker (sign.envelope_sha256) + guard test
- [x] DPoP: dual-layer jti replay (in-memory + db/0295 dpop_jti_replays via rout_dpop_jti_claim)
- [x] Owner: apply db/0294 then db/0295 on Neon (applied 2026-11-19 on owner GO; Neon at 0296)
- [x] Full vitest run 2026-11-19: 3,895 passed, 9 skipped, 0 failed
- [x] docs/HANDOVER.md appendix + roadmap synced (code level 0295, Neon 0293)
- [x] Deleted preview test account lovable-signin-test-20261119@example.com (2026-11-19)
- [x] Deleted the 17 older test accounts in Neon (2026-11-19)
- [x] Account purge cron fails on Neon: rout_app lacks SELECT/DELETE on oauth_email_deliveries + identity_link_events (fixed by db/0296 definer helper, live 2026-11-19; first real purge run not yet observed)

- [x] db/0296: account purge clears relay deliveries + identity history via definer helper (replay test green)
- [x] Owner: apply db/0294, 0295, 0296 on Neon (applied 2026-11-19 21:24-21:25 UTC on owner GO; history check 0 findings, definer check 0 findings)
- [x] Blue mark rosette, clickable crown, page buttons removed, Studio preview 1:1 marks

## Voorbeeld met productiesleutels (2026-11-19, keuze eigenaar)
- [x] Database (rout_app, geen superuser/RLS-omzeiling), aanmeldgeheim, Scaleway (3 buckets) en ROUT_VAULT_KEK ingesteld en gecontroleerd
- [ ] Inloggen op het voorbeeldadres: bestaande passkeys horen bij rout.be en werken hier niet — eigenaar beslist hoe (bv. een extra passkey voor het voorbeeld)
- [ ] Overige sleutels per functie (mail, sms, betalingen, wallet, sociale logins) pas opvragen wanneer een functie ze nodig heeft

## Agent-werkruimtes v1 (directief 2026-11-20, schemaniveau 0297)
- [ ] /api/v1/agent/workspace/create: één POST (rekenbewijs) → zandbak + werkruimte /w/<naam>-<4 Crockford-tekens> + optioneel profiel en inlog-app-specificaties
- [ ] /api/v1/agent/workspace/{id}/studio (GET/PATCH) en /api/v1/agent/developer/apps (GET/PUT) op dezelfde zandbakmotor
- [x] db/0297: achtervoegsel van gratis werkruimtes in Crockford base32 met botsingscontrole (live op Neon 2026-11-21 09:08 UTC, GO eigenaar, checksum cc43af53…8b74)
- [ ] /.well-known/mcp.json, OpenAPI 3.1 met de agent-ingangen (schema's uit de echte invoerregels), llms.txt bijwerken
- [ ] src/test/autonomous-agent-e2e.test.ts + volledige suite
- [ ] Antwoord eigenaar: zwaarte rekenpuzzel (nu ~1 s)

## Organisatieverificatie werkruimtes (directief 2026-11-20, schemaniveau 0298)
- [ ] Entiteitstypes ORGANIZATION / DOMAIN_BRAND / INDIVIDUAL_CREATOR / AUTONOMOUS_AGENT
- [ ] Domeinbinding via DNS TXT-uitdaging (_rout-challenge.<domein>)
- [ ] KBO/VIES-btw en LEI (GLEIF)-controle; nummers alleen verzegeld in vault_enclave, publiek enkel nullifier
- [ ] Volmachtbewijs (EAA) zonder persoonsgegevens van de beheerder op de werkruimte
- [ ] Rozetten: bedrijf / domein / persoon + popover
- [ ] db/0298 + src/test/organization-attestation.test.ts

## Naam bij blauw vinkje (besluit eigenaar 2026-11-21)
- [ ] Gebruikersnaam (hoofdprofiel) pas kiezen na verificatie; afgeleid van de geverifieerde naam
- [ ] Bij verificatie (Didit of team) met niet-passende hoofdnaam: automatisch hernoemen naar de eerste vrije toegestane variant
- [ ] Privé-aliassen vrij; door het team goedgekeurde aliassen blijven bruikbaar tot het team ze intrekt
- [ ] Door het team ingestelde voornaam/achternaam/bedrijfsnaam is wat de popover bij het blauwe vinkje toont

## Overdracht 21 nov 2026 (handover dossier + meldingen)
- [x] Werkruimte-profielfoto verschijnt niet op /w/<slug>: publieke weergave liet alleen `users/<uid>/avatar/` toe, niet `workspace-logo/` (image-proxy-rules.ts + test)
- [x] "ROUT OS v2.5"-statusregel bedekte de mobiele Studio-balk: alleen nog vanaf desktopbreedte
- [x] Studio-kruimelpad: ROUT > Studio > <handle> + paginakiezer (persoonlijk: /, /tip, /booking, /ask; workspace: /, /ask, /feedback, /support) met korte animatie en melding
- [ ] "Select text only"-wolkje (Samsung Internet, S26 Ultra): komt niet uit ROUT-code; wacht op schermafbeelding/plek van de eigenaar
- [x] P1: agent v1-routes aangesloten (workspace/create, workspace/$id/studio, developer/apps)
- [x] P2: ontdekking voor AI (/.well-known/mcp.json, llms.txt via src/content/seo, OpenAPI met /api/v1/agent/*, rout-agent.json)
- [ ] P3: handle pas na KYC, canonieke hernoeming na Didit, team-goedkeuringen, exacte admin-naam (wacht op eigenaarskeuzes + migratie-GO)
- [x] P4: autonomous-agent e2e-test (live deel met ROUT_E2E_ORIGIN), HANDOVER-appendix 0297
- [x] P4: volledige testsuite groen (3921 geslaagd, 10 overgeslagen, 0 mislukt)

## Prioriteit 3 — handles en dubbel profiel
- [x] Tests handle-generator, keuzescherm /verify/handle-select, Didit-terugkeer naar het keuzescherm
- [x] db/0298 live op Neon (2026-11-21, nagekeken)
- [x] Keuzescherm in nl/en/fr/de
- [ ] db-pending/0299 (CONTRACT): wacht tot productie schema 0298 meldt (eigenaar deployt main)
- [ ] Keuzescherm testen met een echte Didit-verificatie (eigenaar)
