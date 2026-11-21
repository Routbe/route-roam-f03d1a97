# ROUT overdracht: stap 1-3 (zero-trust, optie A)

## Al gecontroleerd tegen de code
- Checksum `db/0294_eudi_wallet.sql` = `ede24dc6...7127` (klopt).
- 0294 maakt `oid4vci_offers`, `wallet_credentials`, `oid4vp_requests` aan.
- `CODE_SCHEMA_LEVEL` = `0294`; Neon staat op `0293`.
- Test heet `src/test/migration-0294.test.ts`.

## Stap 1 — Migratie 0294 (optie A, niets op Neon vanuit hier)
1. `roadmap.md`: taken uit deze richtlijn toevoegen.
2. Lokaal draaien: `migration-0294.test.ts` + `migration-rollout.test.ts` (PGlite-replay, dry run).
3. Statische controle van 0294: RLS aan op alle drie tabellen, geen tabelrechten voor `rout_app`, alle SECURITY DEFINER-functies met `search_path = pg_catalog, pg_temp`, expliciete EXECUTE-grants.
4. Neon: ik voer niets uit. Jij draait zelf `bun scripts/migration-rollout.ts --apply db/0294_eudi_wallet.sql`. Daarna doe ik alleen een leescontrole (0294 geregistreerd, tabellen/functies/rechten aanwezig).

## Stap 2 — Testsuite deel 3
- Fixture `src/test/fixtures/ml-dsa-65-acvp.json`: echte NIST ACVP-vectoren (ML-DSA-65 keyGen/sigVer) gedownload uit de officiële NIST ACVP-Server repository, met bronvermelding en commit — nooit zelf verzonnen. Plus Ed25519-vectoren uit RFC 8032 voor het hybride deel.
- Tests (eerst de bestaande code lezen; tests volgen wat er echt gebouwd is):
  - Hybride handtekening: beide geldig = ok; één van beide fout = afgewezen.
  - OID4VCI: aanbod → token (DPoP indien de code dat ondersteunt) → SD-JWT VC met holder key-binding; foute/verlopen/verkeerde-nonce proof direct geweigerd.
  - OID4VP: DCQL-match, nonce- en audience-controle, mismatch afgewezen.
  - Token Status List: bit zetten/lezen, gecomprimeerde status-list-JWT verifiëren, ingetrokken credential faalt. ZK-accumulator alleen als die in de code bestaat; anders meld ik dat.
  - Zeroization: na elke worker-operatie zijn sleutel- en proofbuffers aantoonbaar nul.
- Als een test een echte fout in de app blootlegt, meld ik die en wacht ik op jouw GO voor een codewijziging.
- Volledige suite draaien; exacte aantallen geslaagd/overgeslagen/gefaald rapporteren.

## Stap 3 — Documentatie (pas als alles groen is)
- `docs/HANDOVER.md`: 0294-status alleen in de appendix (genummerde secties blijven letterlijk).
- `roadmap.md`: EUDI/PQ-mijlpalen afvinken; "0294 live op Neon" blijft open tot jouw uitrol.

## Buiten scope
IBAN/BIC, Stripe-webhooksecret, bunq-sleutels: bij livegang, op je eigen hosting.
