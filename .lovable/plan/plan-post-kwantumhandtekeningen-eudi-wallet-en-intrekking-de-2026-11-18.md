# Plan: post-kwantumhandtekeningen, EUDI-wallet en intrekking (deel 3)

Deel 1, 2 en 4 zijn klaar: 0293 draait op Neon, de dekkingsbalk staat op €150,90 en de bankgegevens komen uit de hostinginstellingen of uit bunq. Deel 3 is te groot voor één keer en raakt de vaste regels uit het overdrachtsdossier. Daarom splits ik het op in vier fasen, elk met eigen tests en elk apart goed te keuren.

## Drie correcties op de opdracht

1. **RSG1 versleutelt, het ondertekent niet.** Een RSG1-envelop sluit een pdf af met AES-256-GCM. "RSG1 dubbel ondertekenen" betekent dus: een aparte hybride handtekening (Ed25519 + ML-DSA-65) over de vingerafdruk van de envelop. Het RSG1-formaat zelf verandert niet, zodat alle bestaande documenten blijven openen.
2. **EUDI-wallets gebruiken geen accumulators voor intrekking.** Het EU-walletkader (ARF/HAIP) schrijft de IETF *Token Status List* voor: een gecomprimeerde, ondertekende bitlijst met één bit per credential. Dat is wat wallets echt kunnen controleren. Geen enkele EUDI-wallet ondersteunt vandaag een cryptografische accumulator met zero-knowledge non-membership. Mijn voorstel: Token Status List voor wallets, met een accumulator als optionele extra die alleen ROUT gebruikt (fase D).
3. **ML-DSA in wallets.** EUDI-wallets aanvaarden vandaag ES256 (P-256), geen ML-DSA. Credentials voor wallets worden daarom ondertekend met ES256 + Ed25519. De ML-DSA-65-handtekening reist mee als extra bewijs, dat ROUT-verifiers wel controleren. Anders kan geen enkele wallet het credential lezen.

## Fase A: hybride handtekeningen overal (ca. 1 à 2 dagen)
- Eén gedeelde ondertekenaar, gebouwd op de al geteste schatkist-ondertekenaar. Elk doel krijgt een eigen domeinlabel (`rout.sign.attest.v1`, `rout.didit.attest.v1`, `rout.identity.doc.v1`) en een eigen sleutel, afgeleid van ROUT_SUBJECT_MASTER_KEY.
- Sign: bij het ondertekenen tekent de server {SHA-256 van de envelop, signer-binding, tijdstip}. Die handtekening wordt bewaard naast het bestaande handtekeningrecord (nieuwe migratie 0294, alleen toevoegend). De pdf toont "Ed25519 + ML-DSA-65 geldig" pas nadat de crypto-worker het heeft gecontroleerd.
- Didit: elk nieuw Didit-resultaat krijgt een hybride attestatie, zonder persoonsgegevens (alleen een commitment). Het blauwe-vinkkaartje toont de PQ-regel pas na verificatie.
- Identiteitsdocumenten: dezelfde losse handtekening over de vingerafdruk van de verzegelde kopie. Leesbare inhoud komt nooit op de server.
- Publieke sleutels op `/.well-known/rout-pq-keys.json` (Ed25519 + ML-DSA-65, met sleutel-id's).

## Fase B: OID4VCI, credentials uitgeven aan wallets (ca. 3 à 4 dagen)
- Uitgevergegevens op `/.well-known/openid-credential-issuer`, plus de gegevens van de autorisatieserver.
- Pre-authorized code flow met transactiecode, en daarna token-, nonce- en credential-endpoints. Het credential-endpoint vraagt een key-binding-proof.
- Eerste soorten credentials: ROUT Supporter (bestaat al als SD-JWT VC) en "Geverifieerd mens / ouder dan N". Die laatste gebruikt alleen gegevens die we al hebben, dus geen nationaliteit.
- Formaat: SD-JWT VC (`dc+sd-jwt`). mdoc (ISO 18013-5) laat ik voorlopig weg.
- Developer Console: een nieuw tabblad "Wallet-uitgifte" met een QR-code voor de credential-offer en een testlog.

## Fase C: OID4VP, walletpresentaties controleren (ca. 2 à 3 dagen)
- Op `/oauth` kan een app om een walletpresentatie vragen (DCQL, `direct_post`, ondertekend verzoek).
- De controle omvat: de handtekening van de uitgever, de key-binding, nonce en ontvanger, en de status via de lijst uit fase D.
- Developer Console: een verzoekbouwer en een presentatie-inspecteur.

## Fase D: intrekking (ca. 1 à 2 dagen)
- Token Status List volgens het IETF-ontwerp, zoals EUDI vereist. De lijst is ondertekend als JWT en gecomprimeerd, met één index per uitgegeven credential (migratie 0295).
- Optioneel: een RSA-accumulator met non-membership-bewijzen, alleen voor ROUT-verifiers. Die heet pas echt "zero-knowledge" als er ook een bewijssysteem bij komt. Zonder dat noem ik het een accumulatorbewijs.

## Wat ik van je nodig heb
- Goedkeuring per fase, of "A t/m D op volgorde".
- Is mdoc nu al nodig, of later?
- Wil je de accumulator voor alleen ROUT bovenop de statuslijst in fase D?

## Technische details
- Elke nieuwe migratie gaat via `scripts/migration-rollout.ts`, en alleen na een aparte GO. Definers krijgen search_path pg_catalog, pg_temp, en rout_app krijgt geen tabelrechten.
- Elke nieuwe createServerFn krijgt een guard of een vermelding in PUBLIC_SERVER_FNS. Elke publieke route onder /api/public controleert zelf de beller en de invoer.
- Alle controles in de browser lopen via de crypto-worker (nieuwe ops `pq.verify` en `vc.verify_status`), zonder terugval op de UI-thread.
- Tests: bekende testvectoren voor ML-DSA-65 (FIPS 204), een OID4VCI/OID4VP-flowtest tegen onze eigen endpoints, een encode/decode-test voor de statuslijst, en replaytests voor 0294 en 0295.
