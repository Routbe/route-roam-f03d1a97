-- 0288 (EXPAND, additive): universal identity nullifiers across providers.
--
-- Owner directive 2026-11-17 ("Cross-Provider ICAO Doc 9303 / eIDAS Universal Nullifier Pipeline"):
--   * No name, BSN, national register number or document number is ever stored. A provider result
--     is reduced in the app to universal_nullifier = BLAKE3(Poseidon256(canonical_id) || pepper)
--     (src/lib/kyc/nullifier.ts) over the canonical ICAO/eIDAS anchor (src/lib/kyc/canonical-id.ts).
--   * public.verified_identity_nullifiers keeps one row per anchor with a UNIQUE nullifier, the
--     provider, the claims (is_real_human, has_legal_identity) and the ISO 3166-1
--     alpha-3 jurisdiction.
--   * rout_kyc_attest registers the anchors for the caller (rout.current_user_id only). An anchor
--     another account already holds through a different provider answers
--     'identity_already_attested_across_providers', through the same provider 'duplicate_human'.
--   * Each row names its evidence: 'kyc_document' (a document read by a KYC/eIDAS provider) or
--     'zk_proof' (a zero-knowledge humanity proof). rout_kyc_attest writes only 'kyc_document' and
--     refuses the zero-knowledge provider; 'zk_proof' rows get their own verifier later.
--   * Badges (owner directive 2026-11-17 13:45 UTC, strictly separate): the blue "KYC Attested"
--     shield (didit_legal_identity) comes from a KYC attestation only; the green "Real Human"
--     shield (real_human) comes EXCLUSIVELY from a 'zk_proof' row. A KYC liveness check, W Identity,
--     a manual review or a payment never grants the green shield, and a KYC attestation no longer
--     implies it. rout_public_identity_badges and rout_public_didit_member_count (db/0282) keep
--     their signatures and grants.
-- rout_app reads only its own rows (no nullifier column) and writes only through rout_kyc_attest.
-- Held in db-pending/ until the owner's explicit GO for 0288; it runs after 0287.

create table public.verified_identity_nullifiers (
  universal_nullifier text primary key check (universal_nullifier ~ '^[0-9a-f]{64}$'),
  user_id             uuid not null references public.users(id) on delete cascade,
  provider            text not null check (provider in ('didit', 'w_identity', 'itsme', 'digid', 'eid', 'france_identite',
                        'mitid', 'cie', 'idnow', 'shufti_pro', 'trulioo', 'world_id', 'manual')),
  anchor_kind         text not null check (anchor_kind in ('personal_number', 'document', 'provider_subject')),
  is_real_human       boolean not null default false,
  has_legal_identity  boolean not null default false,
  jurisdiction        text check (jurisdiction is null or jurisdiction ~ '^[A-Z]{3}$'),
  evidence            text not null check (evidence in ('kyc_document', 'zk_proof')),
  attested_at         timestamptz not null default now(),
  -- A zero-knowledge humanity proof says nothing about a legal identity.
  constraint verified_identity_nullifiers_zk_no_legal check (evidence = 'kyc_document' or not has_legal_identity)
);
create index verified_identity_nullifiers_user_id_fkx on public.verified_identity_nullifiers (user_id);

alter table public.verified_identity_nullifiers enable row level security;
revoke all on table public.verified_identity_nullifiers from public, rout_app;
grant select (user_id, provider, anchor_kind, is_real_human, has_legal_identity, jurisdiction, evidence, attested_at)
  on table public.verified_identity_nullifiers to rout_app;
create policy rout_scope on public.verified_identity_nullifiers
  for select to rout_app using (user_id = public.rout_current_user_id());
-- Same visibility as identity_verifications / verified_identities for the atomic merge executor (db/0152).
grant select on table public.verified_identity_nullifiers to rout_merge_executor;
create policy atomic_merge_executor on public.verified_identity_nullifiers
  for select to rout_merge_executor using (true);

create function public.rout_kyc_attest(
  p_provider text, p_nullifiers text[], p_anchor_kinds text[],
  p_is_real_human boolean, p_has_legal_identity boolean, p_jurisdiction text)
 returns text
 language plpgsql
 security definer
 set search_path = pg_catalog, pg_temp
as $function$
declare
  v_user  uuid := public.rout_current_user_id();
  v_n     integer := coalesce(pg_catalog.array_length(p_nullifiers, 1), 0);
  v_other text;
  v_nf    text;
begin
  if v_user is null then
    return 'no_context';
  end if;
  if v_n = 0 or v_n > 4 or v_n <> coalesce(pg_catalog.array_length(p_anchor_kinds, 1), 0)
     or exists (select 1 from pg_catalog.unnest(p_nullifiers) x where x is null or x !~ '^[0-9a-f]{64}$')
     or exists (select 1 from pg_catalog.unnest(p_anchor_kinds) k where k is null or k not in ('personal_number', 'document', 'provider_subject'))
     or (p_jurisdiction is not null and p_jurisdiction !~ '^[A-Z]{3}$')
     or p_provider is null or p_is_real_human is null or p_has_legal_identity is null
     -- World ID is a zero-knowledge proof, never a KYC document; it gets its own verifier.
     or p_provider = 'world_id' then
    return 'invalid_input';
  end if;
  -- Serialise attempts on the same anchors (sorted, so two attempts never wait on each other in a cycle).
  for v_nf in select x from pg_catalog.unnest(p_nullifiers) x order by x loop
    perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(v_nf, 288));
  end loop;
  select n.provider into v_other
    from public.verified_identity_nullifiers n
   where n.universal_nullifier = any (p_nullifiers) and n.user_id <> v_user
   order by n.attested_at
   limit 1;
  if v_other is not null then
    return case when v_other = p_provider then 'duplicate_human' else 'identity_already_attested_across_providers' end;
  end if;
  insert into public.verified_identity_nullifiers
      (universal_nullifier, user_id, provider, anchor_kind, is_real_human, has_legal_identity, jurisdiction, evidence)
    select a.nf, v_user, p_provider, a.kind, p_is_real_human, p_has_legal_identity, p_jurisdiction, 'kyc_document'
      from rows from (pg_catalog.unnest(p_nullifiers), pg_catalog.unnest(p_anchor_kinds)) as a(nf, kind)
  on conflict (universal_nullifier) do nothing;
  return 'ok';
end
$function$;
revoke all on function public.rout_kyc_attest(text, text[], text[], boolean, boolean, text) from public, rout_app;
grant execute on function public.rout_kyc_attest(text, text[], text[], boolean, boolean, text) to rout_app;

create or replace function public.rout_public_identity_badges(p_user_ids uuid[])
 returns table(user_id uuid, didit_legal_identity boolean, real_human boolean)
 language sql
 stable
 security definer
 set search_path = pg_catalog, pg_temp
as $function$
  with t as (
    select p.id,
      (coalesce(iv.is_verified, false) and iv.verification_provider::text = 'didit')
        or (coalesce(vi.tier_2_legal_identity, false) and vi.national_id_nullifier is not null)
        or exists (select 1 from public.verified_identity_nullifiers n
                    where n.user_id = p.id and n.evidence = 'kyc_document' and n.has_legal_identity) as legal,
      exists (select 1 from public.verified_identity_nullifiers n
               where n.user_id = p.id and n.evidence = 'zk_proof' and n.is_real_human) as human
    from public.profiles p
    left join public.identity_verifications iv on iv.user_id = p.id
    left join public.verified_identities vi on vi.user_id = p.id
    where p.id = any (coalesce(p_user_ids[1:200], '{}'::uuid[]))
  )
  select t.id, t.legal, t.human from t
$function$;

create or replace function public.rout_public_didit_member_count()
 returns integer
 language sql
 stable
 security definer
 set search_path = pg_catalog, pg_temp
as $function$
  select pg_catalog.count(*)::integer
    from public.profiles p
    left join public.identity_verifications iv on iv.user_id = p.id
    left join public.verified_identities vi on vi.user_id = p.id
   where p.username is not null
     and coalesce(p.is_banned, false) = false
     and coalesce(p.is_suspended, false) = false
     and ((coalesce(iv.is_verified, false) and iv.verification_provider::text = 'didit')
       or (coalesce(vi.tier_2_legal_identity, false) and vi.national_id_nullifier is not null)
       or exists (select 1 from public.verified_identity_nullifiers n
                   where n.user_id = p.id and n.evidence = 'kyc_document' and n.has_legal_identity))
$function$;

revoke all on function public.rout_public_identity_badges(uuid[]) from public;
grant execute on function public.rout_public_identity_badges(uuid[]) to rout_app;
revoke all on function public.rout_public_didit_member_count() from public;
grant execute on function public.rout_public_didit_member_count() to rout_app;
