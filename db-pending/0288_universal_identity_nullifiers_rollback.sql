-- Rollback of 0288. Refuses once any nullifier is registered: dropping the table would let the
-- same document attest a second account.
do $$ begin
  if exists (select 1 from public.verified_identity_nullifiers) then
    raise exception 'rollback_refused: verified_identity_nullifiers holds attestations';
  end if;
end $$;

-- Restore the db/0282 bodies first (they no longer reference the table).
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
        or (coalesce(vi.tier_2_legal_identity, false) and vi.national_id_nullifier is not null) as legal,
      coalesce(vi.tier_1_real_human, false)
        or (coalesce(iv.is_verified, false) and iv.verification_provider::text in ('w_identity', 'didit', 'manual')) as human
    from public.profiles p
    left join public.identity_verifications iv on iv.user_id = p.id
    left join public.verified_identities vi on vi.user_id = p.id
    where p.id = any (coalesce(p_user_ids[1:200], '{}'::uuid[]))
  )
  select t.id, t.legal, t.legal or t.human from t
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
       or (coalesce(vi.tier_2_legal_identity, false) and vi.national_id_nullifier is not null))
$function$;

drop function public.rout_kyc_attest(text, text[], text[], boolean, boolean, text);
drop table public.verified_identity_nullifiers;
