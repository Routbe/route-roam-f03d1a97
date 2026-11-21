-- 0292 (EXPAND): minor firewall for the public blue-mark card.
--
-- Owner directive of 2026-11-18: when the owner of a public profile is under 18, the verification
-- card shows only the first name and the initial of the last name. rout_user_is_minor answers
-- "under 16" (consent age), so this adds a separate under-18 check:
--   * rout_public_owner_is_minor(uuid): true when the best known age of that member is below 18,
--     taken from the self-declared age floor (aged with the calendar) or the KYC age floor
--     (verified_identity_nullifiers, 0290). Unknown age = false. Returns one boolean, never the age.
-- Applied on the owner's explicit GO for 0292 (2026-11-18); it runs after 0291. Rollback: db-pending/.

create or replace function public.rout_public_owner_is_minor(p_user_id uuid)
 returns boolean
 language sql
 stable security definer
 set search_path = pg_catalog, pg_temp
as $function$
  select coalesce(s.g < 18, false)
    from (select greatest(
      (select u.age_floor + pg_catalog.date_part('year',
                pg_catalog.age(current_date::timestamp, u.age_floor_at::timestamp))::integer
         from public.users u where u.id = p_user_id),
      (select pg_catalog.max(n.age_floor)::integer from public.verified_identity_nullifiers n
        where n.user_id = p_user_id)) as g) s
$function$;

revoke all on function public.rout_public_owner_is_minor(uuid) from public, rout_app;
grant execute on function public.rout_public_owner_is_minor(uuid) to rout_app;
