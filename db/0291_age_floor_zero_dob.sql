-- 0291 (EXPAND + purge): zero raw date of birth. Members keep only a whole-year age floor.
--
-- Owner directive of 2026-11-17 ("ZK Age Floor Sheet & Smart Entry Card"): a raw date of birth is
-- never stored. The server reads it only in memory, computes the age in whole years (capped at 21,
-- the same scale as verified_identity_nullifiers.age_floor from 0290) and stores that number.
--   * public.users.age_floor (0..21) and age_floor_at (the day it was computed). The current age is
--     age_floor plus the whole years since age_floor_at, so it under-states the real age by less than
--     one year and every minor/Q&A protection fails closed.
--   * Existing users.date_of_birth values are converted once to age_floor and then erased; a CHECK
--     keeps the column empty from here on (the column itself is dropped by a later CONTRACT).
--   * rout_users_minor_sync, rout_user_is_minor and rout_profile_qa_level read the age floor.
--   * rout_record_signup_age_floor(): the sign-up path, given only the floor.
--     rout_record_signup_age(.., date, ..) keeps its signature for deploy-order freedom; it turns the
--     date into the floor inside this call and never stores it.
--   * rout_record_my_age_floor(): the post-sign-in age sheet; caller from rout.current_user_id, once.
--   * rout_my_age_floor(): the caller's own current floor (self-declared or KYC), or null.
-- Held in db-pending/ until the owner's explicit GO for 0291; it runs after 0290. One-way once data
-- exists: the erased dates cannot come back.

alter table public.users add column if not exists age_floor smallint;
alter table public.users add column if not exists age_floor_at date;

do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'users_age_floor_shape') then
    alter table public.users add constraint users_age_floor_shape check (
      (age_floor is null and age_floor_at is null)
      or (age_floor between 0 and 21 and age_floor_at is not null));
  end if;
end $$;

-- The old trigger would re-tighten Q&A levels during the conversion; the new one is created below.
drop trigger if exists rout_users_minor_sync on public.users;

update public.users
   set age_floor = least(21, pg_catalog.date_part('year', pg_catalog.age(current_date::timestamp, date_of_birth::timestamp))::integer)::smallint,
       age_floor_at = current_date,
       is_minor = pg_catalog.date_part('year', pg_catalog.age(current_date::timestamp, date_of_birth::timestamp)) < 16
 where date_of_birth is not null and age_floor is null;

update public.users set date_of_birth = null where date_of_birth is not null;

do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'users_no_birth_date') then
    alter table public.users add constraint users_no_birth_date check (date_of_birth is null);
  end if;
end $$;

create or replace function public.rout_users_minor_sync()
 returns trigger
 language plpgsql
 set search_path = pg_catalog, pg_temp
as $function$
declare v_age integer;
begin
  v_age := case when new.age_floor is null then null
                else least(21, new.age_floor + pg_catalog.date_part('year',
                       pg_catalog.age(current_date::timestamp, new.age_floor_at::timestamp))::integer) end;
  new.is_minor := v_age is not null and v_age < 16;
  if v_age is not null and v_age < 18
     and (tg_op = 'INSERT' or old.age_floor is distinct from new.age_floor) then
    new.qa_permission_level := 'verified_only';
  end if;
  return new;
end $function$;

create trigger rout_users_minor_sync before insert or update of age_floor, age_floor_at on public.users
  for each row execute function public.rout_users_minor_sync();

create or replace function public.rout_user_is_minor(p_user_id uuid)
 returns boolean
 language sql
 stable security definer
 set search_path = pg_catalog, pg_temp
as $function$
  select coalesce((select u.age_floor + pg_catalog.date_part('year',
                     pg_catalog.age(current_date::timestamp, u.age_floor_at::timestamp))::integer < 16
                     from public.users u where u.id = p_user_id), false)
$function$;

create or replace function public.rout_profile_qa_level(p_handle text)
 returns public.qa_permission_level
 language sql
 stable security definer
 set search_path = pg_catalog, pg_temp
as $function$
  select case when u.qa_permission_level <> 'public_unrestricted' then u.qa_permission_level
              when u.age_floor is not null
               and u.age_floor + pg_catalog.date_part('year',
                     pg_catalog.age(current_date::timestamp, u.age_floor_at::timestamp))::integer < 16
                then 'verified_only'::public.qa_permission_level
              else u.qa_permission_level end
    from public.profiles p join public.users u on u.id = p.id
   where pg_catalog.lower(p.username) = pg_catalog.lower(p_handle)
   limit 1
$function$;

create function public.rout_record_signup_age_floor(p_email text, p_age_floor smallint, p_parent_email text, p_token_hash text)
 returns uuid
 language plpgsql
 security definer
 set search_path = pg_catalog, pg_temp
as $function$
declare v_id uuid; v_minor boolean;
begin
  if p_age_floor is null or p_age_floor not between 0 and 21 then return null; end if;
  select u.id into v_id from public.users u
   where pg_catalog.lower(u.email) = pg_catalog.lower(p_email) and u.age_floor is null
     and u.created_at > pg_catalog.now() - interval '15 minutes'
   limit 1;
  if v_id is null then return null; end if;
  v_minor := p_age_floor < 16;
  update public.users
     set age_floor = p_age_floor,
         age_floor_at = current_date,
         parent_email = case when v_minor then pg_catalog.lower(p_parent_email) else null end,
         parent_consent_status = case when v_minor then 'pending'::public.parent_consent_status else 'none'::public.parent_consent_status end
   where id = v_id;
  if v_minor and p_token_hash is not null then
    insert into public.parent_authorizations (user_id, token, action_type, expires_at)
    values (v_id, p_token_hash, 'consent', pg_catalog.now() + interval '30 days');
  end if;
  return v_id;
end $function$;

create or replace function public.rout_record_signup_age(p_email text, p_dob date, p_parent_email text, p_token_hash text)
 returns uuid
 language plpgsql
 security definer
 set search_path = pg_catalog, pg_temp
as $function$
begin
  if p_dob is null or p_dob > current_date then return null; end if;
  return public.rout_record_signup_age_floor(p_email,
    least(21, pg_catalog.date_part('year', pg_catalog.age(current_date::timestamp, p_dob::timestamp))::integer)::smallint,
    p_parent_email, p_token_hash);
end $function$;

create function public.rout_record_my_age_floor(p_age_floor smallint, p_parent_email text, p_token_hash text)
 returns text
 language plpgsql
 security definer
 set search_path = pg_catalog, pg_temp
as $function$
declare
  v_user  uuid := public.rout_current_user_id();
  v_minor boolean;
  v_own   text;
begin
  if v_user is null then return 'no_member'; end if;
  if p_age_floor is null or p_age_floor not between 0 and 21 then return 'invalid_input'; end if;
  v_minor := p_age_floor < 16;
  if v_minor then
    if p_parent_email is null or p_parent_email !~ '^[^\s@]+@[^\s@]+\.[^\s@]+$' or pg_catalog.length(p_parent_email) > 254
       or p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$' then
      return 'parent_required';
    end if;
    select u.email into v_own from public.users u where u.id = v_user;
    if pg_catalog.lower(p_parent_email) = pg_catalog.lower(coalesce(v_own, '')) then return 'parent_email_same'; end if;
  end if;
  update public.users
     set age_floor = p_age_floor,
         age_floor_at = current_date,
         parent_email = case when v_minor then pg_catalog.lower(p_parent_email) else parent_email end,
         parent_consent_status = case when v_minor then 'pending'::public.parent_consent_status else parent_consent_status end
   where id = v_user and age_floor is null;
  if not found then return 'already_set'; end if;
  if v_minor then
    insert into public.parent_authorizations (user_id, token, action_type, expires_at)
    values (v_user, p_token_hash, 'consent', pg_catalog.now() + interval '30 days');
  end if;
  return 'ok';
end $function$;

create function public.rout_my_age_floor()
 returns smallint
 language sql
 stable security definer
 set search_path = pg_catalog, pg_temp
as $function$
  -- least() and greatest() skip nulls, so the cap is applied only to a known age.
  select case when s.g is null then null else least(21, s.g)::smallint end
    from (select greatest(
      (select u.age_floor + pg_catalog.date_part('year',
                pg_catalog.age(current_date::timestamp, u.age_floor_at::timestamp))::integer
         from public.users u where u.id = public.rout_current_user_id()),
      (select pg_catalog.max(n.age_floor)::integer from public.verified_identity_nullifiers n
        where n.user_id = public.rout_current_user_id())) as g) s
$function$;

revoke all on function public.rout_record_signup_age_floor(text, smallint, text, text) from public, rout_app;
revoke all on function public.rout_record_my_age_floor(smallint, text, text) from public, rout_app;
revoke all on function public.rout_my_age_floor() from public, rout_app;
grant execute on function public.rout_record_signup_age_floor(text, smallint, text, text) to rout_app;
grant execute on function public.rout_record_my_age_floor(smallint, text, text) to rout_app;
grant execute on function public.rout_my_age_floor() to rout_app;
