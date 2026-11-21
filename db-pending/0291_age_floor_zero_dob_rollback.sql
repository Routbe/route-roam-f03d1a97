-- Rollback of 0291 (zero raw date of birth). The erased dates cannot be restored, so this refuses
-- while any age floor is recorded; on an empty database it restores the 0290 state exactly.
do $$
begin
  if exists (select 1 from public.users where age_floor is not null) then
    raise exception 'rollback_0291_refused: age floors recorded (erased birth dates cannot come back)';
  end if;
end $$;

drop function if exists public.rout_my_age_floor();
drop function if exists public.rout_record_my_age_floor(smallint, text, text);

create or replace function public.rout_record_signup_age(p_email text, p_dob date, p_parent_email text, p_token_hash text)
 returns uuid
 language plpgsql
 security definer
 set search_path = pg_catalog, pg_temp
as $function$
declare v_id uuid; v_minor boolean;
begin
  select id into v_id from public.users
   where lower(email) = lower(p_email) and date_of_birth is null and created_at > now() - interval '15 minutes'
   limit 1;
  if v_id is null then return null; end if;
  v_minor := p_dob > (current_date - interval '16 years');
  update public.users
     set date_of_birth = p_dob,
         parent_email = case when v_minor then lower(p_parent_email) else null end,
         parent_consent_status = case when v_minor then 'pending'::public.parent_consent_status else 'none' end
   where id = v_id;
  if v_minor and p_token_hash is not null then
    insert into public.parent_authorizations (user_id, token, action_type, expires_at)
    values (v_id, p_token_hash, 'consent', now() + interval '30 days');
  end if;
  return v_id;
end $function$;

drop function if exists public.rout_record_signup_age_floor(text, smallint, text, text);

create or replace function public.rout_profile_qa_level(p_handle text)
 returns public.qa_permission_level
 language sql
 stable security definer
 set search_path = pg_catalog, pg_temp
as $function$
  select case when u.qa_permission_level <> 'public_unrestricted' then u.qa_permission_level
              when u.date_of_birth > (current_date - interval '16 years') then 'verified_only'::public.qa_permission_level
              else u.qa_permission_level end
    from public.profiles p join public.users u on u.id = p.id
   where lower(p.username) = lower(p_handle)
   limit 1
$function$;

create or replace function public.rout_user_is_minor(p_user_id uuid)
 returns boolean
 language sql
 stable security definer
 set search_path = pg_catalog, pg_temp
as $function$
  select coalesce((select u.date_of_birth > (current_date - interval '16 years') from public.users u where u.id = p_user_id), false)
$function$;

drop trigger if exists rout_users_minor_sync on public.users;
create or replace function public.rout_users_minor_sync()
 returns trigger
 language plpgsql
 set search_path = public
as $function$
begin
  new.is_minor := new.date_of_birth is not null and new.date_of_birth > (current_date - interval '16 years');
  if new.date_of_birth is not null and new.date_of_birth > (current_date - interval '18 years')
     and (tg_op = 'INSERT' or old.date_of_birth is distinct from new.date_of_birth) then
    new.qa_permission_level := 'verified_only';
  end if;
  return new;
end $function$;
create trigger rout_users_minor_sync before insert or update of date_of_birth on public.users
  for each row execute function public.rout_users_minor_sync();

alter table public.users drop constraint if exists users_no_birth_date;
alter table public.users drop constraint if exists users_age_floor_shape;
alter table public.users drop column if exists age_floor_at;
alter table public.users drop column if exists age_floor;
