-- 0296: automated GDPR Art. 17 deletion of e-mail relay deliveries and identity-link history.
--
-- The purge cron (accountPurgeStatements) deleted public.oauth_email_deliveries and
-- public.identity_link_events as rout_app, which holds no DELETE on either (0143 closed the first,
-- 0113/0117 grant only select, insert on the second, and its append-only trigger refuses every
-- delete). Every due account therefore rolled back on Neon. Instead of widening rout_app with
-- SELECT/DELETE on all rows, both tables are cleared by one SECURITY DEFINER function that
-- re-checks on the database that the deletion is due (public.rout_purge_due), inside the purge's
-- own transaction, so the whole account still goes atomically or not at all.

-- The identity-event chain stays append-only, except for rows of an account whose purge is due
-- and that this transaction explicitly marked for erasure through the function below.
create or replace function public.identity_event_chain() returns trigger
language plpgsql set search_path = pg_catalog, pg_temp as $$
declare owner_id uuid;
begin
  if TG_OP = 'DELETE' then
    if pg_catalog.current_setting('rout.identity_event_purge', true) = OLD.user_id::text
       and public.rout_purge_due(OLD.user_id) then
      return OLD;
    end if;
    raise exception 'identity_events_append_only';
  end if;
  if TG_OP <> 'INSERT' then raise exception 'identity_events_append_only'; end if;
  -- Serialize the chain on the identity row, including the first event.
  select user_id into owner_id from public.identity_links where id = NEW.link_id for update;
  if owner_id is null or owner_id <> NEW.user_id then raise exception 'identity_event_owner_mismatch'; end if;
  select event_hash into NEW.prev_hash from public.identity_link_events where link_id = NEW.link_id order by id desc limit 1;
  NEW.event_hash := public.digest(coalesce(NEW.prev_hash, ''::bytea) || convert_to(
    jsonb_build_object('link_id',NEW.link_id,'user_id',NEW.user_id,'event',NEW.event,'actor',NEW.actor,
      'ip_hash',encode(NEW.ip_hash,'hex'),'ua_hash',encode(NEW.ua_hash,'hex'),
      'created_at',to_char(NEW.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))::text,'UTF8'),'sha256');
  return NEW;
end $$;
revoke all on function public.identity_event_chain() from public;

create or replace function public.rout_identity_records_purge(p_user uuid)
returns void language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
begin
  if not public.rout_purge_due(p_user) then raise exception 'purge_not_due' using errcode = '42501'; end if;
  delete from public.oauth_email_deliveries where user_id = p_user;
  -- Lasts until the end of the purge transaction, so identity_links cascades are allowed too.
  perform pg_catalog.set_config('rout.identity_event_purge', p_user::text, true);
  delete from public.identity_link_events where user_id = p_user;
end $$;
revoke all on function public.rout_identity_records_purge(uuid) from public, rout_app;
grant execute on function public.rout_identity_records_purge(uuid) to rout_app;
