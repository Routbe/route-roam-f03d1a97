-- 0295: DPoP jti replay ledger shared by every server instance (EXPAND, additive).
--
--   dpop_jti_replays  one row per accepted DPoP proof, keyed by the hex SHA-256 of
--                     (key thumbprint, jti) (src/lib/eudi/dpop.ts jtiReplayHash); never the jti,
--                     the key or the token itself. The primary key makes the claim atomic across
--                     instances: of two concurrent claims of one hash exactly one inserts. Expiry
--                     is measured on the database clock, so instance clocks cannot reopen a window.
-- rout_app gets no table rights; the only door is rout_dpop_jti_claim.

create table if not exists public.dpop_jti_replays (
  jti_hash    text primary key check (jti_hash ~ '^[0-9a-f]{64}$'),
  expires_at  timestamptz not null
);
create index if not exists dpop_jti_replays_expires_at_idx on public.dpop_jti_replays (expires_at);

revoke all on public.dpop_jti_replays from public, rout_app;
alter table public.dpop_jti_replays enable row level security;

-- True when the hash is new (or its previous hold has expired) and is now held for p_hold_seconds;
-- false on a replay. Prunes a bounded batch of expired rows first so the table stays small.
create or replace function public.rout_dpop_jti_claim(p_jti_hash text, p_hold_seconds integer)
 returns boolean
 language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
declare
  v_claimed boolean;
begin
  if p_jti_hash is null or p_jti_hash !~ '^[0-9a-f]{64}$' or p_hold_seconds is null or p_hold_seconds not between 1 and 600 then
    raise exception 'invalid dpop jti claim' using errcode = '22023';
  end if;
  delete from public.dpop_jti_replays d
   where d.jti_hash in (select e.jti_hash from public.dpop_jti_replays e where e.expires_at <= now() order by e.expires_at limit 100);
  insert into public.dpop_jti_replays as r (jti_hash, expires_at)
       values (p_jti_hash, now() + make_interval(secs => p_hold_seconds))
  on conflict (jti_hash) do update set expires_at = excluded.expires_at
   where r.expires_at <= now()
  returning true into v_claimed;
  return coalesce(v_claimed, false);
end;
$function$;

revoke all on function public.rout_dpop_jti_claim(text, integer) from public, rout_app;
grant execute on function public.rout_dpop_jti_claim(text, integer) to rout_app;
