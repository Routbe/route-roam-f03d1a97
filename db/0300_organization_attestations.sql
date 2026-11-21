-- 0300: organization attestations, workspace entity types and corporate mandates (EXPAND, additive).
--
--   workspaces.entity_type              ORGANIZATION | DOMAIN_BRAND | INDIVIDUAL_CREATOR | AUTONOMOUS_AGENT.
--                                       Written only by the definers below (or a new row's default);
--                                       rout_app can never set or change it directly.
--   workspace_organization_attestations one row per proof: domain_dns (DNSSEC-validated TXT record),
--                                       vat_vies (EU VIES), lei_gleif (GLEIF). Register numbers are
--                                       never stored: only a keyed BLAKE3 organization nullifier and
--                                       a SHA-256 digest of the register answer.
--   corporate_mandate_credentials       a KYC-attested workspace manager's request to act for the
--                                       attested organization; approved only by a full admin with
--                                       two-factor on, after review outside ROUT.
--   workspace_attestation_events        append-only audit of every attestation and mandate step,
--                                       written in the same transaction as the step itself.
--   Wallet: oid4vci_offers / wallet_credentials accept the new 'rout_corporate_mandate' config and
--   carry the mandate id, so revoking a mandate revokes its wallet credential in the status list.
-- The public trust read (rout_public_workspace_trust) returns booleans, the country, the
-- verified domain and an opt-in register name; never a manager, never a register number.
-- rout_app gets no table rights; everything goes through the definers below.

alter table public.workspaces
  add column if not exists entity_type text not null default 'INDIVIDUAL_CREATOR'
  constraint workspaces_entity_type_check check (entity_type in ('ORGANIZATION', 'DOMAIN_BRAND', 'INDIVIDUAL_CREATOR', 'AUTONOMOUS_AGENT'));

-- Existing data: a verified domain makes a domain brand; a workspace created by an agent sandbox
-- that no human owns yet is an autonomous agent workspace.
update public.workspaces w set entity_type = 'DOMAIN_BRAND'
 where w.domain is not null and w.domain_verified_at is not null and w.entity_type = 'INDIVIDUAL_CREATOR';
update public.workspaces w set entity_type = 'AUTONOMOUS_AGENT'
 where w.entity_type = 'INDIVIDUAL_CREATOR'
   and exists (select 1 from public.agent_sandboxes s where s.workspace_id = w.id)
   and not exists (select 1 from public.workspace_members m where m.workspace_id = w.id and m.role::text = 'owner');

create table if not exists public.workspace_organization_attestations (
  id                 uuid primary key default gen_random_uuid(),
  workspace_id       uuid not null references public.workspaces(id) on delete cascade,
  kind               text not null check (kind in ('domain_dns', 'vat_vies', 'lei_gleif')),
  status             text not null default 'active' check (status in ('active', 'superseded', 'revoked')),
  subject_nullifier  bytea check (subject_nullifier is null or octet_length(subject_nullifier) = 32),
  domain             text check (domain is null or domain ~ '^(?=.{3,253}$)([a-z0-9-]+\.)+[a-z]{2,}$'),
  country            text check (country is null or country ~ '^[A-Z]{2}$'),
  public_name        text check (public_name is null or char_length(public_name) between 1 and 200),
  evidence_digest    bytea not null check (octet_length(evidence_digest) = 32),
  attested_by        uuid references public.users(id) on delete set null,
  verified_at        timestamptz not null default now(),
  expires_at         timestamptz,
  ended_at           timestamptz,
  constraint workspace_org_attestation_shape check (
    (kind = 'domain_dns' and domain is not null and subject_nullifier is null and country is null and public_name is null)
    or (kind in ('vat_vies', 'lei_gleif') and domain is null and subject_nullifier is not null and country is not null and expires_at is not null)
  )
);
create unique index if not exists workspace_org_attestations_one_active
  on public.workspace_organization_attestations (workspace_id, kind) where status = 'active';
-- One organization binds to at most one workspace at a time (anti-impersonation).
create unique index if not exists workspace_org_attestations_nullifier_active
  on public.workspace_organization_attestations (subject_nullifier) where status = 'active' and subject_nullifier is not null;
create index if not exists workspace_org_attestations_attested_by_fkx on public.workspace_organization_attestations (attested_by);

create table if not exists public.corporate_mandate_credentials (
  id              uuid primary key default gen_random_uuid(),
  workspace_id    uuid not null references public.workspaces(id) on delete cascade,
  attestation_id  uuid not null references public.workspace_organization_attestations(id) on delete cascade,
  holder_user_id  uuid not null references public.users(id) on delete cascade,
  status          text not null default 'pending_review' check (status in ('pending_review', 'approved', 'rejected', 'revoked')),
  basis           text not null default 'admin_review' check (basis in ('admin_review')),
  requested_at    timestamptz not null default now(),
  decided_at      timestamptz,
  decided_by      uuid references public.users(id) on delete set null,
  expires_at      timestamptz,
  ended_at        timestamptz,
  constraint corporate_mandate_approved_expiry check (status <> 'approved' or expires_at is not null)
);
create unique index if not exists corporate_mandates_one_open
  on public.corporate_mandate_credentials (workspace_id, holder_user_id) where status in ('pending_review', 'approved');
create index if not exists corporate_mandates_attestation_fkx on public.corporate_mandate_credentials (attestation_id);
create index if not exists corporate_mandates_holder_fkx on public.corporate_mandate_credentials (holder_user_id);
create index if not exists corporate_mandates_decided_by_fkx on public.corporate_mandate_credentials (decided_by);

create table if not exists public.workspace_attestation_events (
  id              bigint generated always as identity primary key,
  workspace_id    uuid not null references public.workspaces(id) on delete cascade,
  attestation_id  uuid references public.workspace_organization_attestations(id) on delete set null,
  mandate_id      uuid references public.corporate_mandate_credentials(id) on delete set null,
  event           text not null check (event in ('domain_attested', 'organization_attested', 'organization_superseded',
                    'organization_revoked', 'mandate_requested', 'mandate_approved', 'mandate_rejected', 'mandate_revoked')),
  actor_user_id   uuid references public.users(id) on delete set null,
  occurred_at     timestamptz not null default now()
);
create index if not exists workspace_attestation_events_ws_idx on public.workspace_attestation_events (workspace_id, occurred_at);
create index if not exists workspace_attestation_events_attestation_fkx on public.workspace_attestation_events (attestation_id);
create index if not exists workspace_attestation_events_mandate_fkx on public.workspace_attestation_events (mandate_id);
create index if not exists workspace_attestation_events_actor_fkx on public.workspace_attestation_events (actor_user_id);

revoke all on public.workspace_organization_attestations, public.corporate_mandate_credentials, public.workspace_attestation_events from public, rout_app;
revoke all on sequence public.workspace_attestation_events_id_seq from public, rout_app;
alter table public.workspace_organization_attestations enable row level security;
alter table public.corporate_mandate_credentials enable row level security;
alter table public.workspace_attestation_events enable row level security;

-- Wallet: the corporate mandate configuration, linked to its mandate.
alter table public.oid4vci_offers drop constraint if exists oid4vci_offers_config_check;
alter table public.oid4vci_offers add constraint oid4vci_offers_config_check check (config in ('rout_verified_human', 'rout_corporate_mandate'));
alter table public.wallet_credentials drop constraint if exists wallet_credentials_config_check;
alter table public.wallet_credentials add constraint wallet_credentials_config_check check (config in ('rout_verified_human', 'rout_corporate_mandate'));
alter table public.oid4vci_offers add column if not exists mandate_id uuid references public.corporate_mandate_credentials(id) on delete cascade;
alter table public.wallet_credentials add column if not exists mandate_id uuid references public.corporate_mandate_credentials(id) on delete cascade;
alter table public.oid4vci_offers drop constraint if exists oid4vci_offers_mandate_shape;
alter table public.oid4vci_offers add constraint oid4vci_offers_mandate_shape check ((config = 'rout_corporate_mandate') = (mandate_id is not null));
alter table public.wallet_credentials drop constraint if exists wallet_credentials_mandate_shape;
alter table public.wallet_credentials add constraint wallet_credentials_mandate_shape check ((config = 'rout_corporate_mandate') = (mandate_id is not null));
create index if not exists oid4vci_offers_mandate_fkx on public.oid4vci_offers (mandate_id);
create index if not exists wallet_credentials_mandate_fkx on public.wallet_credentials (mandate_id);

-- ------------------------------------------------------------------ entity type guard
-- Invoker trigger: only the table owner (that is, the definers below) may set an attested type.
-- rout_app may insert a creator or agent workspace and never changes the type afterwards; a
-- changed or cleared domain drops a DOMAIN_BRAND back to a creator workspace.
create or replace function public.workspaces_entity_type_guard() returns trigger
language plpgsql set search_path = pg_catalog, pg_temp as $$
begin
  if TG_OP = 'UPDATE' and OLD.entity_type = 'DOMAIN_BRAND' and NEW.entity_type = 'DOMAIN_BRAND'
     and (NEW.domain is distinct from OLD.domain or NEW.domain_verified_at is null) then
    NEW.entity_type := 'INDIVIDUAL_CREATOR';
    return NEW;
  end if;
  if pg_catalog.pg_has_role(current_user, (select c.relowner from pg_catalog.pg_class c where c.oid = 'public.workspaces'::regclass), 'MEMBER') then
    return NEW;
  end if;
  if TG_OP = 'INSERT' then
    if NEW.entity_type not in ('INDIVIDUAL_CREATOR', 'AUTONOMOUS_AGENT') then
      raise exception 'workspace_entity_type_attested_only' using errcode = '42501';
    end if;
  elsif NEW.entity_type is distinct from OLD.entity_type then
    raise exception 'workspace_entity_type_attested_only' using errcode = '42501';
  end if;
  return NEW;
end $$;
revoke all on function public.workspaces_entity_type_guard() from public, rout_app;
drop trigger if exists workspaces_entity_type_guard on public.workspaces;
create trigger workspaces_entity_type_guard before insert or update on public.workspaces
  for each row execute function public.workspaces_entity_type_guard();

-- ------------------------------------------------------------------ internal helpers
-- KYC legal identity of a member (same sources as rout_my_identity_claims and 0283).
create or replace function public.rout_user_has_legal_identity(p_user uuid)
returns boolean language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select p_user is not null and (
    exists (select 1 from public.verified_identity_nullifiers n
             where n.user_id = p_user and n.evidence = 'kyc_document' and n.has_legal_identity)
    or exists (select 1 from public.identity_verifications iv
                where iv.user_id = p_user and coalesce(iv.is_verified, false) and iv.verification_provider::text = 'didit'))
$$;
revoke all on function public.rout_user_has_legal_identity(uuid) from public, rout_app;

-- The workspace's entity type from its active proofs.
create or replace function public.rout_workspace_entity_recompute(p_ws uuid)
returns void language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
begin
  update public.workspaces w set entity_type = case
      when exists (select 1 from public.workspace_organization_attestations a
                    where a.workspace_id = w.id and a.status = 'active' and a.kind in ('vat_vies', 'lei_gleif')
                      and a.expires_at > now()) then 'ORGANIZATION'
      when w.domain is not null and w.domain_verified_at is not null
       and exists (select 1 from public.workspace_organization_attestations a
                    where a.workspace_id = w.id and a.status = 'active' and a.kind = 'domain_dns' and a.domain = w.domain) then 'DOMAIN_BRAND'
      when w.entity_type = 'AUTONOMOUS_AGENT' then 'AUTONOMOUS_AGENT'
      else 'INDIVIDUAL_CREATOR' end
   where w.id = p_ws;
end $$;
revoke all on function public.rout_workspace_entity_recompute(uuid) from public, rout_app;

-- Ends every open mandate of the given attestations and revokes their wallet credentials.
create or replace function public.rout_mandates_end_for(p_attestations uuid[], p_actor uuid)
returns void language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare r record;
begin
  for r in update public.corporate_mandate_credentials m set status = 'revoked', ended_at = now()
             where m.attestation_id = any (p_attestations) and m.status in ('pending_review', 'approved')
           returning m.id, m.workspace_id
  loop
    update public.wallet_credentials c set revoked_at = now() where c.mandate_id = r.id and c.revoked_at is null;
    insert into public.workspace_attestation_events (workspace_id, mandate_id, event, actor_user_id)
    values (r.workspace_id, r.id, 'mandate_revoked', p_actor);
  end loop;
end $$;
revoke all on function public.rout_mandates_end_for(uuid[], uuid) from public, rout_app;

-- ------------------------------------------------------------------ attestations (workspace owner/admin)
-- Register attestation. The server checked the register (VIES or GLEIF) just before this call; the
-- database stores the keyed organization nullifier, the country, the digest of the register answer
-- and, only when the manager chose so, the register name. Superseding, mandate revocation, the
-- entity type and the audit event all happen in this one transaction.
create or replace function public.rout_workspace_attest_organization(
  p_ws uuid, p_kind text, p_nullifier bytea, p_country text, p_evidence bytea, p_public_name text)
returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_user uuid := public.rout_current_user_id();
  v_old uuid[];
  v_id uuid;
begin
  if v_user is null or p_ws is null or not public.rout_ws_support_manager(p_ws) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'not_manager');
  end if;
  if p_kind is null or p_kind not in ('vat_vies', 'lei_gleif') or p_nullifier is null or octet_length(p_nullifier) <> 32
     or p_evidence is null or octet_length(p_evidence) <> 32 or p_country is null or p_country !~ '^[A-Z]{2}$'
     or (p_public_name is not null and char_length(p_public_name) not between 1 and 200) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid');
  end if;
  if exists (select 1 from public.workspace_organization_attestations a
              where a.subject_nullifier = p_nullifier and a.status = 'active' and a.workspace_id <> p_ws) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'organization_bound_elsewhere');
  end if;
  -- Re-attesting the same organization keeps its mandates; another organization ends them.
  select pg_catalog.array_agg(a.id) into v_old from public.workspace_organization_attestations a
   where a.workspace_id = p_ws and a.kind = p_kind and a.status = 'active';
  update public.workspace_organization_attestations a set status = 'superseded', ended_at = now()
   where a.id = any (coalesce(v_old, '{}'));
  begin
    insert into public.workspace_organization_attestations
      (workspace_id, kind, subject_nullifier, country, public_name, evidence_digest, attested_by, expires_at)
    values (p_ws, p_kind, p_nullifier, p_country, p_public_name, p_evidence, v_user, now() + interval '365 days')
    returning id into v_id;
  exception when unique_violation then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'organization_bound_elsewhere');
  end;
  if v_old is not null then
    update public.corporate_mandate_credentials m set attestation_id = v_id
     where m.attestation_id = any (v_old) and m.status in ('pending_review', 'approved')
       and exists (select 1 from public.workspace_organization_attestations o
                    where o.id = m.attestation_id and o.subject_nullifier = p_nullifier);
    perform public.rout_mandates_end_for(v_old, v_user);
    insert into public.workspace_attestation_events (workspace_id, attestation_id, event, actor_user_id)
    select p_ws, x, 'organization_superseded', v_user from pg_catalog.unnest(v_old) as x;
  end if;
  insert into public.workspace_attestation_events (workspace_id, attestation_id, event, actor_user_id)
  values (p_ws, v_id, 'organization_attested', v_user);
  perform public.rout_workspace_entity_recompute(p_ws);
  return pg_catalog.jsonb_build_object('ok', true, 'id', v_id);
end $$;
revoke all on function public.rout_workspace_attest_organization(uuid, text, bytea, text, bytea, text) from public, rout_app;
grant execute on function public.rout_workspace_attest_organization(uuid, text, bytea, text, bytea, text) to rout_app;

-- Domain attestation after a DNSSEC-validated TXT record matched (verifyWorkspaceDomain).
create or replace function public.rout_workspace_attest_domain(p_ws uuid, p_domain text, p_evidence bytea)
returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_user uuid := public.rout_current_user_id();
  v_id uuid;
begin
  if v_user is null or p_ws is null or not public.rout_ws_support_manager(p_ws) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'not_manager');
  end if;
  if p_evidence is null or octet_length(p_evidence) <> 32
     or not exists (select 1 from public.workspaces w where w.id = p_ws and w.domain = p_domain) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid');
  end if;
  update public.workspace_organization_attestations a set status = 'superseded', ended_at = now()
   where a.workspace_id = p_ws and a.kind = 'domain_dns' and a.status = 'active';
  insert into public.workspace_organization_attestations (workspace_id, kind, domain, evidence_digest, attested_by)
  values (p_ws, 'domain_dns', p_domain, p_evidence, v_user)
  returning id into v_id;
  update public.workspaces w set domain_verified_at = now() where w.id = p_ws;
  insert into public.workspace_attestation_events (workspace_id, attestation_id, event, actor_user_id)
  values (p_ws, v_id, 'domain_attested', v_user);
  perform public.rout_workspace_entity_recompute(p_ws);
  return pg_catalog.jsonb_build_object('ok', true, 'id', v_id);
end $$;
revoke all on function public.rout_workspace_attest_domain(uuid, text, bytea) from public, rout_app;
grant execute on function public.rout_workspace_attest_domain(uuid, text, bytea) to rout_app;

-- Ends the workspace's register attestation of one kind (owner/admin), with its mandates.
create or replace function public.rout_workspace_revoke_organization(p_ws uuid, p_kind text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_user uuid := public.rout_current_user_id();
  v_old uuid[];
begin
  if v_user is null or p_ws is null or not public.rout_ws_support_manager(p_ws) or p_kind not in ('vat_vies', 'lei_gleif') then
    return false;
  end if;
  update public.workspace_organization_attestations a set status = 'revoked', ended_at = now()
   where a.workspace_id = p_ws and a.kind = p_kind and a.status = 'active'
  returning pg_catalog.array_agg(a.id) over () into v_old;
  if v_old is null then return false; end if;
  perform public.rout_mandates_end_for(v_old, v_user);
  insert into public.workspace_attestation_events (workspace_id, attestation_id, event, actor_user_id)
  select p_ws, x, 'organization_revoked', v_user from pg_catalog.unnest(v_old) as x;
  perform public.rout_workspace_entity_recompute(p_ws);
  return true;
end $$;
revoke all on function public.rout_workspace_revoke_organization(uuid, text) from public, rout_app;
grant execute on function public.rout_workspace_revoke_organization(uuid, text) to rout_app;

-- What the workspace's managers see in Studio: active proofs and the caller's own mandate.
create or replace function public.rout_workspace_trust_manage(p_ws uuid)
returns table(entity_type text, kind text, country text, public_name text, domain text, verified_at timestamptz,
              expires_at timestamptz, my_mandate_id uuid, my_mandate_status text, my_mandate_expires_at timestamptz,
              my_legal_identity boolean)
language plpgsql stable security definer set search_path = pg_catalog, pg_temp as $$
declare v_user uuid := public.rout_current_user_id();
begin
  if v_user is null or p_ws is null or not public.rout_ws_support_manager(p_ws) then return; end if;
  return query
  select w.entity_type, a.kind, a.country, a.public_name, a.domain, a.verified_at, a.expires_at,
         m.id, m.status, m.expires_at, public.rout_user_has_legal_identity(v_user)
    from public.workspaces w
    left join public.workspace_organization_attestations a on a.workspace_id = w.id and a.status = 'active'
    left join lateral (select x.id, x.status, x.expires_at from public.corporate_mandate_credentials x
                        where x.workspace_id = w.id and x.holder_user_id = v_user
                        order by x.requested_at desc limit 1) m on true
   where w.id = p_ws;
end $$;
revoke all on function public.rout_workspace_trust_manage(uuid) from public, rout_app;
grant execute on function public.rout_workspace_trust_manage(uuid) to rout_app;

-- ------------------------------------------------------------------ corporate mandates
-- A KYC-attested owner/admin asks to be recorded as representative of the attested organization.
create or replace function public.rout_mandate_request(p_ws uuid)
returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_user uuid := public.rout_current_user_id();
  v_att uuid;
  v_id uuid;
begin
  if v_user is null or p_ws is null or not public.rout_ws_support_manager(p_ws) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'not_manager');
  end if;
  if not public.rout_user_has_legal_identity(v_user) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'legal_identity_required');
  end if;
  select a.id into v_att from public.workspace_organization_attestations a
   where a.workspace_id = p_ws and a.status = 'active' and a.kind in ('vat_vies', 'lei_gleif') and a.expires_at > now()
   order by a.verified_at desc limit 1;
  if v_att is null then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'organization_required'); end if;
  begin
    insert into public.corporate_mandate_credentials (workspace_id, attestation_id, holder_user_id)
    values (p_ws, v_att, v_user) returning id into v_id;
  exception when unique_violation then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'already_open');
  end;
  insert into public.workspace_attestation_events (workspace_id, attestation_id, mandate_id, event, actor_user_id)
  values (p_ws, v_att, v_id, 'mandate_requested', v_user);
  return pg_catalog.jsonb_build_object('ok', true, 'id', v_id);
end $$;
revoke all on function public.rout_mandate_request(uuid) from public, rout_app;
grant execute on function public.rout_mandate_request(uuid) to rout_app;

-- Holder, a workspace owner/admin or a full admin ends a mandate; its wallet credentials go with it.
create or replace function public.rout_mandate_revoke(p_id uuid)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_user uuid := public.rout_current_user_id();
  m public.corporate_mandate_credentials%rowtype;
begin
  select * into m from public.corporate_mandate_credentials x where x.id = p_id for update;
  if not found or v_user is null or m.status not in ('pending_review', 'approved') then return false; end if;
  if m.holder_user_id <> v_user and not public.rout_ws_support_manager(m.workspace_id)
     and public.rout_recovery_caller_admin() is null then
    return false;
  end if;
  update public.corporate_mandate_credentials x set status = 'revoked', ended_at = now() where x.id = p_id;
  update public.wallet_credentials c set revoked_at = now() where c.mandate_id = p_id and c.revoked_at is null;
  insert into public.workspace_attestation_events (workspace_id, mandate_id, event, actor_user_id)
  values (m.workspace_id, p_id, 'mandate_revoked', v_user);
  return true;
end $$;
revoke all on function public.rout_mandate_revoke(uuid) from public, rout_app;
grant execute on function public.rout_mandate_revoke(uuid) to rout_app;

-- Admin queue: open mandate requests. The admin sees the workspace and the holder's account id
-- (to contact them inside ROUT), never their name or identity document.
create or replace function public.rout_admin_mandate_list()
returns table(id uuid, workspace_id uuid, workspace_slug text, workspace_name text, register_kind text, country text,
              public_name text, holder_user_id uuid, holder_legal_identity boolean, requested_at timestamptz)
language plpgsql stable security definer set search_path = pg_catalog, pg_temp as $$
begin
  if public.rout_recovery_caller_admin() is null then return; end if;
  return query
  select m.id, w.id, w.slug, w.name, a.kind, a.country, a.public_name, m.holder_user_id,
         public.rout_user_has_legal_identity(m.holder_user_id), m.requested_at
    from public.corporate_mandate_credentials m
    join public.workspaces w on w.id = m.workspace_id
    join public.workspace_organization_attestations a on a.id = m.attestation_id
   where m.status = 'pending_review'
   order by m.requested_at
   limit 200;
end $$;
revoke all on function public.rout_admin_mandate_list() from public, rout_app;
grant execute on function public.rout_admin_mandate_list() to rout_app;

-- Full admin with two-factor on approves (after review outside ROUT) or rejects a request.
create or replace function public.rout_admin_mandate_decide(p_id uuid, p_approve boolean)
returns text language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_admin uuid := public.rout_recovery_caller_admin();
  m public.corporate_mandate_credentials%rowtype;
  v_att_exp timestamptz;
begin
  if v_admin is null then return 'forbidden'; end if;
  select * into m from public.corporate_mandate_credentials x where x.id = p_id for update;
  if not found or m.status <> 'pending_review' then return 'not_open'; end if;
  if m.holder_user_id = v_admin then return 'own_request'; end if;
  select a.expires_at into v_att_exp from public.workspace_organization_attestations a
   where a.id = m.attestation_id and a.status = 'active' and a.expires_at > now();
  if coalesce(p_approve, false) then
    if v_att_exp is null then return 'organization_inactive'; end if;
    if not public.rout_user_has_legal_identity(m.holder_user_id) then return 'legal_identity_required'; end if;
    update public.corporate_mandate_credentials x
       set status = 'approved', decided_at = now(), decided_by = v_admin, expires_at = least(v_att_exp, now() + interval '365 days')
     where x.id = p_id;
    insert into public.workspace_attestation_events (workspace_id, mandate_id, event, actor_user_id)
    values (m.workspace_id, p_id, 'mandate_approved', v_admin);
    return 'approved';
  end if;
  update public.corporate_mandate_credentials x set status = 'rejected', decided_at = now(), decided_by = v_admin, ended_at = now()
   where x.id = p_id;
  insert into public.workspace_attestation_events (workspace_id, mandate_id, event, actor_user_id)
  values (m.workspace_id, p_id, 'mandate_rejected', v_admin);
  return 'rejected';
end $$;
revoke all on function public.rout_admin_mandate_decide(uuid, boolean) from public, rout_app;
grant execute on function public.rout_admin_mandate_decide(uuid, boolean) to rout_app;

-- ------------------------------------------------------------------ wallet (EUDI EAA)
-- Offer for the caller's own approved mandate. The claims hold the organization's public
-- reference only: no holder name, birth date or national number (zero-knowledge mandate).
create or replace function public.rout_vci_mandate_offer_create(p_mandate uuid, p_code_hash text, p_tx_hash text)
returns uuid language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_user uuid := public.rout_current_user_id();
  v_claims jsonb;
  v_id uuid;
begin
  if v_user is null or p_mandate is null or p_code_hash !~ '^[0-9a-f]{64}$' or p_tx_hash !~ '^[0-9a-f]{64}$' then
    return null;
  end if;
  select pg_catalog.jsonb_build_object(
           'corporate_mandate', true,
           'mandate_basis', m.basis,
           'organization_workspace', w.slug,
           'organization_country', a.country,
           'organization_register', a.kind,
           'mandate_expires_at', pg_catalog.to_char(m.expires_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
    into v_claims
    from public.corporate_mandate_credentials m
    join public.workspaces w on w.id = m.workspace_id
    join public.workspace_organization_attestations a on a.id = m.attestation_id and a.status = 'active'
   where m.id = p_mandate and m.holder_user_id = v_user and m.status = 'approved' and m.expires_at > now();
  if v_claims is null or not public.rout_user_has_legal_identity(v_user) then return null; end if;
  delete from public.oid4vci_offers o where o.user_id = v_user and o.expires_at < now() - interval '1 day';
  if (select pg_catalog.count(*) from public.oid4vci_offers o where o.user_id = v_user and o.created_at > now() - interval '10 minutes') >= 5 then
    return null;
  end if;
  insert into public.oid4vci_offers (user_id, config, claims, code_hash, tx_hash, expires_at, mandate_id)
  values (v_user, 'rout_corporate_mandate', v_claims, p_code_hash, p_tx_hash, now() + interval '10 minutes', p_mandate)
  returning oid4vci_offers.id into v_id;
  return v_id;
end $$;
revoke all on function public.rout_vci_mandate_offer_create(uuid, text, text) from public, rout_app;
grant execute on function public.rout_vci_mandate_offer_create(uuid, text, text) to rout_app;

-- Credential endpoint (0294) now also issues mandate credentials, only while the mandate holds,
-- and never longer than the mandate.
create or replace function public.rout_vci_issue(p_token_hash text, p_jti_hash text, p_days integer)
 returns table(status_idx bigint, config text, claims jsonb, expires_at timestamptz)
 language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
declare
  v public.oid4vci_offers%rowtype;
  v_idx bigint;
  v_exp timestamptz;
  v_limit timestamptz;
begin
  if p_token_hash !~ '^[0-9a-f]{64}$' or p_jti_hash !~ '^[0-9a-f]{64}$' then return; end if;
  select * into v from public.oid4vci_offers o where o.token_hash = p_token_hash for update;
  if not found or v.issued_at is not null or v.redeemed_at is null or v.redeemed_at < now() - interval '5 minutes' then
    return;
  end if;
  v_limit := now() + pg_catalog.make_interval(days => least(greatest(coalesce(p_days, 1), 1), 365));
  if v.config = 'rout_corporate_mandate' then
    select least(v_limit, m.expires_at) into v_limit from public.corporate_mandate_credentials m
     where m.id = v.mandate_id and m.holder_user_id = v.user_id and m.status = 'approved' and m.expires_at > now();
    if not found then return; end if;
  end if;
  update public.oid4vci_offers o set issued_at = now() where o.id = v.id;
  insert into public.wallet_credentials (user_id, config, jti_hash, expires_at, mandate_id)
  values (v.user_id, v.config, p_jti_hash, v_limit, v.mandate_id)
  returning wallet_credentials.status_idx, wallet_credentials.expires_at into v_idx, v_exp;
  return query select v_idx, v.config, v.claims, v_exp;
end $function$;
revoke all on function public.rout_vci_issue(text, text, integer) from public, rout_app;
grant execute on function public.rout_vci_issue(text, text, integer) to rout_app;

-- ------------------------------------------------------------------ public trust read
-- Everything a visitor's badge needs, for one workspace slug. Booleans, country, verified domain,
-- register kinds and the opt-in register name. No manager, no register number, no nullifier.
create or replace function public.rout_public_workspace_trust(p_slug text)
returns table(entity_type text, domain text, domain_bound boolean, domain_verified_at timestamptz,
              org_verified boolean, org_kinds text[], org_country text, org_public_name text, org_verified_at timestamptz,
              mandate_active boolean, owner_sovereign boolean)
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  with w as (
    select x.* from public.workspaces x where x.slug = pg_catalog.lower(p_slug) limit 1
  ), org as (
    select pg_catalog.array_agg(a.kind order by a.kind) as kinds, pg_catalog.max(a.country) as country,
           pg_catalog.max(a.public_name) as public_name, pg_catalog.max(a.verified_at) as verified_at
      from public.workspace_organization_attestations a, w
     where a.workspace_id = w.id and a.status = 'active' and a.kind in ('vat_vies', 'lei_gleif') and a.expires_at > now()
  )
  select
    case when w.entity_type = 'INDIVIDUAL_CREATOR'
          and exists (select 1 from public.agent_sandboxes s where s.workspace_id = w.id and s.revoked_at is null)
          and not exists (select 1 from public.workspace_members m where m.workspace_id = w.id and m.role::text = 'owner')
         then 'AUTONOMOUS_AGENT' else w.entity_type end,
    case when w.domain_verified_at is not null then w.domain end,
    w.domain is not null and w.domain_verified_at is not null
      and exists (select 1 from public.workspace_organization_attestations a
                   where a.workspace_id = w.id and a.status = 'active' and a.kind = 'domain_dns' and a.domain = w.domain),
    w.domain_verified_at,
    org.kinds is not null,
    coalesce(org.kinds, '{}'::text[]),
    org.country,
    org.public_name,
    org.verified_at,
    exists (select 1 from public.corporate_mandate_credentials m
             join public.workspace_organization_attestations a on a.id = m.attestation_id and a.status = 'active'
            where m.workspace_id = w.id and m.status = 'approved' and m.expires_at > now()
              and public.rout_user_has_legal_identity(m.holder_user_id)),
    exists (select 1 from public.workspace_members m where m.workspace_id = w.id and m.role::text = 'owner'
              and public.rout_user_has_legal_identity(m.user_id))
  from w, org
$$;
revoke all on function public.rout_public_workspace_trust(text) from public, rout_app;
grant execute on function public.rout_public_workspace_trust(text) to rout_app;
