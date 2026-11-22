-- 0300: three-layer workspace trust (EXPAND, additive). Owner decision 2026-11-22: no single
-- choice, but an eIDAS-style assurance model where every layer is stored, signed and shown apart.
--
--   Layer 1  domain   dns_txt (DNSSEC-validated _rout.<domain> TXT bound to workspace id + nonce)
--                     or well_known_email (https://<domain>/.well-known/rout.json + a verified work
--                     e-mail on that domain). Re-checked by cron; a record missing for 72 h lapses
--                     the seal and the domain right (workspaces.domain_verified_at).
--   Layer 2  entity   vat_vies (EU VIES, covers Belgian KBO numbers that are VAT-registered),
--                     lei_gleif (GLEIF), public_body (admin-reviewed Staatsblad/appointment evidence).
--                     Register numbers are never stored: only a keyed BLAKE3 nullifier.
--   Layer 3  mandate  declared (self-service: Didit identity + DNS seal + work e-mail, passkey-confirmed
--                     declaration signed by the server key) or proven (official evidence, AEAD-sealed,
--                     reviewed by a full admin with two-factor on, purged after the decision or 7 days,
--                     only its SHA-256 kept). 12-month TTL; frozen/revoked/expired end it.
--
-- Every step writes workspace_trust_events, an append-only SHA-256 hash chain without foreign
-- keys (no cascade can rewrite it; it holds only opaque ids). rout_app has no table rights;
-- everything goes through the definers below. Evidence ciphertext lives in Neon only for its
-- 7-day review window so blob and purge share one transaction.

-- ------------------------------------------------------------------ entity type
alter table public.workspaces
  add column if not exists entity_type text not null default 'INDIVIDUAL_CREATOR'
  constraint workspaces_entity_type_check check (entity_type in ('ORGANIZATION', 'DOMAIN_BRAND', 'INDIVIDUAL_CREATOR', 'AUTONOMOUS_AGENT'));

-- Existing data: a workspace created by an agent sandbox that no human owns yet is an agent workspace.
-- DOMAIN_BRAND / ORGANIZATION come only from the seals below (legacy verified domains stay creators
-- until they verify again with the nonce-bound record).
update public.workspaces w set entity_type = 'AUTONOMOUS_AGENT'
 where w.entity_type = 'INDIVIDUAL_CREATOR'
   and exists (select 1 from public.agent_sandboxes s where s.workspace_id = w.id)
   and not exists (select 1 from public.workspace_members m where m.workspace_id = w.id and m.role::text = 'owner');

-- ------------------------------------------------------------------ tables
create table if not exists public.workspace_domain_challenges (
  workspace_id uuid primary key references public.workspaces(id) on delete cascade,
  domain       text not null,
  nonce        bytea not null check (octet_length(nonce) = 16),
  created_at   timestamptz not null default now()
);

create table if not exists public.workspace_work_emails (
  id              uuid primary key default gen_random_uuid(),
  workspace_id    uuid not null references public.workspaces(id) on delete cascade,
  user_id         uuid not null references public.users(id) on delete cascade,
  domain          text not null,
  email_hash      bytea not null check (octet_length(email_hash) = 32),
  code_hash       bytea check (code_hash is null or octet_length(code_hash) = 32),
  status          text not null default 'pending' check (status in ('pending', 'verified', 'failed', 'superseded')),
  attempts        smallint not null default 0,
  created_at      timestamptz not null default now(),
  code_expires_at timestamptz not null,
  verified_at     timestamptz,
  expires_at      timestamptz,
  constraint workspace_work_emails_verified_shape check ((status = 'verified') = (verified_at is not null and expires_at is not null and code_hash is null) or status <> 'verified' and verified_at is null)
);
create unique index if not exists workspace_work_emails_one_pending on public.workspace_work_emails (workspace_id, user_id) where status = 'pending';
create unique index if not exists workspace_work_emails_one_verified on public.workspace_work_emails (workspace_id, user_id) where status = 'verified';
create index if not exists workspace_work_emails_user_fkx on public.workspace_work_emails (user_id);

create table if not exists public.workspace_trust_attestations (
  id                uuid primary key default gen_random_uuid(),
  workspace_id      uuid not null references public.workspaces(id) on delete cascade,
  layer             text not null check (layer in ('domain', 'entity')),
  kind              text not null check (kind in ('dns_txt', 'well_known_email', 'vat_vies', 'lei_gleif', 'public_body')),
  status            text not null default 'active' check (status in ('active', 'superseded', 'lapsed', 'revoked', 'expired')),
  subject_nullifier bytea check (subject_nullifier is null or octet_length(subject_nullifier) = 32),
  domain            text check (domain is null or domain ~ '^(?=.{3,253}$)([a-z0-9-]+\.)+[a-z]{2,}$'),
  country           text check (country is null or country ~ '^[A-Z]{2}$'),
  public_name       text check (public_name is null or char_length(public_name) between 1 and 200),
  evidence_digest   bytea not null check (octet_length(evidence_digest) = 32),
  attested_by       uuid references public.users(id) on delete set null,
  verified_at       timestamptz not null default now(),
  last_checked_at   timestamptz,
  failing_since     timestamptz,
  expires_at        timestamptz,
  ended_at          timestamptz,
  end_reason        text,
  constraint workspace_trust_attestation_shape check (
    (layer = 'domain' and kind in ('dns_txt', 'well_known_email') and domain is not null
       and subject_nullifier is null and country is null and public_name is null)
    or (layer = 'entity' and kind in ('vat_vies', 'lei_gleif', 'public_body') and domain is null
       and subject_nullifier is not null and country is not null and expires_at is not null)),
  constraint workspace_trust_attestation_ended check ((status = 'active') = (ended_at is null))
);
create unique index if not exists workspace_trust_one_active_layer on public.workspace_trust_attestations (workspace_id, layer) where status = 'active';
-- One organization and one domain bind to at most one workspace at a time (anti-impersonation).
create unique index if not exists workspace_trust_entity_once on public.workspace_trust_attestations (subject_nullifier) where status = 'active' and layer = 'entity';
create unique index if not exists workspace_trust_domain_once on public.workspace_trust_attestations (domain) where status = 'active' and layer = 'domain';
create index if not exists workspace_trust_attested_by_fkx on public.workspace_trust_attestations (attested_by);

create table if not exists public.trust_evidence_reviews (
  id                uuid primary key,
  workspace_id      uuid not null references public.workspaces(id) on delete cascade,
  requester_user_id uuid not null references public.users(id) on delete cascade,
  subject           text not null check (subject in ('public_body', 'mandate_proven')),
  evidence_kind     text not null check (evidence_kind in ('kbo_extract', 'staatsblad', 'appointment_decision', 'qes_mandate')),
  status            text not null default 'pending' check (status in ('pending', 'approved', 'rejected', 'expired', 'withdrawn')),
  sha256            bytea not null check (octet_length(sha256) = 32),
  mime              text not null check (mime in ('application/pdf', 'image/png', 'image/jpeg')),
  byte_size         integer not null check (byte_size between 1 and 5242880),
  ciphertext        bytea check (ciphertext is null or octet_length(ciphertext) between 33 and 5242976),
  subject_nullifier bytea check (subject_nullifier is null or octet_length(subject_nullifier) = 32),
  country           text check (country is null or country ~ '^[A-Z]{2}$'),
  public_name       text check (public_name is null or char_length(public_name) between 1 and 200),
  submitted_at      timestamptz not null default now(),
  purge_due_at      timestamptz not null,
  purged_at         timestamptz,
  decided_by        uuid references public.users(id) on delete set null,
  decided_at        timestamptz,
  decision_code     text check (decision_code is null or decision_code in ('approved', 'insufficient', 'mismatch', 'unreadable', 'expired', 'withdrawn')),
  -- Closed means purged: the document never outlives its review.
  constraint trust_evidence_purged check ((ciphertext is null) = (purged_at is not null)),
  constraint trust_evidence_open_has_file check ((status = 'pending') = (ciphertext is not null)),
  constraint trust_evidence_window check (purge_due_at <= submitted_at + interval '7 days'),
  constraint trust_evidence_subject_shape check ((subject = 'public_body') = (subject_nullifier is not null and country is not null))
);
create unique index if not exists trust_evidence_one_pending on public.trust_evidence_reviews (workspace_id, subject) where status = 'pending';
create index if not exists trust_evidence_requester_fkx on public.trust_evidence_reviews (requester_user_id);
create index if not exists trust_evidence_decided_by_fkx on public.trust_evidence_reviews (decided_by);
create index if not exists trust_evidence_purge_due_idx on public.trust_evidence_reviews (purge_due_at) where status = 'pending';

create table if not exists public.workspace_mandates (
  id                   uuid primary key default gen_random_uuid(),
  workspace_id         uuid not null references public.workspaces(id) on delete cascade,
  attestation_id       uuid not null references public.workspace_trust_attestations(id) on delete cascade,
  holder_user_id       uuid not null references public.users(id) on delete cascade,
  level                text not null check (level in ('declared', 'proven')),
  status               text not null default 'active' check (status in ('active', 'frozen', 'revoked', 'expired', 'superseded')),
  basis                text not null check (basis in ('signed_declaration', 'kbo_extract', 'staatsblad', 'appointment_decision', 'qes_mandate')),
  statement            text check (statement is null or octet_length(statement) <= 4096),
  statement_digest     bytea not null check (octet_length(statement_digest) = 32),
  signature            text check (signature is null or signature ~ '^[A-Za-z0-9_-]{86}$'),
  signature_kid        text check (signature_kid is null or signature_kid ~ '^[0-9a-f]{16}$'),
  identity_attested_at timestamptz,
  work_email_id        uuid references public.workspace_work_emails(id) on delete set null,
  evidence_review_id   uuid references public.trust_evidence_reviews(id) on delete set null,
  decided_by           uuid references public.users(id) on delete set null,
  activated_at         timestamptz not null default now(),
  expires_at           timestamptz not null,
  frozen_at            timestamptz,
  frozen_by            uuid references public.users(id) on delete set null,
  ended_at             timestamptz,
  end_reason           text check (end_reason is null or end_reason in ('holder', 'manager', 'admin', 'left_workspace', 'domain_lapsed',
                         'domain_changed', 'organization_changed', 'organization_ended', 'expired', 'superseded')),
  constraint workspace_mandate_shape check (
    (level = 'declared' and basis = 'signed_declaration' and statement is not null and signature is not null and signature_kid is not null)
    or (level = 'proven' and basis <> 'signed_declaration' and statement is null)),
  constraint workspace_mandate_ttl check (expires_at <= activated_at + interval '366 days'),
  constraint workspace_mandate_frozen check ((status = 'frozen') = (frozen_at is not null)),
  constraint workspace_mandate_ended check ((status in ('active', 'frozen')) = (ended_at is null))
);
create unique index if not exists workspace_mandates_one_open on public.workspace_mandates (workspace_id, holder_user_id, level) where status in ('active', 'frozen');
create index if not exists workspace_mandates_attestation_fkx on public.workspace_mandates (attestation_id);
create index if not exists workspace_mandates_holder_fkx on public.workspace_mandates (holder_user_id);
create index if not exists workspace_mandates_work_email_fkx on public.workspace_mandates (work_email_id);
create index if not exists workspace_mandates_review_fkx on public.workspace_mandates (evidence_review_id);
create index if not exists workspace_mandates_decided_by_fkx on public.workspace_mandates (decided_by);
create index if not exists workspace_mandates_frozen_by_fkx on public.workspace_mandates (frozen_by);

create table if not exists public.workspace_mandate_objections (
  id                   uuid primary key default gen_random_uuid(),
  workspace_id         uuid not null references public.workspaces(id) on delete cascade,
  filed_by             uuid references public.users(id) on delete set null,
  filer_legal_identity boolean not null,
  reason               text not null check (reason in ('not_authorized', 'left_organization', 'impersonation', 'other')),
  status               text not null default 'open' check (status in ('open', 'upheld', 'dismissed')),
  filed_at             timestamptz not null default now(),
  decided_by           uuid references public.users(id) on delete set null,
  decided_at           timestamptz
);
create unique index if not exists workspace_objections_one_open on public.workspace_mandate_objections (workspace_id, filed_by) where status = 'open';
create index if not exists workspace_objections_filed_by_fkx on public.workspace_mandate_objections (filed_by);
create index if not exists workspace_objections_decided_by_fkx on public.workspace_mandate_objections (decided_by);

create table if not exists public.workspace_trust_events (
  id            bigint generated always as identity primary key,
  workspace_id  uuid not null,
  subject_id    uuid,
  event         text not null check (event in (
                  'domain_attested', 'domain_check_failed', 'domain_lapsed', 'domain_ended',
                  'work_email_sent', 'work_email_verified', 'work_email_failed',
                  'entity_attested', 'entity_superseded', 'entity_revoked', 'entity_expired',
                  'evidence_submitted', 'evidence_viewed', 'evidence_withdrawn', 'evidence_approved', 'evidence_rejected',
                  'evidence_expired', 'evidence_purged',
                  'mandate_declared', 'mandate_proven', 'mandate_frozen', 'mandate_unfrozen', 'mandate_revoked',
                  'mandate_expired', 'mandate_superseded',
                  'objection_filed', 'objection_upheld', 'objection_dismissed')),
  actor_user_id uuid,
  detail        jsonb not null default '{}'::jsonb,
  occurred_at   timestamptz not null default now(),
  prev_hash     bytea not null check (octet_length(prev_hash) = 32),
  row_hash      bytea not null check (octet_length(row_hash) = 32)
);
create index if not exists workspace_trust_events_ws_idx on public.workspace_trust_events (workspace_id, id);

revoke all on public.workspace_domain_challenges, public.workspace_work_emails, public.workspace_trust_attestations,
  public.trust_evidence_reviews, public.workspace_mandates, public.workspace_mandate_objections,
  public.workspace_trust_events from public, rout_app;
revoke all on sequence public.workspace_trust_events_id_seq from public, rout_app;
alter table public.workspace_domain_challenges enable row level security;
alter table public.workspace_work_emails enable row level security;
alter table public.workspace_trust_attestations enable row level security;
alter table public.trust_evidence_reviews enable row level security;
alter table public.workspace_mandates enable row level security;
alter table public.workspace_mandate_objections enable row level security;
alter table public.workspace_trust_events enable row level security;

-- ------------------------------------------------------------------ audit chain
create or replace function public.rout_trust_event_hash(p_prev bytea, p_ws uuid, p_subject uuid, p_event text, p_actor uuid,
  p_detail jsonb, p_at timestamptz)
returns bytea language sql immutable security definer set search_path = pg_catalog, pg_temp as $$
  select pg_catalog.sha256(p_prev || pg_catalog.convert_to(pg_catalog.concat_ws('|', 'rout.trust_event.v1', p_ws::text,
           coalesce(p_subject::text, ''), p_event, coalesce(p_actor::text, ''), p_detail::text,
           pg_catalog.to_char(p_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')), 'UTF8'))
$$;
revoke all on function public.rout_trust_event_hash(bytea, uuid, uuid, text, uuid, jsonb, timestamptz) from public, rout_app;

create or replace function public.rout_trust_log(p_ws uuid, p_subject uuid, p_event text, p_actor uuid, p_detail jsonb default '{}'::jsonb)
returns void language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_prev bytea;
  v_at timestamptz := pg_catalog.clock_timestamp();
  v_detail jsonb := coalesce(p_detail, '{}'::jsonb);
begin
  -- One writer at a time keeps the chain linear across concurrent transactions.
  perform pg_catalog.pg_advisory_xact_lock(7300300);
  select e.row_hash into v_prev from public.workspace_trust_events e order by e.id desc limit 1;
  v_prev := coalesce(v_prev, pg_catalog.sha256(pg_catalog.convert_to('rout.trust_events.genesis', 'UTF8')));
  insert into public.workspace_trust_events (workspace_id, subject_id, event, actor_user_id, detail, occurred_at, prev_hash, row_hash)
  values (p_ws, p_subject, p_event, p_actor, v_detail, v_at, v_prev,
          public.rout_trust_event_hash(v_prev, p_ws, p_subject, p_event, p_actor, v_detail, v_at));
end $$;
revoke all on function public.rout_trust_log(uuid, uuid, text, uuid, jsonb) from public, rout_app;

create or replace function public.workspace_trust_events_immutable() returns trigger
language plpgsql set search_path = pg_catalog, pg_temp as $$
begin
  raise exception 'workspace_trust_events_append_only' using errcode = '42501';
end $$;
revoke all on function public.workspace_trust_events_immutable() from public, rout_app;
drop trigger if exists workspace_trust_events_no_update on public.workspace_trust_events;
create trigger workspace_trust_events_no_update before update or delete on public.workspace_trust_events
  for each row execute function public.workspace_trust_events_immutable();
drop trigger if exists workspace_trust_events_no_truncate on public.workspace_trust_events;
create trigger workspace_trust_events_no_truncate before truncate on public.workspace_trust_events
  for each statement execute function public.workspace_trust_events_immutable();

-- First event id whose hash does not match, or null when the whole chain holds. Full admin only.
create or replace function public.rout_trust_events_verify()
returns bigint language plpgsql stable security definer set search_path = pg_catalog, pg_temp as $$
declare
  r record;
  v_prev bytea := pg_catalog.sha256(pg_catalog.convert_to('rout.trust_events.genesis', 'UTF8'));
begin
  if public.rout_recovery_caller_admin() is null then return -1; end if;
  for r in select * from public.workspace_trust_events order by id loop
    if r.prev_hash <> v_prev
       or r.row_hash <> public.rout_trust_event_hash(r.prev_hash, r.workspace_id, r.subject_id, r.event, r.actor_user_id, r.detail, r.occurred_at) then
      return r.id;
    end if;
    v_prev := r.row_hash;
  end loop;
  return null;
end $$;
revoke all on function public.rout_trust_events_verify() from public, rout_app;
grant execute on function public.rout_trust_events_verify() to rout_app;

-- ------------------------------------------------------------------ entity type guard
-- Invoker trigger: only the table owner (that is, the definers below) may set an attested type.
-- rout_app may insert a creator or agent workspace and never changes the type afterwards.
create or replace function public.workspaces_entity_type_guard() returns trigger
language plpgsql set search_path = pg_catalog, pg_temp as $$
begin
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

-- When the member's Didit / KYC identity was attested (the declaration's identity link).
create or replace function public.rout_user_identity_attested_at(p_user uuid)
returns timestamptz language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select pg_catalog.max(t) from (
    select n.attested_at as t from public.verified_identity_nullifiers n
     where n.user_id = p_user and n.evidence = 'kyc_document' and n.has_legal_identity
    union all
    select iv.verified_at from public.identity_verifications iv
     where iv.user_id = p_user and coalesce(iv.is_verified, false) and iv.verification_provider::text = 'didit') x
$$;
revoke all on function public.rout_user_identity_attested_at(uuid) from public, rout_app;

create or replace function public.rout_trust_entity_recompute(p_ws uuid)
returns void language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
begin
  update public.workspaces w set entity_type = case
      when exists (select 1 from public.workspace_trust_attestations a
                    where a.workspace_id = w.id and a.status = 'active' and a.layer = 'entity' and a.expires_at > now()) then 'ORGANIZATION'
      when exists (select 1 from public.workspace_trust_attestations a
                    where a.workspace_id = w.id and a.status = 'active' and a.layer = 'domain' and a.domain = w.domain
                      and (a.expires_at is null or a.expires_at > now())) then 'DOMAIN_BRAND'
      when w.entity_type = 'AUTONOMOUS_AGENT' then 'AUTONOMOUS_AGENT'
      else 'INDIVIDUAL_CREATOR' end
   where w.id = p_ws;
end $$;
revoke all on function public.rout_trust_entity_recompute(uuid) from public, rout_app;

-- Ends open (active/frozen) mandates of a workspace, optionally of one holder and/or level.
create or replace function public.rout_trust_end_mandates(p_ws uuid, p_holder uuid, p_level text, p_status text, p_reason text, p_actor uuid)
returns integer language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare r record; n integer := 0;
begin
  for r in update public.workspace_mandates m
              set status = p_status, ended_at = now(), end_reason = p_reason, frozen_at = null
            where m.workspace_id = p_ws and m.status in ('active', 'frozen')
              and (p_holder is null or m.holder_user_id = p_holder)
              and (p_level is null or m.level = p_level)
          returning m.id
  loop
    n := n + 1;
    perform public.rout_trust_log(p_ws, r.id,
      case p_status when 'expired' then 'mandate_expired' when 'superseded' then 'mandate_superseded' else 'mandate_revoked' end,
      p_actor, pg_catalog.jsonb_build_object('reason', p_reason));
  end loop;
  return n;
end $$;
revoke all on function public.rout_trust_end_mandates(uuid, uuid, text, text, text, uuid) from public, rout_app;

-- Closes an evidence review and destroys its document in the same transaction.
create or replace function public.rout_trust_evidence_close(p_id uuid, p_status text, p_code text, p_actor uuid)
returns void language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare v_ws uuid;
begin
  update public.trust_evidence_reviews r
     set status = p_status, decision_code = p_code, decided_by = p_actor, decided_at = now(), ciphertext = null, purged_at = now()
   where r.id = p_id and r.status = 'pending'
  returning r.workspace_id into v_ws;
  if v_ws is null then return; end if;
  perform public.rout_trust_log(v_ws, p_id,
    case p_status when 'approved' then 'evidence_approved' when 'rejected' then 'evidence_rejected'
                  when 'withdrawn' then 'evidence_withdrawn' else 'evidence_expired' end,
    p_actor, pg_catalog.jsonb_build_object('code', p_code));
  perform public.rout_trust_log(v_ws, p_id, 'evidence_purged', p_actor, '{}'::jsonb);
end $$;
revoke all on function public.rout_trust_evidence_close(uuid, text, text, uuid) from public, rout_app;

-- Inserts an entity seal (superseding the previous one) and carries or ends mandates.
create or replace function public.rout_trust_entity_insert(p_ws uuid, p_kind text, p_nullifier bytea, p_country text,
  p_evidence bytea, p_public_name text, p_actor uuid)
returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_old record;
  v_id uuid;
begin
  if exists (select 1 from public.workspace_trust_attestations a
              where a.layer = 'entity' and a.status = 'active' and a.subject_nullifier = p_nullifier and a.workspace_id <> p_ws) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'organization_bound_elsewhere');
  end if;
  select a.id, a.subject_nullifier into v_old from public.workspace_trust_attestations a
   where a.workspace_id = p_ws and a.layer = 'entity' and a.status = 'active' for update;
  if v_old.id is not null then
    update public.workspace_trust_attestations a set status = 'superseded', ended_at = now(), end_reason = 'reattested' where a.id = v_old.id;
  end if;
  begin
    insert into public.workspace_trust_attestations (workspace_id, layer, kind, subject_nullifier, country, public_name, evidence_digest, attested_by, expires_at)
    values (p_ws, 'entity', p_kind, p_nullifier, p_country, p_public_name, p_evidence, p_actor, now() + interval '365 days')
    returning id into v_id;
  exception when unique_violation then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'organization_bound_elsewhere');
  end;
  if v_old.id is not null then
    perform public.rout_trust_log(p_ws, v_old.id, 'entity_superseded', p_actor, '{}'::jsonb);
    if v_old.subject_nullifier = p_nullifier then
      update public.workspace_mandates m set attestation_id = v_id where m.attestation_id = v_old.id and m.status in ('active', 'frozen');
    else
      perform public.rout_trust_end_mandates(p_ws, null, null, 'revoked', 'organization_changed', p_actor);
    end if;
  end if;
  perform public.rout_trust_log(p_ws, v_id, 'entity_attested', p_actor, pg_catalog.jsonb_build_object('kind', p_kind, 'country', p_country));
  perform public.rout_trust_entity_recompute(p_ws);
  return pg_catalog.jsonb_build_object('ok', true, 'id', v_id);
end $$;
revoke all on function public.rout_trust_entity_insert(uuid, text, bytea, text, bytea, text, uuid) from public, rout_app;

-- ------------------------------------------------------------------ layer 1: domain
-- The nonce for the workspace's current domain (a new domain gets a new nonce). Owner/admin only.
create or replace function public.rout_trust_domain_challenge(p_ws uuid)
returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_domain text;
  v_nonce bytea;
begin
  if public.rout_current_user_id() is null or p_ws is null or not public.rout_ws_support_manager(p_ws) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'not_manager');
  end if;
  select w.domain into v_domain from public.workspaces w where w.id = p_ws;
  if v_domain is null then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'no_domain'); end if;
  select c.nonce into v_nonce from public.workspace_domain_challenges c where c.workspace_id = p_ws and c.domain = v_domain;
  if v_nonce is null then
    v_nonce := pg_catalog.uuid_send(pg_catalog.gen_random_uuid());
    insert into public.workspace_domain_challenges (workspace_id, domain, nonce) values (p_ws, v_domain, v_nonce)
    on conflict (workspace_id) do update set domain = excluded.domain, nonce = excluded.nonce, created_at = now();
  end if;
  return pg_catalog.jsonb_build_object('ok', true, 'domain', v_domain, 'nonce', pg_catalog.encode(v_nonce, 'hex'));
end $$;
revoke all on function public.rout_trust_domain_challenge(uuid) from public, rout_app;
grant execute on function public.rout_trust_domain_challenge(uuid) to rout_app;

-- Seals the domain after the server matched the nonce-bound proof. dns_txt needs a DNSSEC answer
-- (checked by the server); well_known_email also needs the caller's verified work e-mail here.
create or replace function public.rout_trust_attest_domain(p_ws uuid, p_kind text, p_nonce text, p_evidence bytea)
returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_user uuid := public.rout_current_user_id();
  v_domain text;
  v_email record;
  v_old uuid;
  v_id uuid;
begin
  if v_user is null or p_ws is null or not public.rout_ws_support_manager(p_ws) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'not_manager');
  end if;
  if p_kind not in ('dns_txt', 'well_known_email') or p_evidence is null or octet_length(p_evidence) <> 32 then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid');
  end if;
  select w.domain into v_domain from public.workspaces w
    join public.workspace_domain_challenges c on c.workspace_id = w.id and c.domain = w.domain
   where w.id = p_ws and pg_catalog.encode(c.nonce, 'hex') = p_nonce;
  if v_domain is null then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'challenge_mismatch'); end if;
  if p_kind = 'well_known_email' then
    select e.id, e.expires_at into v_email from public.workspace_work_emails e
     where e.workspace_id = p_ws and e.user_id = v_user and e.status = 'verified' and e.domain = v_domain and e.expires_at > now();
    if v_email.id is null then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'work_email_required'); end if;
  end if;
  if exists (select 1 from public.workspace_trust_attestations a
              where a.layer = 'domain' and a.status = 'active' and a.domain = v_domain and a.workspace_id <> p_ws) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'domain_bound_elsewhere');
  end if;
  update public.workspace_trust_attestations a set status = 'superseded', ended_at = now(), end_reason = 'reattested'
   where a.workspace_id = p_ws and a.layer = 'domain' and a.status = 'active'
  returning a.id into v_old;
  insert into public.workspace_trust_attestations (workspace_id, layer, kind, domain, evidence_digest, attested_by, last_checked_at, expires_at)
  values (p_ws, 'domain', p_kind, v_domain, p_evidence, v_user, now(), case when p_kind = 'well_known_email' then v_email.expires_at end)
  returning id into v_id;
  update public.workspaces w set domain_verified_at = now() where w.id = p_ws;
  perform public.rout_trust_log(p_ws, v_id, 'domain_attested', v_user, pg_catalog.jsonb_build_object('kind', p_kind));
  perform public.rout_trust_entity_recompute(p_ws);
  return pg_catalog.jsonb_build_object('ok', true, 'id', v_id);
end $$;
revoke all on function public.rout_trust_attest_domain(uuid, text, text, bytea) from public, rout_app;
grant execute on function public.rout_trust_attest_domain(uuid, text, text, bytea) to rout_app;

-- Cron: active domain seals to re-check, oldest check first (no member context needed: the list
-- holds only public domains and nonces, which prove nothing without the server key).
create or replace function public.rout_trust_domain_sweep(p_limit integer)
returns jsonb language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('id', x.id, 'workspaceId', x.workspace_id, 'domain', x.domain,
           'kind', x.kind, 'nonce', x.nonce, 'failingSince', x.failing_since)), '[]'::jsonb)
    from (select a.id, a.workspace_id, a.domain, a.kind, pg_catalog.encode(c.nonce, 'hex') as nonce, a.failing_since
            from public.workspace_trust_attestations a
            join public.workspace_domain_challenges c on c.workspace_id = a.workspace_id and c.domain = a.domain
           where a.layer = 'domain' and a.status = 'active'
           order by a.last_checked_at nulls first
           limit least(greatest(coalesce(p_limit, 50), 1), 200)) x
$$;
revoke all on function public.rout_trust_domain_sweep(integer) from public, rout_app;
grant execute on function public.rout_trust_domain_sweep(integer) to rout_app;

-- Cron result for one seal. A lookup error is never reported (no state change). A missing record
-- starts the 72 h grace on the database clock; past it the seal lapses, the workspace loses the
-- domain right and declared mandates (which rest on the DNS seal) end.
create or replace function public.rout_trust_domain_report(p_id uuid, p_present boolean)
returns text language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare a public.workspace_trust_attestations%rowtype;
begin
  select * into a from public.workspace_trust_attestations x where x.id = p_id and x.layer = 'domain' and x.status = 'active' for update;
  if not found or p_present is null then return 'ignored'; end if;
  if p_present then
    update public.workspace_trust_attestations x set last_checked_at = now(), failing_since = null where x.id = p_id;
    return 'ok';
  end if;
  if a.failing_since is null then
    update public.workspace_trust_attestations x set last_checked_at = now(), failing_since = now() where x.id = p_id;
    perform public.rout_trust_log(a.workspace_id, p_id, 'domain_check_failed', null, '{}'::jsonb);
    return 'failing';
  end if;
  if now() - a.failing_since < interval '72 hours' then
    update public.workspace_trust_attestations x set last_checked_at = now() where x.id = p_id;
    return 'failing';
  end if;
  update public.workspace_trust_attestations x set status = 'lapsed', ended_at = now(), end_reason = 'record_missing', last_checked_at = now()
   where x.id = p_id;
  update public.workspaces w set domain_verified_at = null where w.id = a.workspace_id and w.domain = a.domain;
  perform public.rout_trust_log(a.workspace_id, p_id, 'domain_lapsed', null, '{}'::jsonb);
  perform public.rout_trust_end_mandates(a.workspace_id, null, 'declared', 'revoked', 'domain_lapsed', null);
  perform public.rout_trust_entity_recompute(a.workspace_id);
  return 'lapsed';
end $$;
revoke all on function public.rout_trust_domain_report(uuid, boolean) from public, rout_app;
grant execute on function public.rout_trust_domain_report(uuid, boolean) to rout_app;

-- A changed or cleared domain ends its seal, its nonce and the declared mandates resting on it.
create or replace function public.workspaces_trust_domain_changed() returns trigger
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare v_id uuid;
begin
  if NEW.domain is not distinct from OLD.domain then return NEW; end if;
  delete from public.workspace_domain_challenges c where c.workspace_id = NEW.id;
  update public.workspace_trust_attestations a set status = 'superseded', ended_at = now(), end_reason = 'domain_changed'
   where a.workspace_id = NEW.id and a.layer = 'domain' and a.status = 'active'
  returning a.id into v_id;
  if v_id is not null then
    perform public.rout_trust_log(NEW.id, v_id, 'domain_ended', public.rout_current_user_id(), '{}'::jsonb);
  end if;
  update public.workspace_work_emails e set status = 'superseded', code_hash = null, verified_at = null, expires_at = null
   where e.workspace_id = NEW.id and e.status in ('pending', 'verified');
  perform public.rout_trust_end_mandates(NEW.id, null, 'declared', 'revoked', 'domain_changed', public.rout_current_user_id());
  perform public.rout_trust_entity_recompute(NEW.id);
  return NEW;
end $$;
revoke all on function public.workspaces_trust_domain_changed() from public, rout_app;
drop trigger if exists workspaces_trust_domain_changed on public.workspaces;
create trigger workspaces_trust_domain_changed after update of domain on public.workspaces
  for each row execute function public.workspaces_trust_domain_changed();

-- ------------------------------------------------------------------ layer 1: work e-mail
-- Starts a six-digit code challenge for an address on the workspace domain. The server checked the
-- address belongs to the domain and sends the code; the database keeps only keyed hashes.
create or replace function public.rout_trust_work_email_start(p_ws uuid, p_email_hash bytea, p_code_hash bytea)
returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_user uuid := public.rout_current_user_id();
  v_domain text;
  v_id uuid;
begin
  if v_user is null or p_ws is null or not public.rout_ws_support_manager(p_ws) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'not_manager');
  end if;
  if p_email_hash is null or octet_length(p_email_hash) <> 32 or p_code_hash is null or octet_length(p_code_hash) <> 32 then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid');
  end if;
  select w.domain into v_domain from public.workspaces w where w.id = p_ws;
  if v_domain is null then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'no_domain'); end if;
  if (select pg_catalog.count(*) from public.workspace_work_emails e
       where e.user_id = v_user and e.created_at > now() - interval '1 hour') >= 5 then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'rate_limited');
  end if;
  update public.workspace_work_emails e set status = 'superseded', code_hash = null
   where e.workspace_id = p_ws and e.user_id = v_user and e.status = 'pending';
  insert into public.workspace_work_emails (workspace_id, user_id, domain, email_hash, code_hash, code_expires_at)
  values (p_ws, v_user, v_domain, p_email_hash, p_code_hash, now() + interval '15 minutes')
  returning id into v_id;
  perform public.rout_trust_log(p_ws, v_id, 'work_email_sent', v_user, '{}'::jsonb);
  return pg_catalog.jsonb_build_object('ok', true, 'id', v_id);
end $$;
revoke all on function public.rout_trust_work_email_start(uuid, bytea, bytea) from public, rout_app;
grant execute on function public.rout_trust_work_email_start(uuid, bytea, bytea) to rout_app;

-- Confirms the code: at most 5 tries within 15 minutes; a verified address holds for 365 days.
create or replace function public.rout_trust_work_email_confirm(p_ws uuid, p_code_hash bytea)
returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_user uuid := public.rout_current_user_id();
  e public.workspace_work_emails%rowtype;
begin
  if v_user is null or p_ws is null or not public.rout_ws_support_manager(p_ws) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'not_manager');
  end if;
  select * into e from public.workspace_work_emails x
   where x.workspace_id = p_ws and x.user_id = v_user and x.status = 'pending' for update;
  if not found or e.code_expires_at < now() then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'expired'); end if;
  if e.attempts >= 5 then
    update public.workspace_work_emails x set status = 'failed', code_hash = null where x.id = e.id;
    perform public.rout_trust_log(p_ws, e.id, 'work_email_failed', v_user, '{}'::jsonb);
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'too_many_attempts');
  end if;
  if p_code_hash is null or p_code_hash <> e.code_hash then
    update public.workspace_work_emails x set attempts = x.attempts + 1 where x.id = e.id;
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'wrong_code');
  end if;
  update public.workspace_work_emails x set status = 'superseded', verified_at = null, expires_at = null
   where x.workspace_id = p_ws and x.user_id = v_user and x.status = 'verified';
  update public.workspace_work_emails x set status = 'verified', code_hash = null, verified_at = now(), expires_at = now() + interval '365 days'
   where x.id = e.id;
  perform public.rout_trust_log(p_ws, e.id, 'work_email_verified', v_user, '{}'::jsonb);
  return pg_catalog.jsonb_build_object('ok', true, 'id', e.id);
end $$;
revoke all on function public.rout_trust_work_email_confirm(uuid, bytea) from public, rout_app;
grant execute on function public.rout_trust_work_email_confirm(uuid, bytea) to rout_app;

-- ------------------------------------------------------------------ layer 2: entity
-- Register attestation right after the server checked VIES or GLEIF. Stores the keyed nullifier,
-- the country, the digest of the register answer and, only on opt-in, the register name.
create or replace function public.rout_trust_attest_entity(p_ws uuid, p_kind text, p_nullifier bytea, p_country text,
  p_evidence bytea, p_public_name text)
returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare v_user uuid := public.rout_current_user_id();
begin
  if v_user is null or p_ws is null or not public.rout_ws_support_manager(p_ws) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'not_manager');
  end if;
  if p_kind is null or p_kind not in ('vat_vies', 'lei_gleif') or p_nullifier is null or octet_length(p_nullifier) <> 32
     or p_evidence is null or octet_length(p_evidence) <> 32 or p_country is null or p_country !~ '^[A-Z]{2}$'
     or (p_public_name is not null and char_length(p_public_name) not between 1 and 200) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid');
  end if;
  return public.rout_trust_entity_insert(p_ws, p_kind, p_nullifier, p_country, p_evidence, p_public_name, v_user);
end $$;
revoke all on function public.rout_trust_attest_entity(uuid, text, bytea, text, bytea, text) from public, rout_app;
grant execute on function public.rout_trust_attest_entity(uuid, text, bytea, text, bytea, text) to rout_app;

create or replace function public.rout_trust_revoke_entity(p_ws uuid)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_user uuid := public.rout_current_user_id();
  v_id uuid;
begin
  if v_user is null or p_ws is null or not public.rout_ws_support_manager(p_ws) then return false; end if;
  update public.workspace_trust_attestations a set status = 'revoked', ended_at = now(), end_reason = 'manager'
   where a.workspace_id = p_ws and a.layer = 'entity' and a.status = 'active'
  returning a.id into v_id;
  if v_id is null then return false; end if;
  perform public.rout_trust_log(p_ws, v_id, 'entity_revoked', v_user, '{}'::jsonb);
  perform public.rout_trust_end_mandates(p_ws, null, null, 'revoked', 'organization_ended', v_user);
  perform public.rout_trust_entity_recompute(p_ws);
  return true;
end $$;
revoke all on function public.rout_trust_revoke_entity(uuid) from public, rout_app;
grant execute on function public.rout_trust_revoke_entity(uuid) to rout_app;

-- ------------------------------------------------------------------ evidence (public body, proven mandate)
-- Stores a server-sealed (AES-256-GCM) document for review. The id is chosen by the server because
-- it is bound into the ciphertext. Purged on decision, withdrawal or after 7 days at the latest.
create or replace function public.rout_trust_evidence_submit(p_id uuid, p_ws uuid, p_subject text, p_kind text, p_sha256 bytea,
  p_mime text, p_size integer, p_ciphertext bytea, p_nullifier bytea, p_country text, p_public_name text)
returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare v_user uuid := public.rout_current_user_id();
begin
  if v_user is null or p_ws is null or not public.rout_ws_support_manager(p_ws) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'not_manager');
  end if;
  if p_id is null or p_subject not in ('public_body', 'mandate_proven')
     or p_kind not in ('kbo_extract', 'staatsblad', 'appointment_decision', 'qes_mandate')
     or (p_subject = 'public_body' and p_kind = 'qes_mandate')
     or p_sha256 is null or octet_length(p_sha256) <> 32 or p_ciphertext is null
     or p_mime not in ('application/pdf', 'image/png', 'image/jpeg') or p_size not between 1 and 5242880
     or (p_subject = 'public_body') <> (p_nullifier is not null and p_country is not null) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid');
  end if;
  if p_subject = 'mandate_proven' then
    if not public.rout_user_has_legal_identity(v_user) then
      return pg_catalog.jsonb_build_object('ok', false, 'reason', 'legal_identity_required');
    end if;
    if not exists (select 1 from public.workspace_trust_attestations a
                    where a.workspace_id = p_ws and a.layer = 'entity' and a.status = 'active' and a.expires_at > now()) then
      return pg_catalog.jsonb_build_object('ok', false, 'reason', 'organization_required');
    end if;
  elsif exists (select 1 from public.workspace_trust_attestations a
                 where a.layer = 'entity' and a.status = 'active' and a.subject_nullifier = p_nullifier and a.workspace_id <> p_ws) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'organization_bound_elsewhere');
  end if;
  if (select pg_catalog.count(*) from public.trust_evidence_reviews r
       where r.requester_user_id = v_user and r.submitted_at > now() - interval '24 hours') >= 5 then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'rate_limited');
  end if;
  begin
    insert into public.trust_evidence_reviews (id, workspace_id, requester_user_id, subject, evidence_kind, sha256, mime, byte_size,
      ciphertext, subject_nullifier, country, public_name, purge_due_at)
    values (p_id, p_ws, v_user, p_subject, p_kind, p_sha256, p_mime, p_size, p_ciphertext, p_nullifier, p_country,
      p_public_name, now() + interval '7 days');
  exception when unique_violation then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'already_pending');
  end;
  perform public.rout_trust_log(p_ws, p_id, 'evidence_submitted', v_user, pg_catalog.jsonb_build_object('subject', p_subject, 'kind', p_kind));
  return pg_catalog.jsonb_build_object('ok', true, 'id', p_id);
end $$;
revoke all on function public.rout_trust_evidence_submit(uuid, uuid, text, text, bytea, text, integer, bytea, bytea, text, text) from public, rout_app;
grant execute on function public.rout_trust_evidence_submit(uuid, uuid, text, text, bytea, text, integer, bytea, bytea, text, text) to rout_app;

create or replace function public.rout_trust_evidence_withdraw(p_id uuid)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_user uuid := public.rout_current_user_id();
  r public.trust_evidence_reviews%rowtype;
begin
  select * into r from public.trust_evidence_reviews x where x.id = p_id and x.status = 'pending' for update;
  if not found or v_user is null or (r.requester_user_id <> v_user and not public.rout_ws_support_manager(r.workspace_id)) then
    return false;
  end if;
  perform public.rout_trust_evidence_close(p_id, 'withdrawn', 'withdrawn', v_user);
  return true;
end $$;
revoke all on function public.rout_trust_evidence_withdraw(uuid) from public, rout_app;
grant execute on function public.rout_trust_evidence_withdraw(uuid) to rout_app;

-- Admin queue (full admin with two-factor on): open reviews without the documents themselves.
create or replace function public.rout_admin_trust_reviews()
returns jsonb language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select case when public.rout_recovery_caller_admin() is null then null else
    coalesce((select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'id', r.id, 'workspaceId', w.id, 'workspaceSlug', w.slug, 'workspaceName', w.name, 'domain', w.domain,
        'subject', r.subject, 'evidenceKind', r.evidence_kind, 'mime', r.mime, 'byteSize', r.byte_size,
        'sha256', pg_catalog.encode(r.sha256, 'hex'), 'country', r.country, 'publicName', r.public_name,
        'requesterUserId', r.requester_user_id, 'requesterLegalIdentity', public.rout_user_has_legal_identity(r.requester_user_id),
        'ownRequest', r.requester_user_id = public.rout_current_user_id(),
        'entityKind', (select a.kind from public.workspace_trust_attestations a where a.workspace_id = w.id and a.layer = 'entity' and a.status = 'active'),
        'submittedAt', r.submitted_at, 'purgeDueAt', r.purge_due_at) order by r.submitted_at)
       from public.trust_evidence_reviews r join public.workspaces w on w.id = r.workspace_id
      where r.status = 'pending' and r.purge_due_at > now()), '[]'::jsonb) end
$$;
revoke all on function public.rout_admin_trust_reviews() from public, rout_app;
grant execute on function public.rout_admin_trust_reviews() to rout_app;

-- Hands the sealed document to the server for an admin view; every opening is on the chain.
create or replace function public.rout_admin_trust_evidence_open(p_id uuid)
returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_admin uuid := public.rout_recovery_caller_admin();
  r public.trust_evidence_reviews%rowtype;
begin
  if v_admin is null then return null; end if;
  select * into r from public.trust_evidence_reviews x where x.id = p_id and x.status = 'pending' and x.purge_due_at > now();
  if not found or r.requester_user_id = v_admin then return null; end if;
  perform public.rout_trust_log(r.workspace_id, p_id, 'evidence_viewed', v_admin, '{}'::jsonb);
  return pg_catalog.jsonb_build_object('id', r.id, 'mime', r.mime, 'sha256', pg_catalog.encode(r.sha256, 'hex'),
    'ciphertext', pg_catalog.encode(r.ciphertext, 'base64'));
end $$;
revoke all on function public.rout_admin_trust_evidence_open(uuid) from public, rout_app;
grant execute on function public.rout_admin_trust_evidence_open(uuid) to rout_app;

-- Decision. Approval of a public body creates its entity seal; approval of a proven mandate makes the
-- requester's mandate 'proven' for 12 months and supersedes their declaration. Either way the
-- document is destroyed in this transaction; only its SHA-256 and the audit trail remain.
create or replace function public.rout_admin_trust_evidence_decide(p_id uuid, p_approve boolean, p_code text)
returns text language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_admin uuid := public.rout_recovery_caller_admin();
  r public.trust_evidence_reviews%rowtype;
  v_entity uuid;
  v_res jsonb;
  v_mid uuid;
begin
  if v_admin is null then return 'forbidden'; end if;
  select * into r from public.trust_evidence_reviews x where x.id = p_id for update;
  if not found or r.status <> 'pending' then return 'not_open'; end if;
  if r.requester_user_id = v_admin then return 'own_request'; end if;
  if not coalesce(p_approve, false) then
    if p_code is null or p_code not in ('insufficient', 'mismatch', 'unreadable') then return 'invalid'; end if;
    perform public.rout_trust_evidence_close(p_id, 'rejected', p_code, v_admin);
    return 'rejected';
  end if;
  if r.subject = 'public_body' then
    v_res := public.rout_trust_entity_insert(r.workspace_id, 'public_body', r.subject_nullifier, r.country, r.sha256, r.public_name, v_admin);
    if not coalesce((v_res ->> 'ok')::boolean, false) then return v_res ->> 'reason'; end if;
  else
    select a.id into v_entity from public.workspace_trust_attestations a
     where a.workspace_id = r.workspace_id and a.layer = 'entity' and a.status = 'active' and a.expires_at > now();
    if v_entity is null then return 'organization_inactive'; end if;
    if not public.rout_user_has_legal_identity(r.requester_user_id) then return 'legal_identity_required'; end if;
    if not exists (select 1 from public.workspace_members m where m.workspace_id = r.workspace_id
                    and m.user_id = r.requester_user_id and m.role::text in ('owner', 'admin')) then
      return 'not_manager';
    end if;
    perform public.rout_trust_end_mandates(r.workspace_id, r.requester_user_id, null, 'superseded', 'superseded', v_admin);
    insert into public.workspace_mandates (workspace_id, attestation_id, holder_user_id, level, basis, statement_digest,
      identity_attested_at, evidence_review_id, decided_by, expires_at)
    values (r.workspace_id, v_entity, r.requester_user_id, 'proven', r.evidence_kind, r.sha256,
      public.rout_user_identity_attested_at(r.requester_user_id), r.id, v_admin, now() + interval '365 days')
    returning id into v_mid;
    perform public.rout_trust_log(r.workspace_id, v_mid, 'mandate_proven', v_admin, pg_catalog.jsonb_build_object('basis', r.evidence_kind));
  end if;
  perform public.rout_trust_evidence_close(p_id, 'approved', 'approved', v_admin);
  return 'approved';
end $$;
revoke all on function public.rout_admin_trust_evidence_decide(uuid, boolean, text) from public, rout_app;
grant execute on function public.rout_admin_trust_evidence_decide(uuid, boolean, text) to rout_app;

-- ------------------------------------------------------------------ layer 3: declared mandate
-- Self-service declaration. The server built the canonical statement, had it confirmed with a passkey
-- (Sudo Mode) and signed it with its declaration key; here every precondition is checked again and
-- the statement must name exactly this workspace, holder, entity seal, domain and work e-mail.
create or replace function public.rout_trust_mandate_declare(p_ws uuid, p_statement text, p_digest bytea, p_signature text, p_kid text)
returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_user uuid := public.rout_current_user_id();
  v_entity uuid;
  v_domain text;
  v_email uuid;
  v_stmt jsonb;
  v_id uuid;
begin
  if v_user is null or p_ws is null or not public.rout_ws_support_manager(p_ws) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'not_manager');
  end if;
  if not public.rout_user_has_legal_identity(v_user) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'legal_identity_required');
  end if;
  select a.id into v_entity from public.workspace_trust_attestations a
   where a.workspace_id = p_ws and a.layer = 'entity' and a.status = 'active' and a.expires_at > now();
  if v_entity is null then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'organization_required'); end if;
  select a.domain into v_domain from public.workspace_trust_attestations a
    join public.workspaces w on w.id = a.workspace_id and w.domain = a.domain
   where a.workspace_id = p_ws and a.layer = 'domain' and a.status = 'active' and a.kind = 'dns_txt';
  if v_domain is null then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'dns_required'); end if;
  select e.id into v_email from public.workspace_work_emails e
   where e.workspace_id = p_ws and e.user_id = v_user and e.status = 'verified' and e.domain = v_domain and e.expires_at > now();
  if v_email is null then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'work_email_required'); end if;
  if exists (select 1 from public.workspace_mandates m where m.workspace_id = p_ws and m.holder_user_id = v_user
              and m.level = 'proven' and m.status in ('active', 'frozen')) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'already_proven');
  end if;
  if exists (select 1 from public.workspace_mandates m where m.workspace_id = p_ws and m.holder_user_id = v_user and m.status = 'frozen') then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'frozen');
  end if;
  if p_statement is null or octet_length(p_statement) > 4096 or p_digest is null
     or pg_catalog.sha256(pg_catalog.convert_to(p_statement, 'UTF8')) <> p_digest
     or p_signature is null or p_signature !~ '^[A-Za-z0-9_-]{86}$' or p_kid is null or p_kid !~ '^[0-9a-f]{16}$' then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid');
  end if;
  begin
    v_stmt := p_statement::jsonb;
  exception when others then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid');
  end;
  if v_stmt ->> 'v' is distinct from 'rout.mandate.declaration.v1' or v_stmt ->> 'workspace' is distinct from p_ws::text
     or v_stmt ->> 'holder' is distinct from v_user::text or v_stmt ->> 'entity' is distinct from v_entity::text
     or v_stmt ->> 'domain' is distinct from v_domain or v_stmt ->> 'workEmail' is distinct from v_email::text then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'statement_mismatch');
  end if;
  perform public.rout_trust_end_mandates(p_ws, v_user, 'declared', 'superseded', 'superseded', v_user);
  insert into public.workspace_mandates (workspace_id, attestation_id, holder_user_id, level, basis, statement, statement_digest,
    signature, signature_kid, identity_attested_at, work_email_id, expires_at)
  values (p_ws, v_entity, v_user, 'declared', 'signed_declaration', p_statement, p_digest, p_signature, p_kid,
    public.rout_user_identity_attested_at(v_user), v_email, now() + interval '365 days')
  returning id into v_id;
  perform public.rout_trust_log(p_ws, v_id, 'mandate_declared', v_user,
    pg_catalog.jsonb_build_object('digest', pg_catalog.encode(p_digest, 'hex'), 'kid', p_kid));
  return pg_catalog.jsonb_build_object('ok', true, 'id', v_id);
end $$;
revoke all on function public.rout_trust_mandate_declare(uuid, text, bytea, text, text) from public, rout_app;
grant execute on function public.rout_trust_mandate_declare(uuid, text, bytea, text, text) to rout_app;

-- Holder or a workspace owner/admin ends a mandate at once.
create or replace function public.rout_trust_mandate_end(p_id uuid)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_user uuid := public.rout_current_user_id();
  m public.workspace_mandates%rowtype;
begin
  select * into m from public.workspace_mandates x where x.id = p_id and x.status in ('active', 'frozen') for update;
  if not found or v_user is null then return false; end if;
  if m.holder_user_id <> v_user and not public.rout_ws_support_manager(m.workspace_id) then return false; end if;
  update public.workspace_mandates x set status = 'revoked', ended_at = now(), frozen_at = null,
         end_reason = case when m.holder_user_id = v_user then 'holder' else 'manager' end
   where x.id = p_id;
  perform public.rout_trust_log(m.workspace_id, p_id, 'mandate_revoked', v_user,
    pg_catalog.jsonb_build_object('reason', case when m.holder_user_id = v_user then 'holder' else 'manager' end));
  return true;
end $$;
revoke all on function public.rout_trust_mandate_end(uuid) from public, rout_app;
grant execute on function public.rout_trust_mandate_end(uuid) to rout_app;

-- Full admin: freeze (immediate, reversible), unfreeze or revoke.
create or replace function public.rout_admin_trust_mandate_set(p_id uuid, p_action text)
returns text language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_admin uuid := public.rout_recovery_caller_admin();
  m public.workspace_mandates%rowtype;
begin
  if v_admin is null then return 'forbidden'; end if;
  select * into m from public.workspace_mandates x where x.id = p_id and x.status in ('active', 'frozen') for update;
  if not found then return 'not_open'; end if;
  if p_action = 'freeze' and m.status = 'active' then
    update public.workspace_mandates x set status = 'frozen', frozen_at = now(), frozen_by = v_admin where x.id = p_id;
    perform public.rout_trust_log(m.workspace_id, p_id, 'mandate_frozen', v_admin, '{}'::jsonb);
    return 'frozen';
  elsif p_action = 'unfreeze' and m.status = 'frozen' then
    if m.expires_at <= now() then return 'expired'; end if;
    update public.workspace_mandates x set status = 'active', frozen_at = null, frozen_by = null where x.id = p_id;
    perform public.rout_trust_log(m.workspace_id, p_id, 'mandate_unfrozen', v_admin, '{}'::jsonb);
    return 'active';
  elsif p_action = 'revoke' then
    update public.workspace_mandates x set status = 'revoked', ended_at = now(), frozen_at = null, end_reason = 'admin' where x.id = p_id;
    perform public.rout_trust_log(m.workspace_id, p_id, 'mandate_revoked', v_admin, pg_catalog.jsonb_build_object('reason', 'admin'));
    return 'revoked';
  end if;
  return 'invalid';
end $$;
revoke all on function public.rout_admin_trust_mandate_set(uuid, text) from public, rout_app;
grant execute on function public.rout_admin_trust_mandate_set(uuid, text) to rout_app;

-- Leaving the workspace or losing owner/admin ends the member's mandates immediately.
create or replace function public.workspace_members_trust_mandates() returns trigger
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
begin
  if OLD.role::text in ('owner', 'admin') and (TG_OP = 'DELETE' or NEW.role::text not in ('owner', 'admin')) then
    perform public.rout_trust_end_mandates(OLD.workspace_id, OLD.user_id, null, 'revoked', 'left_workspace', public.rout_current_user_id());
  end if;
  return null;
end $$;
revoke all on function public.workspace_members_trust_mandates() from public, rout_app;
drop trigger if exists workspace_members_trust_mandates on public.workspace_members;
create trigger workspace_members_trust_mandates after delete or update of role on public.workspace_members
  for each row execute function public.workspace_members_trust_mandates();

-- ------------------------------------------------------------------ objections
-- Any signed-in member may object (e.g. an official director); a full admin decides. Filing alone
-- never freezes anything, so an objection cannot be used to sabotage a workspace.
create or replace function public.rout_trust_objection_file(p_slug text, p_reason text)
returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_user uuid := public.rout_current_user_id();
  v_ws uuid;
  v_id uuid;
begin
  if v_user is null then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'sign_in'); end if;
  if p_reason not in ('not_authorized', 'left_organization', 'impersonation', 'other') then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid');
  end if;
  select w.id into v_ws from public.workspaces w where w.slug = pg_catalog.lower(p_slug);
  if v_ws is null or not exists (select 1 from public.workspace_mandates m where m.workspace_id = v_ws and m.status in ('active', 'frozen')) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'no_mandate');
  end if;
  if (select pg_catalog.count(*) from public.workspace_mandate_objections o
       where o.filed_by = v_user and o.filed_at > now() - interval '24 hours') >= 3 then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'rate_limited');
  end if;
  begin
    insert into public.workspace_mandate_objections (workspace_id, filed_by, filer_legal_identity, reason)
    values (v_ws, v_user, public.rout_user_has_legal_identity(v_user), p_reason)
    returning id into v_id;
  exception when unique_violation then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'already_open');
  end;
  perform public.rout_trust_log(v_ws, v_id, 'objection_filed', v_user, pg_catalog.jsonb_build_object('reason', p_reason));
  return pg_catalog.jsonb_build_object('ok', true, 'id', v_id);
end $$;
revoke all on function public.rout_trust_objection_file(text, text) from public, rout_app;
grant execute on function public.rout_trust_objection_file(text, text) to rout_app;

create or replace function public.rout_admin_trust_objections()
returns jsonb language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select case when public.rout_recovery_caller_admin() is null then null else
    coalesce((select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'id', o.id, 'workspaceId', w.id, 'workspaceSlug', w.slug, 'workspaceName', w.name, 'reason', o.reason,
        'filerLegalIdentity', o.filer_legal_identity, 'filedAt', o.filed_at,
        'mandates', coalesce((select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('id', m.id, 'level', m.level, 'status', m.status,
            'holderUserId', m.holder_user_id, 'expiresAt', m.expires_at) order by m.activated_at)
           from public.workspace_mandates m where m.workspace_id = w.id and m.status in ('active', 'frozen')), '[]'::jsonb))
        order by o.filed_at)
       from public.workspace_mandate_objections o join public.workspaces w on w.id = o.workspace_id
      where o.status = 'open'), '[]'::jsonb) end
$$;
revoke all on function public.rout_admin_trust_objections() from public, rout_app;
grant execute on function public.rout_admin_trust_objections() to rout_app;

-- Upholding freezes every open mandate of the workspace at once; the admin may then revoke.
create or replace function public.rout_admin_trust_objection_decide(p_id uuid, p_uphold boolean)
returns text language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_admin uuid := public.rout_recovery_caller_admin();
  o public.workspace_mandate_objections%rowtype;
  r record;
begin
  if v_admin is null then return 'forbidden'; end if;
  select * into o from public.workspace_mandate_objections x where x.id = p_id and x.status = 'open' for update;
  if not found then return 'not_open'; end if;
  if o.filed_by = v_admin then return 'own_request'; end if;
  update public.workspace_mandate_objections x set status = case when p_uphold then 'upheld' else 'dismissed' end,
         decided_by = v_admin, decided_at = now()
   where x.id = p_id;
  if p_uphold then
    for r in update public.workspace_mandates m set status = 'frozen', frozen_at = now(), frozen_by = v_admin
              where m.workspace_id = o.workspace_id and m.status = 'active' returning m.id
    loop
      perform public.rout_trust_log(o.workspace_id, r.id, 'mandate_frozen', v_admin, pg_catalog.jsonb_build_object('objection', p_id));
    end loop;
  end if;
  perform public.rout_trust_log(o.workspace_id, p_id, case when p_uphold then 'objection_upheld' else 'objection_dismissed' end, v_admin, '{}'::jsonb);
  return case when p_uphold then 'upheld' else 'dismissed' end;
end $$;
revoke all on function public.rout_admin_trust_objection_decide(uuid, boolean) from public, rout_app;
grant execute on function public.rout_admin_trust_objection_decide(uuid, boolean) to rout_app;

-- ------------------------------------------------------------------ maintenance (cron, time-based only)
create or replace function public.rout_trust_maintenance()
returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  r record;
  v_evidence integer := 0;
  v_mandates integer := 0;
  v_entities integer := 0;
  v_domains integer := 0;
begin
  for r in select x.id from public.trust_evidence_reviews x where x.status = 'pending' and x.purge_due_at <= now() for update loop
    perform public.rout_trust_evidence_close(r.id, 'expired', 'expired', null);
    v_evidence := v_evidence + 1;
  end loop;
  for r in update public.workspace_mandates m set status = 'expired', ended_at = now(), frozen_at = null, end_reason = 'expired'
            where m.status in ('active', 'frozen') and m.expires_at <= now() returning m.id, m.workspace_id loop
    perform public.rout_trust_log(r.workspace_id, r.id, 'mandate_expired', null, '{}'::jsonb);
    v_mandates := v_mandates + 1;
  end loop;
  for r in update public.workspace_trust_attestations a set status = 'expired', ended_at = now(), end_reason = 'expired'
            where a.status = 'active' and a.expires_at is not null and a.expires_at <= now() returning a.id, a.workspace_id, a.layer loop
    if r.layer = 'entity' then
      perform public.rout_trust_log(r.workspace_id, r.id, 'entity_expired', null, '{}'::jsonb);
      perform public.rout_trust_end_mandates(r.workspace_id, null, null, 'expired', 'organization_ended', null);
      v_entities := v_entities + 1;
    else
      update public.workspaces w set domain_verified_at = null where w.id = r.workspace_id;
      perform public.rout_trust_log(r.workspace_id, r.id, 'domain_lapsed', null, pg_catalog.jsonb_build_object('reason', 'expired'));
      v_domains := v_domains + 1;
    end if;
    perform public.rout_trust_entity_recompute(r.workspace_id);
  end loop;
  update public.workspace_work_emails e set status = 'failed', code_hash = null
   where e.status = 'pending' and e.code_expires_at < now() - interval '1 day';
  return pg_catalog.jsonb_build_object('evidencePurged', v_evidence, 'mandatesExpired', v_mandates,
    'entitiesExpired', v_entities, 'domainsExpired', v_domains);
end $$;
revoke all on function public.rout_trust_maintenance() from public, rout_app;
grant execute on function public.rout_trust_maintenance() to rout_app;

-- ------------------------------------------------------------------ reads
-- Studio overview for the workspace's owners/admins.
create or replace function public.rout_trust_manage(p_ws uuid)
returns jsonb language plpgsql stable security definer set search_path = pg_catalog, pg_temp as $$
declare v_user uuid := public.rout_current_user_id();
begin
  if v_user is null or p_ws is null or not public.rout_ws_support_manager(p_ws) then return null; end if;
  return (select pg_catalog.jsonb_build_object(
    'entityType', w.entity_type,
    'domain', w.domain,
    'legacyDomainVerified', w.domain_verified_at is not null,
    'domainSeal', (select pg_catalog.jsonb_build_object('id', a.id, 'kind', a.kind, 'verifiedAt', a.verified_at,
        'lastCheckedAt', a.last_checked_at, 'failingSince', a.failing_since, 'expiresAt', a.expires_at)
        from public.workspace_trust_attestations a where a.workspace_id = w.id and a.layer = 'domain' and a.status = 'active'),
    'entity', (select pg_catalog.jsonb_build_object('id', a.id, 'kind', a.kind, 'country', a.country, 'publicName', a.public_name,
        'verifiedAt', a.verified_at, 'expiresAt', a.expires_at)
        from public.workspace_trust_attestations a where a.workspace_id = w.id and a.layer = 'entity' and a.status = 'active'),
    'workEmail', (select pg_catalog.jsonb_build_object('id', e.id, 'status', e.status, 'verifiedAt', e.verified_at,
        'expiresAt', e.expires_at, 'codeExpiresAt', e.code_expires_at)
        from public.workspace_work_emails e where e.workspace_id = w.id and e.user_id = v_user and e.status in ('pending', 'verified')
        order by (e.status = 'verified') desc, e.created_at desc limit 1),
    'legalIdentity', public.rout_user_has_legal_identity(v_user),
    'identityAttestedAt', public.rout_user_identity_attested_at(v_user),
    'mandates', coalesce((select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('id', m.id, 'level', m.level, 'status', m.status,
        'basis', m.basis, 'mine', m.holder_user_id = v_user, 'activatedAt', m.activated_at, 'expiresAt', m.expires_at) order by m.activated_at)
        from public.workspace_mandates m where m.workspace_id = w.id and m.status in ('active', 'frozen')), '[]'::jsonb),
    'reviews', coalesce((select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('id', r.id, 'subject', r.subject, 'kind', r.evidence_kind,
        'submittedAt', r.submitted_at, 'purgeDueAt', r.purge_due_at) order by r.submitted_at)
        from public.trust_evidence_reviews r where r.workspace_id = w.id and r.status = 'pending'), '[]'::jsonb),
    'lastDecision', (select pg_catalog.jsonb_build_object('subject', r.subject, 'status', r.status, 'code', r.decision_code, 'decidedAt', r.decided_at)
        from public.trust_evidence_reviews r where r.workspace_id = w.id and r.status <> 'pending' order by r.decided_at desc nulls last limit 1))
    from public.workspaces w where w.id = p_ws);
end $$;
revoke all on function public.rout_trust_manage(uuid) from public, rout_app;
grant execute on function public.rout_trust_manage(uuid) to rout_app;

-- Everything a visitor's badge needs, per layer: never a manager, register number, nullifier or e-mail.
-- A mandate counts only while its holder still has a legal identity and still manages the workspace,
-- the entity seal holds and, for a declaration, the DNS seal holds too.
create or replace function public.rout_public_workspace_trust(p_slug text)
returns jsonb language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  with w as (select x.* from public.workspaces x where x.slug = pg_catalog.lower(p_slug) limit 1),
  dom as (select a.* from public.workspace_trust_attestations a, w
           where a.workspace_id = w.id and a.layer = 'domain' and a.status = 'active' and a.domain = w.domain
             and (a.expires_at is null or a.expires_at > now())),
  ent as (select a.* from public.workspace_trust_attestations a, w
           where a.workspace_id = w.id and a.layer = 'entity' and a.status = 'active' and a.expires_at > now()),
  man as (select m.* from public.workspace_mandates m, w, ent
           where m.workspace_id = w.id and m.attestation_id = ent.id and m.expires_at > now()
             and public.rout_user_has_legal_identity(m.holder_user_id)
             and exists (select 1 from public.workspace_members wm where wm.workspace_id = w.id and wm.user_id = m.holder_user_id
                          and wm.role::text in ('owner', 'admin'))
             and (m.level = 'proven' or exists (select 1 from dom where dom.kind = 'dns_txt')))
  select pg_catalog.jsonb_build_object(
    'entityType', case when w.entity_type = 'INDIVIDUAL_CREATOR'
          and exists (select 1 from public.agent_sandboxes s where s.workspace_id = w.id and s.revoked_at is null)
          and not exists (select 1 from public.workspace_members m where m.workspace_id = w.id and m.role::text = 'owner')
         then 'AUTONOMOUS_AGENT' else w.entity_type end,
    'domain', (select pg_catalog.jsonb_build_object('name', dom.domain, 'kind', dom.kind, 'verifiedAt', dom.verified_at,
                 'lastCheckedAt', dom.last_checked_at) from dom),
    'entity', (select pg_catalog.jsonb_build_object('kind', ent.kind, 'country', ent.country, 'publicName', ent.public_name,
                 'verifiedAt', ent.verified_at, 'expiresAt', ent.expires_at) from ent),
    'mandate', (select pg_catalog.jsonb_build_object('level', m.level, 'activatedAt', m.activated_at, 'expiresAt', m.expires_at)
                  from man m where m.status = 'active' order by (m.level = 'proven') desc, m.activated_at desc limit 1),
    'mandateFrozen', exists (select 1 from man m where m.status = 'frozen'),
    'ownerSovereign', exists (select 1 from public.workspace_members m where m.workspace_id = w.id and m.role::text = 'owner'
                               and public.rout_user_has_legal_identity(m.user_id)))
  from w
$$;
revoke all on function public.rout_public_workspace_trust(text) from public, rout_app;
grant execute on function public.rout_public_workspace_trust(text) to rout_app;
