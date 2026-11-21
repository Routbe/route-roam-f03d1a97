-- Rollback of db-pending/0287_profile_field_encryption.sql (owner GO only).
-- Refuses while any value is sealed or any key version exists: dropping either would destroy
-- data whose plaintext is already NULL. Run the backfill's --restore mode first if ever needed.
do $$
begin
  if exists (select 1 from vault_enclave.profile_field_keys) then
    raise exception '0287 rollback refused: profile field keys exist';
  end if;
  if exists (select 1 from vault_enclave.audit_logs where action = 'profile_field_key_register') then
    raise exception '0287 rollback refused: the audit chain records key registrations';
  end if;
  if exists (select 1 from public.profiles where coalesce(business_vat_sealed, stripe_account_id_sealed, payment_method_sealed,
      moderation_reason_sealed, moderated_by_sealed, email_sealed, forwarding_email_sealed, legal_first_name_sealed,
      legal_last_name_sealed, last_city_sealed, last_country_sealed, forwarding_email_token_bidx) is not null) then
    raise exception '0287 rollback refused: sealed profile values exist';
  end if;
end $$;

drop function public.rout_profile_referred_mine();
drop function public.rout_profile_field_key_register(bytea, bytea, bytea);
drop function public.rout_profile_field_keys();
alter table public.profiles
  drop column business_vat_sealed, drop column stripe_account_id_sealed, drop column payment_method_sealed,
  drop column moderation_reason_sealed, drop column moderated_by_sealed, drop column email_sealed,
  drop column forwarding_email_sealed, drop column legal_first_name_sealed, drop column legal_last_name_sealed,
  drop column last_city_sealed, drop column last_country_sealed, drop column business_vat_bidx,
  drop column stripe_account_id_bidx, drop column email_bidx, drop column forwarding_email_bidx,
  drop column forwarding_email_token_bidx;
drop function public.rout_rpf1_shape_ok(bytea);
drop trigger profile_field_keys_no_truncate on vault_enclave.profile_field_keys;
drop trigger profile_field_keys_guard on vault_enclave.profile_field_keys;
drop table vault_enclave.profile_field_keys;
drop function vault_enclave.profile_field_keys_guard();
alter table vault_enclave.audit_logs drop constraint audit_logs_action_check;
alter table vault_enclave.audit_logs add constraint audit_logs_action_check
  check (action in ('step_up_register', 'token_store', 'token_retrieve', 'server_key_register',
                    'sdm_card_register', 'sdm_recovery_retrieve', 'sdm_recovery_confirm',
                    'sdm_fleet_register', 'sdm_batch_register', 'sdm_batch_cards_register',
                    'sdm_tap_begin', 'sdm_tap_confirm', 'sdm_tap_consume',
                    'sdm_card_activate', 'sdm_batch_list', 'sdm_batch_export',
                    'sdm_station_register', 'sdm_station_list', 'sdm_station_retire',
                    'card_step_up_begin', 'card_step_up_complete', 'card_step_up_claim',
                    'sdm_card_revoke',
                    'pake_setup_register', 'pake_register', 'pake_signup_register',
                    'pake_unregister', 'pake_login',
                    'passkey_attestation_record',
                    'recovery_v4_begin', 'recovery_v4_confirm', 'recovery_v4_commit',
                    'recovery_v4_abort', 'recovery_v4_remove', 'recovery_v4_expire',
                    'recovery_v4_replay', 'recovery_v4_compromise', 'recovery_v4_server_share',
                    'anon_host_key_init', 'anon_host_key_advance', 'anon_host_key_retire',
                    'anon_host_state_read', 'anon_booking_record', 'anon_booking_check',
                    'anon_pseudonym_invalidate', 'anon_capacity_open', 'anon_ledger_read',
                    'anon_host_purge', 'anon_host_merge',
                    'anon_device_register', 'anon_device_revoke', 'anon_device_list'));
