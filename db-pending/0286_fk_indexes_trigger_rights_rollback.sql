-- Rollback of db/0286. Restores the pre-0286 state exactly: drops the 47 foreign-key indexes and
-- re-grants EXECUTE as 0260 recorded it (rout_app on all four trigger functions, PUBLIC on two).
-- Run only after the owner's GO; it removes no data.

drop index if exists public.account_merge_tickets_secondary_user_id_fkx;
drop index if exists public.admin_bootstrap_tokens_consumed_by_fkx;
drop index if exists public.admin_permissions_granted_by_fkx;
drop index if exists public.agent_workspace_claims_claimed_by_fkx;
drop index if exists public.agent_workspace_claims_sandbox_id_fkx;
drop index if exists public.analytics_events_profile_id_fkx;
drop index if exists public.booking_holds_event_type_id_fkx;
drop index if exists public.bookings_workspace_id_fkx;
drop index if exists public.community_reviews_user_id_fkx;
drop index if exists public.credential_issue_requests_badge_id_fkx;
drop index if exists public.factory_card_inventory_user_id_fkx;
drop index if exists public.feedback_forms_user_id_fkx;
drop index if exists public.identity_relays_connected_app_id_fkx;
drop index if exists public.identity_verification_sessions_user_id_fkx;
drop index if exists public.oauth_access_tokens_client_id_fkx;
drop index if exists public.oauth_clients_workspace_id_fkx;
drop index if exists public.oauth_refresh_tokens_client_id_fkx;
drop index if exists public.platform_feature_switches_updated_by_fkx;
drop index if exists public.platform_integration_switches_updated_by_fkx;
drop index if exists public.profile_events_user_id_fkx;
drop index if exists public.qa_mute_actions_source_question_id_fkx;
drop index if exists public.qa_trust_charges_sender_user_id_fkx;
drop index if exists public.reserved_brand_releases_released_by_fkx;
drop index if exists public.reserved_brand_releases_user_id_fkx;
drop index if exists public.rout_calendars_event_type_id_fkx;
drop index if exists public.rout_calendars_workspace_id_fkx;
drop index if exists public.sepa_review_queue_decided_by_fkx;
drop index if exists public.shadow_mutes_muted_sender_id_fkx;
drop index if exists public.user_connected_apps_visibility_client_id_fkx;
drop index if exists public.user_encrypted_audit_logs_user_id_key_id_fkx;
drop index if exists public.user_feature_blocks_created_by_fkx;
drop index if exists public.users_migrated_to_workspace_id_fkx;
drop index if exists public.wallet_passes_user_id_fkx;
drop index if exists public.webhook_deliveries_endpoint_id_fkx;
drop index if exists public.workspace_ask_settings_updated_by_fkx;
drop index if exists public.workspace_faq_items_published_by_fkx;
drop index if exists public.workspace_invites_invited_by_fkx;
drop index if exists public.workspace_invites_invited_user_id_fkx;
drop index if exists public.workspace_keys_created_by_fkx;
drop index if exists public.workspace_profile_drafts_updated_by_fkx;
drop index if exists public.workspace_psp_credentials_saved_by_fkx;
drop index if exists public.workspace_question_replies_replied_by_fkx;
drop index if exists public.workspace_social_links_created_by_fkx;
drop index if exists public.workspace_tip_settings_updated_by_fkx;
drop index if exists public.workspace_transfers_target_user_id_fkx;
drop index if exists public.workspace_transfers_workspace_id_fkx;
drop index if exists public.workspaces_legacy_user_id_fkx;

grant execute on function public.enforce_short_link_limits() to rout_app;
grant execute on function public.grant_early_verified_promo() to public, rout_app;
grant execute on function public.handle_new_user() to rout_app;
grant execute on function public.rout_shadow_mute_trust() to public, rout_app;
delete from public.schema_migrations where filename = '0286_fk_indexes_trigger_rights.sql';
