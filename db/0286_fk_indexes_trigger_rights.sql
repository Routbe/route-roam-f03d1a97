-- 0286 (EXPAND, additive): indexes for unindexed foreign keys, and no direct EXECUTE on
-- trigger-only SECURITY DEFINER functions.
--
-- Owner GO 2026-11-16 after the live read-only audit (HANDOVER appendix "live read-only audit
-- of Neon", findings A2 and A3).
--
-- A2: 47 foreign keys in public had no index whose leading columns match the key, so a delete
-- or key change on the referenced row (mostly public.users) scans the referencing table
-- under lock. Each index below covers exactly the key columns, in key order. The tables are
-- small, so a plain CREATE INDEX inside the rollout transaction is fine (no CONCURRENTLY,
-- which cannot run in a transaction).
--
-- A3: enforce_short_link_limits, grant_early_verified_promo, handle_new_user and
-- rout_shadow_mute_trust are SECURITY DEFINER trigger functions. PostgreSQL never lets anyone
-- call a trigger function directly and does not check EXECUTE when a trigger fires, so the
-- grants 0260 recorded (rout_app on all four, PUBLIC on two) only broke the rule that
-- trigger-only definers carry no EXECUTE for PUBLIC or rout_app. Revoked here; the triggers
-- keep firing for rout_app (src/test/migration-0286.test.ts proves a trigger fires for rout_app
-- without EXECUTE). rout_shadow_mute_trust has no trigger since 0183 dropped it and nothing
-- calls it, so on Neon it was a PUBLIC-callable orphan definer (verified read-only 2026-11-16).
--
-- No table, column, policy or function body changes. Rollback: drop the indexes and
-- re-grant per 0260 (db-pending/0286_fk_indexes_trigger_rights_rollback.sql).

-- --------------------------------------------------------------------------- A2: foreign-key indexes
create index if not exists account_merge_tickets_secondary_user_id_fkx on public.account_merge_tickets (secondary_user_id);
create index if not exists admin_bootstrap_tokens_consumed_by_fkx on public.admin_bootstrap_tokens (consumed_by);
create index if not exists admin_permissions_granted_by_fkx on public.admin_permissions (granted_by);
create index if not exists agent_workspace_claims_claimed_by_fkx on public.agent_workspace_claims (claimed_by);
create index if not exists agent_workspace_claims_sandbox_id_fkx on public.agent_workspace_claims (sandbox_id);
create index if not exists analytics_events_profile_id_fkx on public.analytics_events (profile_id);
create index if not exists booking_holds_event_type_id_fkx on public.booking_holds (event_type_id);
create index if not exists bookings_workspace_id_fkx on public.bookings (workspace_id);
create index if not exists community_reviews_user_id_fkx on public.community_reviews (user_id);
create index if not exists credential_issue_requests_badge_id_fkx on public.credential_issue_requests (badge_id);
create index if not exists factory_card_inventory_user_id_fkx on public.factory_card_inventory (user_id);
create index if not exists feedback_forms_user_id_fkx on public.feedback_forms (user_id);
create index if not exists identity_relays_connected_app_id_fkx on public.identity_relays (connected_app_id);
create index if not exists identity_verification_sessions_user_id_fkx on public.identity_verification_sessions (user_id);
create index if not exists oauth_access_tokens_client_id_fkx on public.oauth_access_tokens (client_id);
create index if not exists oauth_clients_workspace_id_fkx on public.oauth_clients (workspace_id);
create index if not exists oauth_refresh_tokens_client_id_fkx on public.oauth_refresh_tokens (client_id);
create index if not exists platform_feature_switches_updated_by_fkx on public.platform_feature_switches (updated_by);
create index if not exists platform_integration_switches_updated_by_fkx on public.platform_integration_switches (updated_by);
create index if not exists profile_events_user_id_fkx on public.profile_events (user_id);
create index if not exists qa_mute_actions_source_question_id_fkx on public.qa_mute_actions (source_question_id);
create index if not exists qa_trust_charges_sender_user_id_fkx on public.qa_trust_charges (sender_user_id);
create index if not exists reserved_brand_releases_released_by_fkx on public.reserved_brand_releases (released_by);
create index if not exists reserved_brand_releases_user_id_fkx on public.reserved_brand_releases (user_id);
create index if not exists rout_calendars_event_type_id_fkx on public.rout_calendars (event_type_id);
create index if not exists rout_calendars_workspace_id_fkx on public.rout_calendars (workspace_id);
create index if not exists sepa_review_queue_decided_by_fkx on public.sepa_review_queue (decided_by);
create index if not exists shadow_mutes_muted_sender_id_fkx on public.shadow_mutes (muted_sender_id);
create index if not exists user_connected_apps_visibility_client_id_fkx on public.user_connected_apps_visibility (client_id);
create index if not exists user_encrypted_audit_logs_user_id_key_id_fkx on public.user_encrypted_audit_logs (user_id, key_id);
create index if not exists user_feature_blocks_created_by_fkx on public.user_feature_blocks (created_by);
create index if not exists users_migrated_to_workspace_id_fkx on public.users (migrated_to_workspace_id);
create index if not exists wallet_passes_user_id_fkx on public.wallet_passes (user_id);
create index if not exists webhook_deliveries_endpoint_id_fkx on public.webhook_deliveries (endpoint_id);
create index if not exists workspace_ask_settings_updated_by_fkx on public.workspace_ask_settings (updated_by);
create index if not exists workspace_faq_items_published_by_fkx on public.workspace_faq_items (published_by);
create index if not exists workspace_invites_invited_by_fkx on public.workspace_invites (invited_by);
create index if not exists workspace_invites_invited_user_id_fkx on public.workspace_invites (invited_user_id);
create index if not exists workspace_keys_created_by_fkx on public.workspace_keys (created_by);
create index if not exists workspace_profile_drafts_updated_by_fkx on public.workspace_profile_drafts (updated_by);
create index if not exists workspace_psp_credentials_saved_by_fkx on public.workspace_psp_credentials (saved_by);
create index if not exists workspace_question_replies_replied_by_fkx on public.workspace_question_replies (replied_by);
create index if not exists workspace_social_links_created_by_fkx on public.workspace_social_links (created_by);
create index if not exists workspace_tip_settings_updated_by_fkx on public.workspace_tip_settings (updated_by);
create index if not exists workspace_transfers_target_user_id_fkx on public.workspace_transfers (target_user_id);
create index if not exists workspace_transfers_workspace_id_fkx on public.workspace_transfers (workspace_id);
create index if not exists workspaces_legacy_user_id_fkx on public.workspaces (legacy_user_id);

-- --------------------------------------------------------------------------- A3: trigger-only definers
revoke all on function public.enforce_short_link_limits() from public, rout_app;
revoke all on function public.grant_early_verified_promo() from public, rout_app;
revoke all on function public.handle_new_user() from public, rout_app;
revoke all on function public.rout_shadow_mute_trust() from public, rout_app;
