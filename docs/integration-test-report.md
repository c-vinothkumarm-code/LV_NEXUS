# Integration test report

Generated 2026-11-17T06:05Z in the build environment (Python 3.13.18, MySQL 8.0.46-0ubuntu0.24.04.5, Node v22.23.4).

| Run | Result |
|---|---|
| MySQL 8 through the Alembic migration, with append-only triggers | 119 passed in 26.31s |
| In-memory SQLite | 118 passed, 1 skipped in 4.97s (the skipped test needs database triggers) |
| Backend statement coverage | 85% of 3490 statements |
| Lint | ruff: no findings |
| Frontend | `tsc -b && vite build` succeeded; all six pages rendered in headless Chromium against MySQL with no console errors |
| Local app on MySQL | `/health` ok; `/health/ready` database ok, 14 jobs in catalogue |
| Azure SQL | Not tested |

**Scope of evidence.** Cloud SDK calls are stubbed: botocore Stubber for AWS (real request/response validation), fakes for
GCP and Azure whose method names are checked against the installed SDK classes, mocked HTTP for Gemini and Google Chat,
an in-memory backend for Google Sheets. No live cloud, Google Workspace or AI API was called, and the BigQuery billing
query was not executed. Acceptance criteria therefore show "logic tested", not "validated", until the live runs are done.

## Acceptance criteria

| # | Criterion | Status | Evidence (test) |
|---|---|---|---|
| 1-3 | All AWS accounts / GCP projects / Azure subscriptions discovered | Logic tested; live pending | test_discovers_all_scopes_across_three_clouds, pagination and nested-folder tests |
| 4 | New scopes detected automatically | Logic tested | test_new_scope_detected_without_code_change |
| 5 | Failed authentication reported | Logic tested | test_access_failure_is_reported_with_exact_scope_and_creates_task |
| 6 | Missing audit logging identified | Logic tested | test_missing_cloudtrail_is_identified |
| 7 | CloudTrail collection | Logic tested; live pending | test_cloudtrail_collector_paginates_filters_writes_and_dedups_regions |
| 8 | GCP Audit Log collection | Normaliser tested; collector call not exercised | test_gcp_normalisation |
| 9 | Azure Activity Log collection | Normaliser tested; collector call not exercised | test_azure_normalisation_skips_in_flight_records |
| 10 | Findings from verified events | Logic tested | test_collects_detects_and_is_idempotent, test_high_risk_rules |
| 11 | Review statuses maintained | Tested | test_duplicate_finding_counts_occurrences_and_keeps_review |
| 12 | AWS billing account-wise | Logic tested; live pending | test_aws_cost_explorer_pagination_and_provisional_flag |
| 13 | GCP billing project-wise | Configuration check tested; query not executed | test_gcp_collector_requires_valid_export_table |
| 14-15 | Azure billing subscription-wise, own billing periods | Logic tested; live pending | test_azure_uses_each_subscriptions_own_billing_period |
| 16 | VM inventory across scopes | Logic tested; live pending | AWS, GCP, Azure VM collector tests |
| 17-18 | CPU/memory/disk where available; missing metrics reported | Tested | test_missing_metrics_are_never_healthy |
| 19 | Sheets without duplicates | Tested on in-memory backend; Google API calls not exercised | test_register_creates_17_tabs_without_duplicates_and_keeps_reviewer_columns |
| 20 | Dashboard figures match database | Tested | test_overview_figures_match_database |
| 21 | Gmail notifications | Dispatcher tested; Gmail API not exercised | test_notifications_marked_sent_only_after_delivery |
| 22 | Google Chat notifications | Dispatcher tested; webhook not exercised | same |
| 23 | Failed jobs reported | Tested | job engine tests, test_daily_report_states_partial_and_names_the_failing_scope |
| 24 | Historical records maintained | Tested | append-only ORM and trigger tests |
| 25 | No unauthorised infrastructure changes | Tested statically | test_connectors_make_only_read_only_cloud_calls |

## Test output (MySQL run)

```
tests/integration/test_api.py::test_health_and_readiness PASSED
tests/integration/test_api.py::test_empty_database_reports_not_collected_not_healthy PASSED
tests/integration/test_api.py::test_overview_figures_match_database PASSED
tests/integration/test_api.py::test_inventory_filters_and_onboarding_summary PASSED
tests/integration/test_api.py::test_task_decision_is_recorded_and_audited PASSED
tests/integration/test_api.py::test_manual_run_with_no_providers_is_reported_failed PASSED
tests/integration/test_api.py::test_history_is_append_only PASSED
tests/integration/test_api.py::test_database_trigger_blocks_raw_sql_tampering PASSED
tests/integration/test_discovery_workflow.py::test_discovers_all_scopes_across_three_clouds PASSED
tests/integration/test_discovery_workflow.py::test_rerun_is_idempotent PASSED
tests/integration/test_discovery_workflow.py::test_new_scope_detected_without_code_change PASSED
tests/integration/test_discovery_workflow.py::test_access_failure_is_reported_with_exact_scope_and_creates_task PASSED
tests/integration/test_discovery_workflow.py::test_task_resolves_when_check_passes_and_is_not_duplicated PASSED
tests/integration/test_discovery_workflow.py::test_rejected_task_is_not_reopened PASSED
tests/integration/test_discovery_workflow.py::test_missing_audit_logging_is_partial_onboarding PASSED
tests/integration/test_discovery_workflow.py::test_discovery_failure_does_not_touch_inventory_and_is_not_success PASSED
tests/integration/test_discovery_workflow.py::test_removed_and_suspended_scopes_become_inactive PASSED
tests/integration/test_discovery_workflow.py::test_unconfigured_or_absent_providers_fail_loudly PASSED
tests/integration/test_discovery_workflow.py::test_validation_exception_never_counts_as_onboarded PASSED
tests/integration/test_discovery_workflow.py::test_monitoring_disabled_scope_is_skipped PASSED
tests/integration/test_discovery_workflow.py::test_overlapping_execution_is_prevented PASSED
tests/integration/test_discovery_workflow.py::test_job_exception_is_recorded_and_lock_released PASSED
tests/integration/test_register_reports_ai.py::test_register_creates_17_tabs_without_duplicates_and_keeps_reviewer_columns PASSED
tests/integration/test_register_reports_ai.py::test_register_picks_up_new_scopes_and_updates_in_place PASSED
tests/integration/test_register_reports_ai.py::test_sheets_job_reports_tab_failures_and_disabled_state PASSED
tests/integration/test_register_reports_ai.py::test_notifications_marked_sent_only_after_delivery PASSED
tests/integration/test_register_reports_ai.py::test_delivery_gives_up_after_max_attempts PASSED
tests/integration/test_register_reports_ai.py::test_daily_report_states_partial_and_names_the_failing_scope PASSED
tests/integration/test_register_reports_ai.py::test_consolidated_report_job_queues_and_never_claims_delivery PASSED
tests/integration/test_register_reports_ai.py::test_ai_analysis_is_advisory_and_never_changes_review_status PASSED
tests/integration/test_register_reports_ai.py::test_prompt_injection_in_log_data_is_contained PASSED
tests/integration/test_register_reports_ai.py::test_bad_ai_output_is_rejected_and_detection_still_stands[not json] PASSED
tests/integration/test_register_reports_ai.py::test_bad_ai_output_is_rejected_and_detection_still_stands[{"summary": "x"}] PASSED
tests/integration/test_register_reports_ai.py::test_bad_ai_output_is_rejected_and_detection_still_stands[reply2] PASSED
tests/integration/test_register_reports_ai.py::test_bad_ai_output_is_rejected_and_detection_still_stands[["Closed"]] PASSED
tests/integration/test_register_reports_ai.py::test_bad_ai_output_is_rejected_and_detection_still_stands[reply4] PASSED
tests/integration/test_register_reports_ai.py::test_ai_unconfigured_does_not_block_rules PASSED
tests/integration/test_register_reports_ai.py::test_gemini_provider_request_shape_and_parsing PASSED
tests/integration/test_register_reports_ai.py::test_local_scheduler_fires_each_cron_slot_once_in_ist PASSED
tests/integration/test_soc_pipeline.py::test_collects_detects_and_is_idempotent PASSED
tests/integration/test_soc_pipeline.py::test_checkpoint_advances_and_first_run_uses_lookback PASSED
tests/integration/test_soc_pipeline.py::test_duplicate_finding_counts_occurrences_and_keeps_review PASSED
tests/integration/test_soc_pipeline.py::test_confirmed_suspicious_opens_incident_and_queues_alerts PASSED
tests/integration/test_soc_pipeline.py::test_new_critical_finding_requests_verification_not_confirmation PASSED
tests/integration/test_soc_pipeline.py::test_threshold_rules_and_untrusted_network PASSED
tests/integration/test_soc_pipeline.py::test_failing_and_unvalidated_scopes_are_reported_not_skipped PASSED
tests/integration/test_soc_pipeline.py::test_no_scopes_or_providers_is_failed PASSED
tests/integration/test_soc_pipeline.py::test_event_cap_keeps_checkpoint_at_last_event PASSED
tests/security/test_security.py::test_unauthenticated_requests_are_rejected PASSED
tests/security/test_security.py::test_forged_session_cookie_is_rejected PASSED
tests/security/test_security.py::test_viewer_cannot_approve_run_jobs_or_see_soc_and_finops PASSED
tests/security/test_security.py::test_deactivated_user_loses_access PASSED
tests/security/test_security.py::test_prerequisites_never_expose_secret_values PASSED
tests/security/test_security.py::test_pubsub_endpoint_requires_configuration_and_token PASSED
tests/security/test_security.py::test_security_headers PASSED
tests/security/test_security.py::test_connectors_make_only_read_only_cloud_calls PASSED
tests/security/test_security.py::test_no_hardcoded_cloud_ids_or_static_keys_in_source PASSED
tests/unit/test_aws_connector.py::test_discovery_paginates_and_reads_ou PASSED
tests/unit/test_aws_connector.py::test_validate_fully_onboarded_member PASSED
tests/unit/test_aws_connector.py::test_assume_role_denied_reports_access_failure_and_task PASSED
tests/unit/test_aws_connector.py::test_missing_cloudtrail_is_identified PASSED
tests/unit/test_aws_connector.py::test_trail_present_but_not_logging PASSED
tests/unit/test_aws_connector.py::test_missing_monitoring_permission_and_billing_denied PASSED
tests/unit/test_aws_connector.py::test_requires_role_name PASSED
tests/unit/test_core.py::test_derive_status[c0-True-True-Fully Onboarded] PASSED
tests/unit/test_core.py::test_derive_status[c1-True-True-Discovered] PASSED
tests/unit/test_core.py::test_derive_status[c2-False-True-Inactive] PASSED
tests/unit/test_core.py::test_derive_status[c3-True-False-Monitoring Disabled] PASSED
tests/unit/test_core.py::test_derive_status[c4-True-True-Access Failed] PASSED
tests/unit/test_core.py::test_derive_status[c5-True-True-Access Failed] PASSED
tests/unit/test_core.py::test_derive_status[c6-True-True-Pending Access] PASSED
tests/unit/test_core.py::test_derive_status[c7-True-True-Pending Access] PASSED
tests/unit/test_core.py::test_derive_status[c8-True-True-Partially Onboarded] PASSED
tests/unit/test_core.py::test_derive_status[c9-True-True-Partially Onboarded] PASSED
tests/unit/test_core.py::test_derive_status[c10-True-True-Pending Configuration] PASSED
tests/unit/test_core.py::test_derive_status[c11-True-True-Partially Onboarded] PASSED
tests/unit/test_core.py::test_unknown_is_never_fully_onboarded PASSED
tests/unit/test_core.py::test_redaction_removes_credentials PASSED
tests/unit/test_core.py::test_safe_error_is_bounded_and_redacted PASSED
tests/unit/test_core.py::test_production_rejects_dev_auth_and_weak_secret PASSED
tests/unit/test_core.py::test_csv_settings PASSED
tests/unit/test_core.py::test_no_cloud_scope_ids_in_default_settings PASSED
tests/unit/test_core.py::test_backoff_retries_throttling_then_succeeds PASSED
tests/unit/test_core.py::test_backoff_does_not_retry_permission_errors PASSED
tests/unit/test_finops.py::test_currency_conversion_stores_rate_and_never_guesses PASSED
tests/unit/test_finops.py::test_aws_cost_explorer_pagination_and_provisional_flag PASSED
tests/unit/test_finops.py::test_gcp_collector_requires_valid_export_table PASSED
tests/unit/test_finops.py::test_azure_uses_each_subscriptions_own_billing_period PASSED
tests/unit/test_finops.py::test_upsert_is_idempotent_and_final_is_not_overwritten PASSED
tests/unit/test_finops.py::test_month_finality PASSED
tests/unit/test_finops.py::test_budget_levels_forecast_and_anomaly PASSED
tests/unit/test_finops.py::test_weekly_and_daily_summaries PASSED
tests/unit/test_finops.py::test_billing_job_reports_unconfigured_and_failed_collectors PASSED
tests/unit/test_gcp_azure_connectors.py::test_gcp_discovery_walks_nested_folders PASSED
tests/unit/test_gcp_azure_connectors.py::test_gcp_validate_all_pass_and_records_billing_account PASSED
tests/unit/test_gcp_azure_connectors.py::test_gcp_missing_permission_api_billing_and_audit PASSED
tests/unit/test_gcp_azure_connectors.py::test_gcp_transient_error_is_unknown_not_pass PASSED
tests/unit/test_gcp_azure_connectors.py::test_gcp_fake_matches_real_sdk_surface PASSED
tests/unit/test_gcp_azure_connectors.py::test_azure_discovery_filters_tenant_and_state PASSED
tests/unit/test_gcp_azure_connectors.py::test_azure_validate_all_pass PASSED
tests/unit/test_gcp_azure_connectors.py::test_azure_missing_roles_and_denied_probes PASSED
tests/unit/test_gcp_azure_connectors.py::test_azure_roles_unverifiable_without_principal_id PASSED
tests/unit/test_gcp_azure_connectors.py::test_azure_fake_matches_real_sdk_surface PASSED
tests/unit/test_soc.py::test_cloudtrail_normalisation_and_denied_outcome PASSED
tests/unit/test_soc.py::test_console_login_failure_and_missing_mfa PASSED
tests/unit/test_soc.py::test_gcp_normalisation PASSED
tests/unit/test_soc.py::test_azure_normalisation_skips_in_flight_records PASSED
tests/unit/test_soc.py::test_high_risk_rules PASSED
tests/unit/test_soc.py::test_trusted_network_check PASSED
tests/unit/test_soc.py::test_cloudtrail_collector_paginates_filters_writes_and_dedups_regions PASSED
tests/unit/test_vm.py::test_missing_metrics_are_never_healthy PASSED
tests/unit/test_vm.py::test_thresholds_and_environment_overrides PASSED
tests/unit/test_vm.py::test_public_exposure_needs_public_ip_and_flags_sensitive_ports PASSED
tests/unit/test_vm.py::test_inventory_history_alert_lifecycle_and_deletion PASSED
tests/unit/test_vm.py::test_aws_vm_collector_reads_instances_groups_and_metrics PASSED
tests/unit/test_vm.py::test_gcp_vm_collector_firewall_exposure_and_metrics PASSED
tests/unit/test_vm.py::test_azure_vm_collector_power_state_nsg_and_metrics PASSED
tests/unit/test_vm.py::test_vm_job_reports_scope_failures PASSED
tests/unit/test_vm.py::test_sdk_surface_used_by_vm_collectors_exists PASSED
============================= 119 passed in 26.31s =============================
```
