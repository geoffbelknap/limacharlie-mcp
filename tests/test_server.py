from __future__ import annotations

import anyio

from limacharlie_mcp import server


OID = "263c19e9-bd4a-475a-8cd3-5403af446cb9"


def test_mcp_tools_return_ax_input_error_for_invalid_oid() -> None:
    result = server.lc_list_sensors("not-an-oid")

    assert result["ok"] is False
    assert result["operation"] == "sensor.list"
    assert result["error"]["class"] == "input"
    assert result["error"]["code"] == "invalid_input"
    assert result["error"]["same_input_retryable"] is False
    assert result["side_effects"] == []
    assert result["request_id"].startswith("req_")


def test_mcp_tools_return_ax_input_error_for_missing_time_window() -> None:
    result = server.lc_list_artifacts(OID)

    assert result["ok"] is False
    assert result["operation"] == "artifact.list"
    assert result["error"]["class"] == "input"
    assert "start and end" in result["error"]["message"]


def test_mcp_tool_schema_snapshot_for_representative_tools() -> None:
    async def collect_tools() -> dict:
        tools = await server.mcp.list_tools()
        return {tool.name: tool.model_dump() for tool in tools}

    tools = anyio.run(collect_tools)

    assert {
        "lc_auth_status",
        "lc_auth_refresh",
        "lc_list_sensor_events",
        "lc_get_sensor_isolation_status",
        "lc_get_sensor_seal_status",
        "lc_wait_sensor_online",
        "lc_preview_sensor_task",
        "lc_preview_isolate_sensor",
        "lc_preview_rejoin_sensor",
        "lc_preview_seal_sensor",
        "lc_preview_unseal_sensor",
        "lc_preview_delete_sensor",
        "lc_wait_job",
        "lc_preview_delete_job",
        "lc_list_reliable_tasks",
        "lc_preview_reliable_task",
        "lc_preview_delete_reliable_task",
        "lc_list_audit_logs",
        "lc_list_yara_rules",
        "lc_list_fp_rules",
        "lc_list_schemas",
        "lc_list_online_sensors",
        "lc_get_org_urls",
        "lc_get_runtime_metadata",
        "lc_get_quota_usage",
        "lc_check_org_name",
        "lc_preview_create_org",
        "lc_get_org_config_value",
        "lc_preview_set_org_config_value",
        "lc_preview_dismiss_org_error",
        "lc_get_org_delete_confirmation",
        "lc_preview_delete_org",
        "lc_preview_set_org_quota",
        "lc_preview_rename_org",
        "lc_get_billing_status",
        "lc_get_billing_details",
        "lc_get_billing_invoice_url",
        "lc_list_billing_plans",
        "lc_list_groups",
        "lc_preview_create_group",
        "lc_get_group",
        "lc_preview_delete_group",
        "lc_list_group_logs",
        "lc_preview_add_group_member",
        "lc_preview_remove_group_member",
        "lc_preview_add_group_owner",
        "lc_preview_remove_group_owner",
        "lc_preview_set_group_permissions",
        "lc_preview_add_group_org",
        "lc_preview_remove_group_org",
        "lc_preview_invite_user",
        "lc_preview_remove_user",
        "lc_preview_add_user_permission",
        "lc_preview_remove_user_permission",
        "lc_preview_set_user_role",
        "lc_preview_create_api_key",
        "lc_preview_delete_api_key",
        "lc_preview_create_installation_key",
        "lc_preview_delete_installation_key",
        "lc_preview_create_ingestion_key",
        "lc_preview_delete_ingestion_key",
        "lc_preview_create_output",
        "lc_preview_delete_output",
        "lc_preview_subscribe_extension",
        "lc_preview_unsubscribe_extension",
        "lc_preview_rekey_extension",
        "lc_preview_create_extension",
        "lc_preview_update_extension",
        "lc_preview_delete_extension",
        "lc_preview_extension_request",
        "lc_list_sensor_download_targets",
        "lc_list_adapter_download_targets",
        "lc_batch_search_iocs",
        "lc_get_object_information",
        "lc_get_insight_status",
        "lc_list_vulnerability_cves",
        "lc_get_vulnerability_cve",
        "lc_list_vulnerability_cve_hosts",
        "lc_list_vulnerability_cve_packages",
        "lc_list_vulnerability_endpoints",
        "lc_list_vulnerability_host_packages",
        "lc_get_vulnerability_dashboard",
        "lc_list_vulnerability_resolutions",
        "lc_list_vulnerability_snapshots",
        "lc_get_vulnerability_epss_history",
        "lc_preview_create_case",
        "lc_preview_update_case",
        "lc_preview_add_case_note",
        "lc_preview_update_case_note_visibility",
        "lc_preview_bulk_update_cases",
        "lc_preview_merge_cases",
        "lc_list_case_detections",
        "lc_preview_add_case_detection",
        "lc_preview_remove_case_detection",
        "lc_list_case_entities",
        "lc_search_case_entities",
        "lc_preview_add_case_entity",
        "lc_preview_update_case_entity",
        "lc_preview_remove_case_entity",
        "lc_list_case_telemetry",
        "lc_preview_add_case_telemetry",
        "lc_preview_update_case_telemetry",
        "lc_preview_remove_case_telemetry",
        "lc_list_case_artifacts",
        "lc_preview_add_case_artifact",
        "lc_preview_remove_case_artifact",
        "lc_export_case",
        "lc_get_cases_report_summary",
        "lc_get_cases_dashboard_counts",
        "lc_get_cases_config",
        "lc_preview_set_cases_config",
        "lc_list_case_assignees",
        "lc_list_case_orgs",
        "lc_preview_set_case_tags",
        "lc_preview_add_case_tags",
        "lc_preview_remove_case_tags",
        "lc_export_sensors",
        "lc_preview_set_sensor_version",
        "lc_list_available_services",
        "lc_preview_service_request",
        "lc_fetch_config",
        "lc_preview_push_config",
        "lc_list_exfil_rules",
        "lc_preview_create_exfil_watch",
        "lc_preview_create_exfil_event",
        "lc_preview_delete_exfil_event",
        "lc_preview_delete_exfil_watch",
        "lc_list_feedback_channels",
        "lc_preview_set_feedback_channels",
        "lc_preview_feedback_simple_approval",
        "lc_preview_feedback_acknowledgement",
        "lc_preview_feedback_question",
        "lc_validate_search_query",
        "lc_estimate_search_query",
        "lc_execute_search_query",
        "lc_poll_search_query",
        "lc_cancel_search_query",
        "lc_list_saved_queries",
        "lc_get_saved_query",
        "lc_preview_set_saved_query",
        "lc_preview_delete_saved_query",
        "lc_execute_saved_query",
        "lc_validate_replay_rule",
        "lc_replay_scan_events",
        "lc_replay_dry_run",
        "lc_list_payloads",
        "lc_get_payload_download_url",
        "lc_preview_payload_upload_url",
        "lc_preview_delete_payload",
        "lc_get_arl",
        "lc_preview_set_artifact_rule",
        "lc_preview_delete_artifact_rule",
        "lc_preview_set_logging_rule",
        "lc_preview_delete_logging_rule",
        "lc_preview_set_dr_rule",
        "lc_preview_delete_dr_rule",
        "lc_preview_set_fp_rule",
        "lc_preview_delete_fp_rule",
        "lc_list_integrity_rules",
        "lc_get_integrity_rule",
        "lc_preview_set_integrity_rule",
        "lc_preview_delete_integrity_rule",
        "lc_validate_usp_mapping",
        "lc_list_hive_types",
        "lc_list_hive_records",
        "lc_get_hive_record",
        "lc_get_hive_record_metadata",
        "lc_get_hive_schema",
        "lc_validate_hive_record",
        "lc_preview_set_hive_record",
        "lc_preview_delete_hive_record",
        "lc_preview_rename_hive_record",
        "lc_preview_set_hive_record_enabled",
        "lc_list_secrets",
        "lc_get_secret",
        "lc_preview_set_secret",
        "lc_preview_delete_secret",
        "lc_preview_set_secret_enabled",
        "lc_list_lookups",
        "lc_get_lookup",
        "lc_preview_set_lookup",
        "lc_preview_delete_lookup",
        "lc_preview_set_lookup_enabled",
        "lc_list_cloud_adapters",
        "lc_get_cloud_adapter",
        "lc_preview_set_cloud_adapter",
        "lc_preview_delete_cloud_adapter",
        "lc_preview_set_cloud_adapter_enabled",
        "lc_list_external_adapters",
        "lc_get_external_adapter",
        "lc_preview_set_external_adapter",
        "lc_preview_delete_external_adapter",
        "lc_preview_set_external_adapter_enabled",
        "lc_list_playbooks",
        "lc_get_playbook",
        "lc_preview_set_playbook",
        "lc_preview_delete_playbook",
        "lc_preview_set_playbook_enabled",
        "lc_list_sops",
        "lc_get_sop",
        "lc_preview_set_sop",
        "lc_preview_delete_sop",
        "lc_preview_set_sop_enabled",
        "lc_list_org_notes",
        "lc_get_org_note",
        "lc_preview_set_org_note",
        "lc_preview_delete_org_note",
        "lc_preview_set_org_note_enabled",
        "lc_list_ai_agents",
        "lc_get_ai_agent",
        "lc_preview_set_ai_agent",
        "lc_preview_delete_ai_agent",
        "lc_preview_set_ai_agent_enabled",
        "lc_list_ai_skills",
        "lc_get_ai_skill",
        "lc_preview_set_ai_skill",
        "lc_preview_delete_ai_skill",
        "lc_preview_set_ai_skill_enabled",
        "lc_list_ai_memory_records",
        "lc_get_ai_memory_record",
        "lc_list_ai_memories",
        "lc_get_ai_memory",
        "lc_preview_set_ai_memory",
        "lc_preview_delete_ai_memory",
        "lc_preview_delete_ai_memory_record",
        "lc_list_ai_sessions",
        "lc_get_ai_session",
        "lc_get_ai_session_history",
        "lc_preview_terminate_ai_session",
        "lc_list_ai_usage_identities",
        "lc_get_ai_usage",
        "lc_preview_yara_scan",
        "lc_preview_set_yara_rule",
        "lc_preview_delete_yara_rule",
        "lc_preview_set_yara_source",
        "lc_preview_delete_yara_source",
        "lc_list_pending_mutations",
        "lc_preview_add_sensor_tag",
        "lc_preview_remove_sensor_tag",
        "lc_confirm_mutation",
        "lc_cancel_mutation",
    } <= set(tools)
    event_schema = tools["lc_list_sensor_events"]["inputSchema"]
    assert set(event_schema["required"]) == {"oid", "sensor_id", "start", "end"}
    assert event_schema["properties"]["limit"]["default"] == 100
    assert event_schema["properties"]["cursor"]["default"] == "-"
    wait_schema = tools["lc_wait_job"]["inputSchema"]
    assert set(wait_schema["required"]) == {"oid", "job_id"}
    assert wait_schema["properties"]["timeout_seconds"]["default"] == 60
    assert wait_schema["properties"]["poll_interval_seconds"]["default"] == 5
    wait_sensor_schema = tools["lc_wait_sensor_online"]["inputSchema"]
    assert set(wait_sensor_schema["required"]) == {"oid", "sensor_id"}
    assert wait_sensor_schema["properties"]["timeout_seconds"]["default"] == 300
    assert wait_sensor_schema["properties"]["poll_interval_seconds"]["default"] == 5
    isolation_status_schema = tools["lc_get_sensor_isolation_status"]["inputSchema"]
    assert set(isolation_status_schema["required"]) == {"oid", "sensor_id"}
    seal_status_schema = tools["lc_get_sensor_seal_status"]["inputSchema"]
    assert set(seal_status_schema["required"]) == {"oid", "sensor_id"}
    task_schema = tools["lc_preview_sensor_task"]["inputSchema"]
    assert set(task_schema["required"]) == {"oid", "sensor_id", "tasks"}
    assert task_schema["properties"]["token_ttl_seconds"]["default"] == 300
    reliable_list_schema = tools["lc_list_reliable_tasks"]["inputSchema"]
    assert set(reliable_list_schema["required"]) == {"oid"}
    reliable_task_schema = tools["lc_preview_reliable_task"]["inputSchema"]
    assert set(reliable_task_schema["required"]) == {"oid", "task"}
    assert reliable_task_schema["properties"]["sensor_id"]["default"] is None
    assert reliable_task_schema["properties"]["selector"]["default"] is None
    assert reliable_task_schema["properties"]["context"]["default"] is None
    assert reliable_task_schema["properties"]["token_ttl_seconds"]["default"] == 300
    reliable_delete_schema = tools["lc_preview_delete_reliable_task"]["inputSchema"]
    assert set(reliable_delete_schema["required"]) == {"oid", "task_id"}
    assert reliable_delete_schema["properties"]["sensor_id"]["default"] is None
    assert reliable_delete_schema["properties"]["selector"]["default"] is None
    preview_tag_schema = tools["lc_preview_add_sensor_tag"]["inputSchema"]
    assert set(preview_tag_schema["required"]) == {"oid", "sensor_id", "tag"}
    assert preview_tag_schema["properties"]["ttl_seconds"]["default"] == 0
    assert preview_tag_schema["properties"]["token_ttl_seconds"]["default"] == 300
    runtime_schema = tools["lc_get_runtime_metadata"]["inputSchema"]
    assert set(runtime_schema["required"]) == {"oid"}
    assert runtime_schema["properties"]["limit"]["default"] == 100
    org_name_schema = tools["lc_check_org_name"]["inputSchema"]
    assert set(org_name_schema["required"]) == {"name"}
    org_config_schema = tools["lc_preview_set_org_config_value"]["inputSchema"]
    assert set(org_config_schema["required"]) == {"oid", "config_name", "value"}
    org_delete_schema = tools["lc_preview_delete_org"]["inputSchema"]
    assert set(org_delete_schema["required"]) == {"oid", "confirmation"}
    group_schema = tools["lc_get_group"]["inputSchema"]
    assert set(group_schema["required"]) == {"group_id"}
    create_group_schema = tools["lc_preview_create_group"]["inputSchema"]
    assert set(create_group_schema["required"]) == {"name"}
    group_member_schema = tools["lc_preview_add_group_member"]["inputSchema"]
    assert set(group_member_schema["required"]) == {"group_id", "email"}
    invite_schema = tools["lc_preview_invite_user"]["inputSchema"]
    assert set(invite_schema["required"]) == {"oid", "email"}
    role_schema = tools["lc_preview_set_user_role"]["inputSchema"]
    assert set(role_schema["required"]) == {"oid", "email", "role"}
    api_key_schema = tools["lc_preview_create_api_key"]["inputSchema"]
    assert set(api_key_schema["required"]) == {"oid", "name", "permissions"}
    output_schema = tools["lc_preview_create_output"]["inputSchema"]
    assert set(output_schema["required"]) == {"oid", "name", "module", "data_type"}
    extension_request_schema = tools["lc_preview_extension_request"]["inputSchema"]
    assert set(extension_request_schema["required"]) == {"oid", "extension_name", "action"}
    vuln_cves_schema = tools["lc_list_vulnerability_cves"]["inputSchema"]
    assert set(vuln_cves_schema["required"]) == {"oid"}
    assert vuln_cves_schema["properties"]["limit"]["default"] == 100
    vuln_cve_schema = tools["lc_get_vulnerability_cve"]["inputSchema"]
    assert set(vuln_cve_schema["required"]) == {"oid", "cve"}
    vuln_host_schema = tools["lc_list_vulnerability_host_packages"]["inputSchema"]
    assert set(vuln_host_schema["required"]) == {"oid", "sensor_id"}
    assert vuln_host_schema["properties"]["rollup_subpackages"]["default"] is None
    case_list_schema = tools["lc_list_cases"]["inputSchema"]
    assert set(case_list_schema["required"]) == {"oid"}
    assert case_list_schema["properties"]["limit"]["default"] == 100
    case_update_schema = tools["lc_preview_update_case"]["inputSchema"]
    assert set(case_update_schema["required"]) == {"oid", "case_number"}
    case_note_schema = tools["lc_preview_add_case_note"]["inputSchema"]
    assert set(case_note_schema["required"]) == {"oid", "case_number", "content"}
    case_bulk_schema = tools["lc_preview_bulk_update_cases"]["inputSchema"]
    assert set(case_bulk_schema["required"]) == {"oid", "case_numbers"}
    case_entity_schema = tools["lc_preview_add_case_entity"]["inputSchema"]
    assert set(case_entity_schema["required"]) == {"oid", "case_number", "entity_type", "entity_value"}
    case_artifact_schema = tools["lc_preview_add_case_artifact"]["inputSchema"]
    assert set(case_artifact_schema["required"]) == {"oid", "case_number", "path", "source"}
    cases_config_schema = tools["lc_preview_set_cases_config"]["inputSchema"]
    assert set(cases_config_schema["required"]) == {"oid", "config"}
    case_tag_schema = tools["lc_preview_set_case_tags"]["inputSchema"]
    assert set(case_tag_schema["required"]) == {"oid", "case_number", "tags"}
    service_schema = tools["lc_preview_service_request"]["inputSchema"]
    assert set(service_schema["required"]) == {"oid", "service_name", "request_data"}
    push_config_schema = tools["lc_preview_push_config"]["inputSchema"]
    assert set(push_config_schema["required"]) == {"oid", "config"}
    exfil_watch_schema = tools["lc_preview_create_exfil_watch"]["inputSchema"]
    assert set(exfil_watch_schema["required"]) == {"oid", "name", "event", "value", "operator", "path"}
    exfil_event_schema = tools["lc_preview_create_exfil_event"]["inputSchema"]
    assert set(exfil_event_schema["required"]) == {"oid", "name", "events"}
    feedback_channels_schema = tools["lc_preview_set_feedback_channels"]["inputSchema"]
    assert set(feedback_channels_schema["required"]) == {"oid", "channels"}
    feedback_approval_schema = tools["lc_preview_feedback_simple_approval"]["inputSchema"]
    assert set(feedback_approval_schema["required"]) == {"oid", "channel", "question", "feedback_destination"}
    search_execute_schema = tools["lc_execute_search_query"]["inputSchema"]
    assert set(search_execute_schema["required"]) == {"oid", "query", "start", "end"}
    search_poll_schema = tools["lc_poll_search_query"]["inputSchema"]
    assert set(search_poll_schema["required"]) == {"oid", "query_id"}
    assert search_poll_schema["properties"]["limit"]["default"] == 100
    saved_query_set_schema = tools["lc_preview_set_saved_query"]["inputSchema"]
    assert set(saved_query_set_schema["required"]) == {"oid", "name", "query"}
    saved_query_delete_schema = tools["lc_preview_delete_saved_query"]["inputSchema"]
    assert set(saved_query_delete_schema["required"]) == {"oid", "name"}
    saved_query_execute_schema = tools["lc_execute_saved_query"]["inputSchema"]
    assert set(saved_query_execute_schema["required"]) == {"oid", "name"}
    replay_schema = tools["lc_replay_dry_run"]["inputSchema"]
    assert set(replay_schema["required"]) == {"oid", "start", "end"}
    assert replay_schema["properties"]["limit_events"]["default"] == 1000
    billing_invoice_schema = tools["lc_get_billing_invoice_url"]["inputSchema"]
    assert set(billing_invoice_schema["required"]) == {"oid", "year", "month"}
    usp_schema = tools["lc_validate_usp_mapping"]["inputSchema"]
    assert set(usp_schema["required"]) == {"oid", "platform"}
    payload_upload_schema = tools["lc_preview_payload_upload_url"]["inputSchema"]
    assert set(payload_upload_schema["required"]) == {"oid", "name"}
    hive_get_schema = tools["lc_get_hive_record"]["inputSchema"]
    assert set(hive_get_schema["required"]) == {"oid", "hive_name", "key"}
    hive_validate_schema = tools["lc_validate_hive_record"]["inputSchema"]
    assert set(hive_validate_schema["required"]) == {"oid", "hive_name", "key", "data"}
    hive_rename_schema = tools["lc_preview_rename_hive_record"]["inputSchema"]
    assert set(hive_rename_schema["required"]) == {"oid", "hive_name", "key", "new_name"}
    hive_enabled_schema = tools["lc_preview_set_hive_record_enabled"]["inputSchema"]
    assert set(hive_enabled_schema["required"]) == {"oid", "hive_name", "key", "enabled"}
    secret_get_schema = tools["lc_get_secret"]["inputSchema"]
    assert set(secret_get_schema["required"]) == {"oid", "name"}
    secret_set_schema = tools["lc_preview_set_secret"]["inputSchema"]
    assert set(secret_set_schema["required"]) == {"oid", "name", "secret_value"}
    secret_enabled_schema = tools["lc_preview_set_secret_enabled"]["inputSchema"]
    assert set(secret_enabled_schema["required"]) == {"oid", "name", "enabled"}
    lookup_get_schema = tools["lc_get_lookup"]["inputSchema"]
    assert set(lookup_get_schema["required"]) == {"oid", "name"}
    lookup_set_schema = tools["lc_preview_set_lookup"]["inputSchema"]
    assert set(lookup_set_schema["required"]) == {"oid", "name"}
    lookup_enabled_schema = tools["lc_preview_set_lookup_enabled"]["inputSchema"]
    assert set(lookup_enabled_schema["required"]) == {"oid", "name", "enabled"}
    cloud_adapter_set_schema = tools["lc_preview_set_cloud_adapter"]["inputSchema"]
    assert set(cloud_adapter_set_schema["required"]) == {"oid", "name", "data"}
    playbook_set_schema = tools["lc_preview_set_playbook"]["inputSchema"]
    assert set(playbook_set_schema["required"]) == {"oid", "name", "data"}
    sop_get_schema = tools["lc_get_sop"]["inputSchema"]
    assert set(sop_get_schema["required"]) == {"oid", "name"}
    org_note_enabled_schema = tools["lc_preview_set_org_note_enabled"]["inputSchema"]
    assert set(org_note_enabled_schema["required"]) == {"oid", "name", "enabled"}
    ai_agent_set_schema = tools["lc_preview_set_ai_agent"]["inputSchema"]
    assert set(ai_agent_set_schema["required"]) == {"oid", "name", "data"}
    ai_skill_delete_schema = tools["lc_preview_delete_ai_skill"]["inputSchema"]
    assert set(ai_skill_delete_schema["required"]) == {"oid", "name"}
    ai_memory_set_schema = tools["lc_preview_set_ai_memory"]["inputSchema"]
    assert set(ai_memory_set_schema["required"]) == {"oid", "agent", "memory_name", "content"}
    ai_memory_get_schema = tools["lc_get_ai_memory"]["inputSchema"]
    assert set(ai_memory_get_schema["required"]) == {"oid", "agent", "memory_name"}
    ai_session_get_schema = tools["lc_get_ai_session"]["inputSchema"]
    assert set(ai_session_get_schema["required"]) == {"oid", "session_id"}
    ai_session_terminate_schema = tools["lc_preview_terminate_ai_session"]["inputSchema"]
    assert set(ai_session_terminate_schema["required"]) == {"oid", "session_id"}
    ai_usage_schema = tools["lc_get_ai_usage"]["inputSchema"]
    assert set(ai_usage_schema["required"]) == {"oid", "identity"}
    artifact_set_schema = tools["lc_preview_set_artifact_rule"]["inputSchema"]
    assert set(artifact_set_schema["required"]) == {"oid", "name", "platforms", "patterns"}
    assert artifact_set_schema["properties"]["retention_days"]["default"] == 30
    dr_set_schema = tools["lc_preview_set_dr_rule"]["inputSchema"]
    assert set(dr_set_schema["required"]) == {"oid", "name", "data"}
    assert dr_set_schema["properties"]["token_ttl_seconds"]["default"] == 300
    yara_scan_schema = tools["lc_preview_yara_scan"]["inputSchema"]
    assert set(yara_scan_schema["required"]) == {"oid", "sensor_id", "rule"}
    yara_source_schema = tools["lc_preview_set_yara_source"]["inputSchema"]
    assert set(yara_source_schema["required"]) == {"oid", "name", "source"}
    confirm_schema = tools["lc_confirm_mutation"]["inputSchema"]
    assert set(confirm_schema["required"]) == {"confirmation_token"}
