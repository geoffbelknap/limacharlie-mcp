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
        "lc_preview_sensor_task",
        "lc_preview_isolate_sensor",
        "lc_preview_rejoin_sensor",
        "lc_preview_seal_sensor",
        "lc_preview_unseal_sensor",
        "lc_preview_delete_sensor",
        "lc_wait_job",
        "lc_preview_delete_job",
        "lc_list_audit_logs",
        "lc_list_yara_rules",
        "lc_list_fp_rules",
        "lc_list_schemas",
        "lc_list_online_sensors",
        "lc_get_org_urls",
        "lc_get_runtime_metadata",
        "lc_get_quota_usage",
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
        "lc_validate_search_query",
        "lc_estimate_search_query",
        "lc_execute_search_query",
        "lc_poll_search_query",
        "lc_cancel_search_query",
        "lc_validate_replay_rule",
        "lc_replay_scan_events",
        "lc_replay_dry_run",
        "lc_list_payloads",
        "lc_get_payload_download_url",
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
    task_schema = tools["lc_preview_sensor_task"]["inputSchema"]
    assert set(task_schema["required"]) == {"oid", "sensor_id", "tasks"}
    assert task_schema["properties"]["token_ttl_seconds"]["default"] == 300
    preview_tag_schema = tools["lc_preview_add_sensor_tag"]["inputSchema"]
    assert set(preview_tag_schema["required"]) == {"oid", "sensor_id", "tag"}
    assert preview_tag_schema["properties"]["ttl_seconds"]["default"] == 0
    assert preview_tag_schema["properties"]["token_ttl_seconds"]["default"] == 300
    runtime_schema = tools["lc_get_runtime_metadata"]["inputSchema"]
    assert set(runtime_schema["required"]) == {"oid"}
    assert runtime_schema["properties"]["limit"]["default"] == 100
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
    search_execute_schema = tools["lc_execute_search_query"]["inputSchema"]
    assert set(search_execute_schema["required"]) == {"oid", "query", "start", "end"}
    search_poll_schema = tools["lc_poll_search_query"]["inputSchema"]
    assert set(search_poll_schema["required"]) == {"oid", "query_id"}
    assert search_poll_schema["properties"]["limit"]["default"] == 100
    replay_schema = tools["lc_replay_dry_run"]["inputSchema"]
    assert set(replay_schema["required"]) == {"oid", "start", "end"}
    assert replay_schema["properties"]["limit_events"]["default"] == 1000
    billing_invoice_schema = tools["lc_get_billing_invoice_url"]["inputSchema"]
    assert set(billing_invoice_schema["required"]) == {"oid", "year", "month"}
    usp_schema = tools["lc_validate_usp_mapping"]["inputSchema"]
    assert set(usp_schema["required"]) == {"oid", "platform"}
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
