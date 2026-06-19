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
        "lc_wait_job",
        "lc_list_audit_logs",
        "lc_list_yara_rules",
        "lc_list_fp_rules",
        "lc_list_schemas",
        "lc_list_online_sensors",
        "lc_get_org_urls",
        "lc_get_runtime_metadata",
        "lc_get_quota_usage",
        "lc_get_billing_status",
        "lc_get_billing_details",
        "lc_get_billing_invoice_url",
        "lc_list_billing_plans",
        "lc_list_groups",
        "lc_get_group",
        "lc_list_group_logs",
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
        "lc_list_integrity_rules",
        "lc_get_integrity_rule",
        "lc_validate_usp_mapping",
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
    preview_tag_schema = tools["lc_preview_add_sensor_tag"]["inputSchema"]
    assert set(preview_tag_schema["required"]) == {"oid", "sensor_id", "tag"}
    assert preview_tag_schema["properties"]["ttl_seconds"]["default"] == 0
    assert preview_tag_schema["properties"]["token_ttl_seconds"]["default"] == 300
    runtime_schema = tools["lc_get_runtime_metadata"]["inputSchema"]
    assert set(runtime_schema["required"]) == {"oid"}
    assert runtime_schema["properties"]["limit"]["default"] == 100
    group_schema = tools["lc_get_group"]["inputSchema"]
    assert set(group_schema["required"]) == {"group_id"}
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
    confirm_schema = tools["lc_confirm_mutation"]["inputSchema"]
    assert set(confirm_schema["required"]) == {"confirmation_token"}
