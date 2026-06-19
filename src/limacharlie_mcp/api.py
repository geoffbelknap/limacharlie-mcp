from __future__ import annotations

import base64
import gzip
import json
import os
import re
import time
import uuid
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

import httpx


class HttpClient(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json: Any | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        ...


@dataclass(frozen=True)
class ToolResponse:
    ok: bool
    operation: str
    data: Any
    meta: dict[str, Any]
    request_id: str
    resource: dict[str, Any] | None = None
    state: dict[str, Any] | None = None
    side_effects: list[dict[str, Any]] | None = None
    warnings: list[str] | None = None
    observed_at: str | None = None
    error: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ok": self.ok,
            "operation": self.operation,
            "request_id": self.request_id,
            "resource": self.resource,
            "state": self.state or {},
            "data": self.data,
            "side_effects": self.side_effects or [],
            "warnings": self.warnings or [],
            "meta": self.meta,
            "observed_at": self.observed_at,
        }
        if self.error:
            result["error"] = self.error
        return result


@dataclass
class Token:
    value: str
    expires_at: float


@dataclass
class PendingMutation:
    token: str
    expires_at: float
    operation: str
    oid: str
    method: str
    path: str
    resource: dict[str, Any]
    base_url: str | None
    params: dict[str, Any] | None
    data: dict[str, Any] | None
    json_body: Any | None
    expected_effect: str
    reversibility: str
    side_effects: list[dict[str, Any]]


class ValidationError(ValueError):
    """Invalid MCP tool input."""


def input_error_response(operation: str, message: str) -> dict[str, Any]:
    return ToolResponse(
        ok=False,
        operation=operation,
        request_id=f"req_{uuid.uuid4().hex}",
        resource=None,
        state={},
        data=None,
        side_effects=[],
        warnings=[],
        meta={"summary": {"shape": "empty"}, "truncated": False},
        observed_at=observed_at(),
        error={
            "code": "invalid_input",
            "class": "input",
            "message": message,
            "retryable": False,
            "same_input_retryable": False,
            "suggested_next_actions": [
                "Call lc_tool_catalog to inspect required inputs and bounds.",
                "Retry with corrected input values.",
            ],
        },
    ).as_dict()


OPERATION_CATALOG: dict[str, dict[str, Any]] = {
    "auth.whoami": {
        "suite": "platform",
        "tool": "lc_auth_whoami",
        "action": "read",
        "resource_type": "identity",
        "required_inputs": [],
        "optional_inputs": ["oid", "check_perm"],
        "side_effects": "none",
        "notes": "Use with oid plus check_perm to test a permission in a concrete org context.",
    },
    "auth.status": {
        "suite": "platform",
        "tool": "lc_auth_status",
        "action": "read",
        "resource_type": "auth_session",
        "required_inputs": [],
        "optional_inputs": ["oid"],
        "side_effects": "none",
        "notes": "Shows credential mode and cached JWT freshness without exposing secrets.",
    },
    "auth.refresh": {
        "suite": "platform",
        "tool": "lc_auth_refresh",
        "action": "execute",
        "resource_type": "auth_session",
        "required_inputs": [],
        "optional_inputs": ["oid"],
        "side_effects": "local_jwt_cache_refresh",
        "notes": "Forces a new short-lived LimaCharlie JWT. Users should not paste JWTs manually.",
    },
    "org.list": {
        "suite": "administration",
        "tool": "lc_list_orgs",
        "action": "read",
        "resource_type": "organization_collection",
        "required_inputs": [],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Uses LimaCharlie's minimal JWT org placeholder for discovery.",
    },
    "download.sensor_targets.list": {
        "suite": "platform",
        "tool": "lc_list_sensor_download_targets",
        "action": "read",
        "resource_type": "download_target_collection",
        "required_inputs": [],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Lists supported sensor installer target URLs without downloading binaries.",
    },
    "download.adapter_targets.list": {
        "suite": "platform",
        "tool": "lc_list_adapter_download_targets",
        "action": "read",
        "resource_type": "download_target_collection",
        "required_inputs": [],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Lists supported adapter binary target URLs without downloading binaries.",
    },
    "sensor.list": {
        "suite": "investigation",
        "tool": "lc_list_sensors",
        "action": "read",
        "resource_type": "sensor_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["selector", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Use before choosing a sensor for an investigation or response workflow.",
    },
    "sensor.get": {
        "suite": "investigation",
        "tool": "lc_get_sensor",
        "action": "read",
        "resource_type": "sensor",
        "required_inputs": ["oid", "sensor_id"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Use to verify hostname, platform, IPs, and online state for one sensor.",
    },
    "sensor.task.preview": {
        "suite": "response",
        "tool": "lc_preview_sensor_task",
        "action": "preview",
        "resource_type": "sensor_task",
        "required_inputs": ["oid", "sensor_id", "tasks"],
        "optional_inputs": ["investigation_id", "token_ttl_seconds"],
        "bounds": {"tasks_max": 20, "token_ttl_min": 30, "token_ttl_max": 900},
        "side_effects": "none_until_confirmed",
        "notes": "Previews tasking one sensor. Requires lc_confirm_mutation before remote execution.",
    },
    "sensor.isolate.preview": {
        "suite": "response",
        "tool": "lc_preview_isolate_sensor",
        "action": "preview",
        "resource_type": "sensor_isolation",
        "required_inputs": ["oid", "sensor_id"],
        "optional_inputs": ["token_ttl_seconds"],
        "bounds": {"token_ttl_min": 30, "token_ttl_max": 900},
        "side_effects": "none_until_confirmed",
        "notes": "Previews network isolation for one sensor.",
    },
    "sensor.rejoin.preview": {
        "suite": "response",
        "tool": "lc_preview_rejoin_sensor",
        "action": "preview",
        "resource_type": "sensor_isolation",
        "required_inputs": ["oid", "sensor_id"],
        "optional_inputs": ["token_ttl_seconds"],
        "bounds": {"token_ttl_min": 30, "token_ttl_max": 900},
        "side_effects": "none_until_confirmed",
        "notes": "Previews removing network isolation from one sensor.",
    },
    "sensor.seal.preview": {
        "suite": "response",
        "tool": "lc_preview_seal_sensor",
        "action": "preview",
        "resource_type": "sensor_seal",
        "required_inputs": ["oid", "sensor_id"],
        "optional_inputs": ["token_ttl_seconds"],
        "bounds": {"token_ttl_min": 30, "token_ttl_max": 900},
        "side_effects": "none_until_confirmed",
        "notes": "Previews sealing one sensor against uninstall.",
    },
    "sensor.unseal.preview": {
        "suite": "response",
        "tool": "lc_preview_unseal_sensor",
        "action": "preview",
        "resource_type": "sensor_seal",
        "required_inputs": ["oid", "sensor_id"],
        "optional_inputs": ["token_ttl_seconds"],
        "bounds": {"token_ttl_min": 30, "token_ttl_max": 900},
        "side_effects": "none_until_confirmed",
        "notes": "Previews unsealing one sensor.",
    },
    "sensor.delete.preview": {
        "suite": "response",
        "tool": "lc_preview_delete_sensor",
        "action": "preview",
        "resource_type": "sensor",
        "required_inputs": ["oid", "sensor_id"],
        "optional_inputs": ["token_ttl_seconds"],
        "bounds": {"token_ttl_min": 30, "token_ttl_max": 900},
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting one sensor record.",
    },
    "sensor.online.list": {
        "suite": "investigation",
        "tool": "lc_list_online_sensors",
        "action": "read",
        "resource_type": "online_sensor_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Returns currently online sensors/counts from GET /v1/online/{oid}.",
    },
    "detection.list": {
        "suite": "investigation",
        "tool": "lc_list_detections",
        "action": "read",
        "resource_type": "detection_collection",
        "required_inputs": ["oid", "start", "end"],
        "optional_inputs": ["limit", "cursor", "category"],
        "bounds": {"limit_min": 1, "limit_max": 500, "time_format": "unix_seconds"},
        "side_effects": "none",
        "notes": "Returns one bounded page. Use next_cursor for additional pages.",
    },
    "detection.get": {
        "suite": "investigation",
        "tool": "lc_get_detection",
        "action": "read",
        "resource_type": "detection",
        "required_inputs": ["oid", "detect_id"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Use after listing detections or receiving a detection ID from another system.",
    },
    "case.list": {
        "suite": "investigation",
        "tool": "lc_list_cases",
        "action": "read",
        "resource_type": "case_collection",
        "required_inputs": ["oid"],
        "optional_inputs": [
            "status",
            "severity",
            "classification",
            "assignee",
            "search",
            "sensor_id",
            "tags",
            "sort",
            "order",
            "limit",
            "page_token",
        ],
        "bounds": {"limit_min": 1, "limit_max": 200, "order": ["asc", "desc"]},
        "side_effects": "none",
        "notes": "Lists one Cases API page with optional filters. Use page_token for pagination.",
    },
    "case.get": {
        "suite": "investigation",
        "tool": "lc_get_case",
        "action": "read",
        "resource_type": "case",
        "required_inputs": ["oid", "case_number"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Use for a specific numeric case number.",
    },
    "event.list": {
        "suite": "investigation",
        "tool": "lc_list_sensor_events",
        "action": "read",
        "resource_type": "event_collection",
        "required_inputs": ["oid", "sensor_id", "start", "end"],
        "optional_inputs": ["event_type", "limit", "cursor", "is_forward"],
        "bounds": {"limit_min": 1, "limit_max": 500, "time_format": "unix_seconds"},
        "side_effects": "none",
        "notes": "Returns one bounded page for one sensor; follow next_cursor explicitly.",
    },
    "event.overview": {
        "suite": "investigation",
        "tool": "lc_get_sensor_event_overview",
        "action": "read",
        "resource_type": "event_overview",
        "required_inputs": ["oid", "sensor_id", "start", "end"],
        "optional_inputs": [],
        "bounds": {"time_format": "unix_seconds"},
        "side_effects": "none",
        "notes": "Use before pulling full events to identify useful time ranges.",
    },
    "event.get": {
        "suite": "investigation",
        "tool": "lc_get_event",
        "action": "read",
        "resource_type": "event",
        "required_inputs": ["oid", "sensor_id", "atom"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches one event by atom on one sensor.",
    },
    "event.children": {
        "suite": "investigation",
        "tool": "lc_list_child_events",
        "action": "read",
        "resource_type": "event_collection",
        "required_inputs": ["oid", "sensor_id", "atom"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Fetches child events for a parent event atom.",
    },
    "event.retention": {
        "suite": "investigation",
        "tool": "lc_get_event_retention",
        "action": "read",
        "resource_type": "event_retention",
        "required_inputs": ["oid", "sensor_id", "start", "end"],
        "optional_inputs": ["is_detailed"],
        "bounds": {"time_format": "unix_seconds"},
        "side_effects": "none",
        "notes": "Use to understand retained event volume before pulling full data.",
    },
    "ioc.search": {
        "suite": "investigation",
        "tool": "lc_search_ioc",
        "action": "read",
        "resource_type": "ioc_search",
        "required_inputs": ["oid", "obj_type", "obj_name"],
        "optional_inputs": ["info", "case_sensitive", "wildcards", "limit", "per_object"],
        "bounds": {"limit_min": 1, "limit_max": 1000, "info": ["summary", "locations"]},
        "side_effects": "none",
        "notes": "Searches Insight object prevalence and locations for one indicator.",
    },
    "ioc.batch_search": {
        "suite": "investigation",
        "tool": "lc_batch_search_iocs",
        "action": "read",
        "resource_type": "ioc_batch_search",
        "required_inputs": ["oid", "objects"],
        "optional_inputs": ["info", "case_sensitive", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 1000, "object_types": ["domain", "ip", "file_hash", "file_path", "file_name", "user", "service_name", "package_name"]},
        "side_effects": "none",
        "notes": "Batch Insight prevalence/location lookup for bounded indicator groups.",
    },
    "ioc.object_info": {
        "suite": "investigation",
        "tool": "lc_get_object_information",
        "action": "read",
        "resource_type": "ioc_search",
        "required_inputs": ["oid", "obj_type", "obj_name"],
        "optional_inputs": ["info", "case_sensitive", "wildcards", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 1000, "info": ["summary", "locations"]},
        "side_effects": "none",
        "notes": "Alias for a single-object Insight lookup with enrichment-oriented naming.",
    },
    "insight.status": {
        "suite": "investigation",
        "tool": "lc_get_insight_status",
        "action": "read",
        "resource_type": "insight_status",
        "required_inputs": ["oid"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Checks whether Insight retention appears enabled for an org.",
    },
    "search.validate": {
        "suite": "investigation",
        "tool": "lc_validate_search_query",
        "action": "read",
        "resource_type": "lcql_validation",
        "required_inputs": ["oid", "query"],
        "optional_inputs": ["start", "end", "stream"],
        "bounds": {"time_format": "unix_seconds", "stream": ["event", "detect", "audit"]},
        "side_effects": "none",
        "notes": "Validates LCQL through the org's search service. Use before estimate or execute.",
    },
    "search.estimate": {
        "suite": "investigation",
        "tool": "lc_estimate_search_query",
        "action": "read",
        "resource_type": "lcql_estimate",
        "required_inputs": ["oid", "query", "start", "end"],
        "optional_inputs": ["stream"],
        "bounds": {"time_format": "unix_seconds", "stream": ["event", "detect", "audit"]},
        "side_effects": "none",
        "notes": "Uses LimaCharlie's search validation endpoint with an explicit time window to estimate query cost.",
    },
    "search.execute": {
        "suite": "investigation",
        "tool": "lc_execute_search_query",
        "action": "execute",
        "resource_type": "lcql_search_job",
        "required_inputs": ["oid", "query", "start", "end"],
        "optional_inputs": ["stream"],
        "bounds": {"time_format": "unix_seconds", "stream": ["event", "detect", "audit"]},
        "side_effects": "starts_server_search_query",
        "notes": "Starts a paginated LCQL search and returns a query_id. Poll explicitly for bounded results.",
    },
    "search.poll": {
        "suite": "investigation",
        "tool": "lc_poll_search_query",
        "action": "read",
        "resource_type": "lcql_search_page",
        "required_inputs": ["oid", "query_id"],
        "optional_inputs": ["token", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Polls one bounded search page and returns checkpoint state including next_token when present.",
    },
    "search.cancel": {
        "suite": "investigation",
        "tool": "lc_cancel_search_query",
        "action": "execute",
        "resource_type": "lcql_search_job",
        "required_inputs": ["oid", "query_id"],
        "optional_inputs": [],
        "side_effects": "cancels_server_search_query",
        "notes": "Cancels a server-side LCQL search job to release search resources.",
    },
    "replay.validate_rule": {
        "suite": "content",
        "tool": "lc_validate_replay_rule",
        "action": "read",
        "resource_type": "replay_validation",
        "required_inputs": ["oid", "rule_content"],
        "optional_inputs": ["trace", "limit_events", "limit_evals"],
        "bounds": {"limit_events_max": 1000, "limit_evals_max": 100000},
        "side_effects": "none",
        "notes": "Validates a D&R rule by dry-running a minimal event through Replay.",
    },
    "replay.scan_events": {
        "suite": "content",
        "tool": "lc_replay_scan_events",
        "action": "read",
        "resource_type": "replay_result",
        "required_inputs": ["oid", "events"],
        "optional_inputs": ["rule_name", "namespace", "rule_content", "trace", "limit_events", "limit_evals", "stream"],
        "bounds": {"events_max": 100, "limit_events_max": 1000, "limit_evals_max": 100000, "stream": ["event", "detect", "audit"]},
        "side_effects": "none",
        "notes": "Dry-runs a rule against explicit events through Replay without generating detections.",
    },
    "replay.run_dry": {
        "suite": "content",
        "tool": "lc_replay_dry_run",
        "action": "read",
        "resource_type": "replay_result",
        "required_inputs": ["oid", "start", "end"],
        "optional_inputs": ["rule_name", "detect", "respond", "sensor_id", "selector", "stream", "trace", "limit_events", "limit_evals"],
        "bounds": {"time_format": "unix_seconds", "limit_events_max": 100000, "limit_evals_max": 1000000, "stream": ["event", "detect", "audit"]},
        "side_effects": "none",
        "notes": "Dry-runs a D&R rule against historical data. Non-dry-run replay remains gated behind future preview/confirm.",
    },
    "artifact.list": {
        "suite": "investigation",
        "tool": "lc_list_artifacts",
        "action": "read",
        "resource_type": "artifact_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["sensor_id", "start", "end", "cursor", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 500, "time_format": "unix_seconds"},
        "side_effects": "none",
        "notes": "Use a time window or cursor; returns one bounded page.",
    },
    "artifact.get_url": {
        "suite": "investigation",
        "tool": "lc_get_artifact_url",
        "action": "read",
        "resource_type": "artifact",
        "required_inputs": ["oid", "artifact_id"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Requests original artifact data or signed export URL.",
    },
    "payload.list": {
        "suite": "content",
        "tool": "lc_list_payloads",
        "action": "read",
        "resource_type": "payload_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists payload metadata. Does not download payload bytes.",
    },
    "payload.get_url": {
        "suite": "content",
        "tool": "lc_get_payload_download_url",
        "action": "read",
        "resource_type": "payload",
        "required_inputs": ["oid", "name"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Returns the API response containing a signed payload download URL when available; does not fetch binary bytes.",
    },
    "arl.get": {
        "suite": "investigation",
        "tool": "lc_get_arl",
        "action": "read",
        "resource_type": "authenticated_resource_locator",
        "required_inputs": ["oid", "arl_url"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Resolves a LimaCharlie authenticated resource locator in explicit org context.",
    },
    "job.list": {
        "suite": "investigation",
        "tool": "lc_list_jobs",
        "action": "read",
        "resource_type": "job_collection",
        "required_inputs": ["oid", "start", "end"],
        "optional_inputs": ["sensor_id", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 500, "time_format": "unix_seconds"},
        "side_effects": "none",
        "notes": "Lists service jobs without returned job data payloads.",
    },
    "job.get": {
        "suite": "investigation",
        "tool": "lc_get_job",
        "action": "read",
        "resource_type": "job",
        "required_inputs": ["oid", "job_id"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches one job status/result record.",
    },
    "job.wait": {
        "suite": "investigation",
        "tool": "lc_wait_job",
        "action": "read",
        "resource_type": "job",
        "required_inputs": ["oid", "job_id"],
        "optional_inputs": ["timeout_seconds", "poll_interval_seconds"],
        "bounds": {"timeout_min": 1, "timeout_max": 600, "poll_interval_min": 1, "poll_interval_max": 30},
        "side_effects": "none",
        "notes": "Polls one job until terminal state or timeout with bounded intervals.",
    },
    "job.delete.preview": {
        "suite": "response",
        "tool": "lc_preview_delete_job",
        "action": "preview",
        "resource_type": "job",
        "required_inputs": ["oid", "job_id"],
        "optional_inputs": ["token_ttl_seconds"],
        "bounds": {"token_ttl_min": 30, "token_ttl_max": 900},
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting one job record.",
    },
    "audit.list": {
        "suite": "investigation",
        "tool": "lc_list_audit_logs",
        "action": "read",
        "resource_type": "audit_log_collection",
        "required_inputs": ["oid", "start", "end"],
        "optional_inputs": ["event_type", "sensor_id", "limit", "cursor"],
        "bounds": {"limit_min": 1, "limit_max": 500, "time_format": "unix_seconds"},
        "side_effects": "none",
        "notes": "Returns one bounded audit-log page for an explicit time window.",
    },
    "tag.list": {
        "suite": "investigation",
        "tool": "lc_list_tags",
        "action": "read",
        "resource_type": "tag_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists tags observed across sensors in the org.",
    },
    "tag.sensor_search": {
        "suite": "investigation",
        "tool": "lc_find_sensors_by_tag",
        "action": "read",
        "resource_type": "sensor_collection",
        "required_inputs": ["oid", "tag"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Finds sensors matching a specific tag.",
    },
    "sensor.hostname_search": {
        "suite": "investigation",
        "tool": "lc_find_sensors_by_hostname",
        "action": "read",
        "resource_type": "sensor_collection",
        "required_inputs": ["oid", "hostname"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Finds sensors by hostname prefix.",
    },
    "schema.list": {
        "suite": "content",
        "tool": "lc_list_schemas",
        "action": "read",
        "resource_type": "schema_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["platform", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists event schemas for the org, optionally filtered by platform.",
    },
    "schema.get": {
        "suite": "content",
        "tool": "lc_get_schema",
        "action": "read",
        "resource_type": "schema",
        "required_inputs": ["oid", "name"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches one event schema definition.",
    },
    "ontology.get": {
        "suite": "content",
        "tool": "lc_get_ontology",
        "action": "read",
        "resource_type": "ontology",
        "required_inputs": [],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Fetches LimaCharlie ontology/event definitions.",
    },
    "event_type.list": {
        "suite": "content",
        "tool": "lc_list_event_types",
        "action": "read",
        "resource_type": "event_type_collection",
        "required_inputs": [],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists available event types.",
    },
    "mitre.get": {
        "suite": "content",
        "tool": "lc_get_mitre_report",
        "action": "read",
        "resource_type": "mitre_report",
        "required_inputs": ["oid"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches org MITRE ATT&CK coverage data.",
    },
    "org.get": {
        "suite": "administration",
        "tool": "lc_get_org_info",
        "action": "read",
        "resource_type": "organization",
        "required_inputs": ["oid"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Org inventory, quotas, and service metadata.",
    },
    "org.stats": {
        "suite": "administration",
        "tool": "lc_get_org_stats",
        "action": "read",
        "resource_type": "organization_stats",
        "required_inputs": ["oid"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Usage and quota statistics.",
    },
    "org.errors": {
        "suite": "administration",
        "tool": "lc_list_org_errors",
        "action": "read",
        "resource_type": "organization_error_collection",
        "required_inputs": ["oid"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Current organization component errors.",
    },
    "org.urls": {
        "suite": "administration",
        "tool": "lc_get_org_urls",
        "action": "read",
        "resource_type": "organization_urls",
        "required_inputs": ["oid"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Service URLs for sensors, adapters, webhooks, replay, and other org-scoped connectivity.",
    },
    "org.runtime_metadata": {
        "suite": "administration",
        "tool": "lc_get_runtime_metadata",
        "action": "read",
        "resource_type": "runtime_metadata",
        "required_inputs": ["oid"],
        "optional_inputs": ["entity_type", "entity_name", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists runtime metadata, optionally filtered by entity type/name.",
    },
    "org.quota_usage": {
        "suite": "administration",
        "tool": "lc_get_quota_usage",
        "action": "read",
        "resource_type": "quota_usage",
        "required_inputs": ["oid"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Returns enforced quota usage; use with online sensor count for capacity checks.",
    },
    "org.quota.set.preview": {
        "suite": "administration",
        "tool": "lc_preview_set_org_quota",
        "action": "preview",
        "resource_type": "organization_quota",
        "required_inputs": ["oid", "quota"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews setting the org sensor quota.",
    },
    "org.rename.preview": {
        "suite": "administration",
        "tool": "lc_preview_rename_org",
        "action": "preview",
        "resource_type": "organization",
        "required_inputs": ["oid", "new_name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews renaming the organization.",
    },
    "group.list": {
        "suite": "administration",
        "tool": "lc_list_groups",
        "action": "read",
        "resource_type": "group_collection",
        "required_inputs": [],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists organization groups accessible to the authenticated identity.",
    },
    "group.create.preview": {
        "suite": "administration",
        "tool": "lc_preview_create_group",
        "action": "preview",
        "resource_type": "group",
        "required_inputs": ["name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating an organization group.",
    },
    "billing.status": {
        "suite": "administration",
        "tool": "lc_get_billing_status",
        "action": "read",
        "resource_type": "billing_status",
        "required_inputs": ["oid"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Gets current billing status for an org.",
    },
    "billing.details": {
        "suite": "administration",
        "tool": "lc_get_billing_details",
        "action": "read",
        "resource_type": "billing_details",
        "required_inputs": ["oid"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Gets detailed billing information for an org.",
    },
    "billing.invoice_url": {
        "suite": "administration",
        "tool": "lc_get_billing_invoice_url",
        "action": "read",
        "resource_type": "billing_invoice",
        "required_inputs": ["oid", "year", "month"],
        "optional_inputs": ["fmt"],
        "bounds": {"month_min": 1, "month_max": 12, "fmt": ["pdf", "csv"]},
        "side_effects": "none",
        "notes": "Gets an invoice URL for a specific billing month.",
    },
    "billing.plans": {
        "suite": "administration",
        "tool": "lc_list_billing_plans",
        "action": "read",
        "resource_type": "billing_plan_collection",
        "required_inputs": [],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists available billing plans.",
    },
    "group.get": {
        "suite": "administration",
        "tool": "lc_get_group",
        "action": "read",
        "resource_type": "group",
        "required_inputs": ["group_id"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches one group definition, including members, owners, orgs, and permissions when available.",
    },
    "group.delete.preview": {
        "suite": "administration",
        "tool": "lc_preview_delete_group",
        "action": "preview",
        "resource_type": "group",
        "required_inputs": ["group_id"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting an organization group.",
    },
    "group.member.add.preview": {
        "suite": "administration",
        "tool": "lc_preview_add_group_member",
        "action": "preview",
        "resource_type": "group_member",
        "required_inputs": ["group_id", "email"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews adding a group member.",
    },
    "group.member.remove.preview": {
        "suite": "administration",
        "tool": "lc_preview_remove_group_member",
        "action": "preview",
        "resource_type": "group_member",
        "required_inputs": ["group_id", "email"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews removing a group member.",
    },
    "group.owner.add.preview": {
        "suite": "administration",
        "tool": "lc_preview_add_group_owner",
        "action": "preview",
        "resource_type": "group_owner",
        "required_inputs": ["group_id", "email"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews adding a group owner.",
    },
    "group.owner.remove.preview": {
        "suite": "administration",
        "tool": "lc_preview_remove_group_owner",
        "action": "preview",
        "resource_type": "group_owner",
        "required_inputs": ["group_id", "email"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews removing a group owner.",
    },
    "group.permissions.set.preview": {
        "suite": "administration",
        "tool": "lc_preview_set_group_permissions",
        "action": "preview",
        "resource_type": "group_permissions",
        "required_inputs": ["group_id", "permissions"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews replacing a group's permission list.",
    },
    "group.org.add.preview": {
        "suite": "administration",
        "tool": "lc_preview_add_group_org",
        "action": "preview",
        "resource_type": "group_org_membership",
        "required_inputs": ["group_id", "member_oid"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews adding an org to a group.",
    },
    "group.org.remove.preview": {
        "suite": "administration",
        "tool": "lc_preview_remove_group_org",
        "action": "preview",
        "resource_type": "group_org_membership",
        "required_inputs": ["group_id", "member_oid"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews removing an org from a group.",
    },
    "group.logs": {
        "suite": "administration",
        "tool": "lc_list_group_logs",
        "action": "read",
        "resource_type": "group_log_collection",
        "required_inputs": ["group_id"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists audit logs for one group.",
    },
    "user.list": {
        "suite": "administration",
        "tool": "lc_list_users",
        "action": "read",
        "resource_type": "user_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists users with access to the org.",
    },
    "user.invite.preview": {
        "suite": "administration",
        "tool": "lc_preview_invite_user",
        "action": "preview",
        "resource_type": "user",
        "required_inputs": ["oid", "email"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews inviting a user to an org.",
    },
    "user.remove.preview": {
        "suite": "administration",
        "tool": "lc_preview_remove_user",
        "action": "preview",
        "resource_type": "user",
        "required_inputs": ["oid", "email"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews removing a user from an org.",
    },
    "user.permission.list": {
        "suite": "administration",
        "tool": "lc_list_user_permissions",
        "action": "read",
        "resource_type": "user_permission_collection",
        "required_inputs": ["oid"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Lists permission mappings by user.",
    },
    "user.permission.add.preview": {
        "suite": "administration",
        "tool": "lc_preview_add_user_permission",
        "action": "preview",
        "resource_type": "user_permission",
        "required_inputs": ["oid", "email", "permission"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews granting one permission to a user.",
    },
    "user.permission.remove.preview": {
        "suite": "administration",
        "tool": "lc_preview_remove_user_permission",
        "action": "preview",
        "resource_type": "user_permission",
        "required_inputs": ["oid", "email", "permission"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews revoking one permission from a user.",
    },
    "user.role.set.preview": {
        "suite": "administration",
        "tool": "lc_preview_set_user_role",
        "action": "preview",
        "resource_type": "user_role",
        "required_inputs": ["oid", "email", "role"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews replacing a user's permissions with a predefined role.",
    },
    "api_key.list": {
        "suite": "administration",
        "tool": "lc_list_api_keys",
        "action": "read",
        "resource_type": "api_key_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists API key metadata. Secrets are not expected from list responses.",
    },
    "api_key.create.preview": {
        "suite": "administration",
        "tool": "lc_preview_create_api_key",
        "action": "preview",
        "resource_type": "api_key",
        "required_inputs": ["oid", "name", "permissions"],
        "optional_inputs": ["ip_range", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating an API key. Credential-shaped confirmation response fields are redacted.",
    },
    "api_key.delete.preview": {
        "suite": "administration",
        "tool": "lc_preview_delete_api_key",
        "action": "preview",
        "resource_type": "api_key",
        "required_inputs": ["oid", "key_hash"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting an API key by key hash.",
    },
    "installation_key.list": {
        "suite": "administration",
        "tool": "lc_list_installation_keys",
        "action": "read",
        "resource_type": "installation_key_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists installation key metadata.",
    },
    "installation_key.get": {
        "suite": "administration",
        "tool": "lc_get_installation_key",
        "action": "read",
        "resource_type": "installation_key",
        "required_inputs": ["oid", "installation_key_id"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches one installation key by ID.",
    },
    "installation_key.create.preview": {
        "suite": "administration",
        "tool": "lc_preview_create_installation_key",
        "action": "preview",
        "resource_type": "installation_key",
        "required_inputs": ["oid", "description"],
        "optional_inputs": ["tags", "use_public_ca", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating an installation key.",
    },
    "installation_key.delete.preview": {
        "suite": "administration",
        "tool": "lc_preview_delete_installation_key",
        "action": "preview",
        "resource_type": "installation_key",
        "required_inputs": ["oid", "installation_key_id"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting an installation key.",
    },
    "ingestion_key.create.preview": {
        "suite": "administration",
        "tool": "lc_preview_create_ingestion_key",
        "action": "preview",
        "resource_type": "ingestion_key",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating an ingestion key.",
    },
    "ingestion_key.delete.preview": {
        "suite": "administration",
        "tool": "lc_preview_delete_ingestion_key",
        "action": "preview",
        "resource_type": "ingestion_key",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting an ingestion key.",
    },
    "output.list": {
        "suite": "administration",
        "tool": "lc_list_outputs",
        "action": "read",
        "resource_type": "output_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists output integration configuration.",
    },
    "output.create.preview": {
        "suite": "administration",
        "tool": "lc_preview_create_output",
        "action": "preview",
        "resource_type": "output",
        "required_inputs": ["oid", "name", "module", "data_type"],
        "optional_inputs": ["config", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating an output integration.",
    },
    "output.delete.preview": {
        "suite": "administration",
        "tool": "lc_preview_delete_output",
        "action": "preview",
        "resource_type": "output",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting an output integration.",
    },
    "extension.list_subscribed": {
        "suite": "administration",
        "tool": "lc_list_extension_subscriptions",
        "action": "read",
        "resource_type": "extension_subscription_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists extensions subscribed by the org.",
    },
    "extension.subscribe.preview": {
        "suite": "administration",
        "tool": "lc_preview_subscribe_extension",
        "action": "preview",
        "resource_type": "extension_subscription",
        "required_inputs": ["oid", "extension_name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews subscribing an org to an extension.",
    },
    "extension.unsubscribe.preview": {
        "suite": "administration",
        "tool": "lc_preview_unsubscribe_extension",
        "action": "preview",
        "resource_type": "extension_subscription",
        "required_inputs": ["oid", "extension_name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews unsubscribing an org from an extension.",
    },
    "extension.rekey.preview": {
        "suite": "administration",
        "tool": "lc_preview_rekey_extension",
        "action": "preview",
        "resource_type": "extension_subscription",
        "required_inputs": ["oid", "extension_name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews rotating an extension subscription API key.",
    },
    "extension.list_available": {
        "suite": "administration",
        "tool": "lc_list_available_extensions",
        "action": "read",
        "resource_type": "extension_definition_collection",
        "required_inputs": [],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists extension definitions available globally.",
    },
    "extension.get": {
        "suite": "administration",
        "tool": "lc_get_extension",
        "action": "read",
        "resource_type": "extension_definition",
        "required_inputs": ["extension_name"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches one extension definition.",
    },
    "extension.create.preview": {
        "suite": "administration",
        "tool": "lc_preview_create_extension",
        "action": "preview",
        "resource_type": "extension_definition",
        "required_inputs": ["extension_definition"],
        "optional_inputs": ["extension_name", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating an extension definition.",
    },
    "extension.update.preview": {
        "suite": "administration",
        "tool": "lc_preview_update_extension",
        "action": "preview",
        "resource_type": "extension_definition",
        "required_inputs": ["extension_definition"],
        "optional_inputs": ["extension_name", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews updating an extension definition.",
    },
    "extension.delete.preview": {
        "suite": "administration",
        "tool": "lc_preview_delete_extension",
        "action": "preview",
        "resource_type": "extension_definition",
        "required_inputs": ["extension_name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting an extension definition.",
    },
    "extension.schema.get": {
        "suite": "administration",
        "tool": "lc_get_extension_schema",
        "action": "read",
        "resource_type": "extension_schema",
        "required_inputs": ["oid", "extension_name"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches extension schema for an org context.",
    },
    "extension.request.preview": {
        "suite": "administration",
        "tool": "lc_preview_extension_request",
        "action": "preview",
        "resource_type": "extension_request",
        "required_inputs": ["oid", "extension_name", "action"],
        "optional_inputs": ["data", "impersonate", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews a generic extension request. Side effects depend on the extension action.",
    },
    "vulnerability.cve.list": {
        "suite": "investigation",
        "tool": "lc_list_vulnerability_cves",
        "action": "read",
        "resource_type": "vulnerability_cve_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["cursor", "limit", "sort_by", "sort_asc", "filters", "search", "include_tags", "include_enrichment", "filter_via_state"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Paginated CVE rollup from ext-vulnerability-reporting.",
    },
    "vulnerability.cve.get": {
        "suite": "investigation",
        "tool": "lc_get_vulnerability_cve",
        "action": "read",
        "resource_type": "vulnerability_cve",
        "required_inputs": ["oid", "cve"],
        "optional_inputs": ["include_enrichment"],
        "side_effects": "none",
        "notes": "Single-CVE details, optionally including KEV, EPSS, and exploit refs.",
    },
    "vulnerability.cve.hosts": {
        "suite": "investigation",
        "tool": "lc_list_vulnerability_cve_hosts",
        "action": "read",
        "resource_type": "vulnerability_host_collection",
        "required_inputs": ["oid", "cve"],
        "optional_inputs": ["cursor", "limit", "sort_by", "sort_asc", "filters", "search", "include_tags", "filter_via_state", "normalized_package_name"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists endpoints affected by one CVE.",
    },
    "vulnerability.cve.packages": {
        "suite": "investigation",
        "tool": "lc_list_vulnerability_cve_packages",
        "action": "read",
        "resource_type": "vulnerability_package_collection",
        "required_inputs": ["oid", "cve"],
        "optional_inputs": ["cursor", "limit", "sort_by", "sort_asc", "include_enrichment"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists package/version pairs affected by one CVE.",
    },
    "vulnerability.endpoint.list": {
        "suite": "investigation",
        "tool": "lc_list_vulnerability_endpoints",
        "action": "read",
        "resource_type": "vulnerability_endpoint_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["cursor", "limit", "sort_by", "sort_asc", "filters", "search", "include_tags", "filter_via_state"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists endpoints with vulnerability counts.",
    },
    "vulnerability.host.packages": {
        "suite": "investigation",
        "tool": "lc_list_vulnerability_host_packages",
        "action": "read",
        "resource_type": "vulnerability_package_collection",
        "required_inputs": ["oid", "sensor_id"],
        "optional_inputs": ["cursor", "limit", "sort_by", "sort_asc", "filters", "search", "include_tags", "include_enrichment", "filter_via_state", "rollup_subpackages"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists vulnerable packages and CVEs on one sensor.",
    },
    "vulnerability.dashboard": {
        "suite": "investigation",
        "tool": "lc_get_vulnerability_dashboard",
        "action": "read",
        "resource_type": "vulnerability_dashboard",
        "required_inputs": ["oid"],
        "optional_inputs": ["sort_asc"],
        "side_effects": "none",
        "notes": "Dashboard graph data from ext-vulnerability-reporting.",
    },
    "vulnerability.resolution.list": {
        "suite": "investigation",
        "tool": "lc_list_vulnerability_resolutions",
        "action": "read",
        "resource_type": "vulnerability_resolution_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["scope", "resolutions", "cursor", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 500, "scope": ["org", "host"]},
        "side_effects": "none",
        "notes": "Lists stored finding resolution overlays. Missing rows imply open findings.",
    },
    "vulnerability.snapshot.list": {
        "suite": "investigation",
        "tool": "lc_list_vulnerability_snapshots",
        "action": "read",
        "resource_type": "vulnerability_snapshot_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["days", "severities"],
        "bounds": {"days_min": 1, "days_max": 365},
        "side_effects": "none",
        "notes": "Daily open-finding counts for burndown views.",
    },
    "vulnerability.epss_history": {
        "suite": "investigation",
        "tool": "lc_get_vulnerability_epss_history",
        "action": "read",
        "resource_type": "vulnerability_epss_history",
        "required_inputs": ["oid", "cve"],
        "optional_inputs": ["days"],
        "bounds": {"days_min": 1, "days_max": 365},
        "side_effects": "none",
        "notes": "Per-day EPSS score and percentile history for one CVE.",
    },
    "artifact_rule.list": {
        "suite": "content",
        "tool": "lc_list_artifact_rules",
        "action": "read",
        "resource_type": "artifact_rule_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists artifact collection rules.",
    },
    "artifact_rule.set.preview": {
        "suite": "content",
        "tool": "lc_preview_set_artifact_rule",
        "action": "preview",
        "resource_type": "artifact_rule",
        "required_inputs": ["oid", "name", "platforms", "patterns"],
        "optional_inputs": ["is_delete_after", "retention_days", "tags", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating or updating an artifact collection rule.",
    },
    "artifact_rule.delete.preview": {
        "suite": "content",
        "tool": "lc_preview_delete_artifact_rule",
        "action": "preview",
        "resource_type": "artifact_rule",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting an artifact collection rule.",
    },
    "ingestion_key.list": {
        "suite": "administration",
        "tool": "lc_list_ingestion_keys",
        "action": "read",
        "resource_type": "ingestion_key_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists ingestion key metadata.",
    },
    "logging_rule.list": {
        "suite": "content",
        "tool": "lc_list_logging_rules",
        "action": "read",
        "resource_type": "logging_rule_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists logging collection rules through the logging service.",
    },
    "logging_rule.set.preview": {
        "suite": "content",
        "tool": "lc_preview_set_logging_rule",
        "action": "preview",
        "resource_type": "logging_rule",
        "required_inputs": ["oid", "name", "patterns"],
        "optional_inputs": ["tags", "platforms", "retention_days", "delete_after", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating or updating a logging collection rule.",
    },
    "logging_rule.delete.preview": {
        "suite": "content",
        "tool": "lc_preview_delete_logging_rule",
        "action": "preview",
        "resource_type": "logging_rule",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting a logging collection rule.",
    },
    "dr_rule.list": {
        "suite": "content",
        "tool": "lc_list_dr_rules",
        "action": "read",
        "resource_type": "dr_rule_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["namespace", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 500, "namespace": ["general", "managed", "service"]},
        "side_effects": "none",
        "notes": "Lists D&R rules from the corresponding hive namespace.",
    },
    "dr_rule.get": {
        "suite": "content",
        "tool": "lc_get_dr_rule",
        "action": "read",
        "resource_type": "dr_rule",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["namespace"],
        "bounds": {"namespace": ["general", "managed", "service"]},
        "side_effects": "none",
        "notes": "Fetches one D&R hive record.",
    },
    "dr_rule.set.preview": {
        "suite": "content",
        "tool": "lc_preview_set_dr_rule",
        "action": "preview",
        "resource_type": "dr_rule",
        "required_inputs": ["oid", "name", "data"],
        "optional_inputs": ["namespace", "enabled", "tags", "comment", "expiry", "etag", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating or updating a D&R hive record.",
    },
    "dr_rule.delete.preview": {
        "suite": "content",
        "tool": "lc_preview_delete_dr_rule",
        "action": "preview",
        "resource_type": "dr_rule",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["namespace", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting a D&R hive record.",
    },
    "fp_rule.list": {
        "suite": "content",
        "tool": "lc_list_fp_rules",
        "action": "read",
        "resource_type": "fp_rule_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists false-positive rules from the fp hive.",
    },
    "fp_rule.get": {
        "suite": "content",
        "tool": "lc_get_fp_rule",
        "action": "read",
        "resource_type": "fp_rule",
        "required_inputs": ["oid", "name"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches one false-positive hive record.",
    },
    "fp_rule.set.preview": {
        "suite": "content",
        "tool": "lc_preview_set_fp_rule",
        "action": "preview",
        "resource_type": "fp_rule",
        "required_inputs": ["oid", "name", "data"],
        "optional_inputs": ["enabled", "tags", "comment", "expiry", "etag", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating or updating a false-positive hive record.",
    },
    "fp_rule.delete.preview": {
        "suite": "content",
        "tool": "lc_preview_delete_fp_rule",
        "action": "preview",
        "resource_type": "fp_rule",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting a false-positive hive record.",
    },
    "integrity_rule.list": {
        "suite": "content",
        "tool": "lc_list_integrity_rules",
        "action": "read",
        "resource_type": "integrity_rule_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists integrity monitoring rules through the integrity service.",
    },
    "integrity_rule.get": {
        "suite": "content",
        "tool": "lc_get_integrity_rule",
        "action": "read",
        "resource_type": "integrity_rule",
        "required_inputs": ["oid", "name"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches one integrity rule by name from the integrity service list.",
    },
    "integrity_rule.set.preview": {
        "suite": "content",
        "tool": "lc_preview_set_integrity_rule",
        "action": "preview",
        "resource_type": "integrity_rule",
        "required_inputs": ["oid", "name", "patterns"],
        "optional_inputs": ["tags", "platforms", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating or updating an integrity monitoring rule.",
    },
    "integrity_rule.delete.preview": {
        "suite": "content",
        "tool": "lc_preview_delete_integrity_rule",
        "action": "preview",
        "resource_type": "integrity_rule",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting an integrity monitoring rule.",
    },
    "usp.validate": {
        "suite": "content",
        "tool": "lc_validate_usp_mapping",
        "action": "read",
        "resource_type": "usp_validation",
        "required_inputs": ["oid", "platform"],
        "optional_inputs": ["mapping", "mappings", "text_input", "json_input", "hostname", "indexing"],
        "bounds": {"payload_max_bytes": 200000},
        "side_effects": "none",
        "notes": "Validates Universal Sensor Protocol mapping/input configuration.",
    },
    "yara_rule.list": {
        "suite": "content",
        "tool": "lc_list_yara_rules",
        "action": "read",
        "resource_type": "yara_rule_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists YARA scanning rules through the YARA service.",
    },
    "yara.scan.preview": {
        "suite": "response",
        "tool": "lc_preview_yara_scan",
        "action": "preview",
        "resource_type": "yara_scan",
        "required_inputs": ["oid", "sensor_id", "rule"],
        "optional_inputs": ["timeout_seconds", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews running an ad-hoc YARA scan on one sensor.",
    },
    "yara_rule.set.preview": {
        "suite": "content",
        "tool": "lc_preview_set_yara_rule",
        "action": "preview",
        "resource_type": "yara_rule",
        "required_inputs": ["oid", "name", "sources"],
        "optional_inputs": ["tags", "platforms", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating or updating a YARA scanning rule.",
    },
    "yara_rule.delete.preview": {
        "suite": "content",
        "tool": "lc_preview_delete_yara_rule",
        "action": "preview",
        "resource_type": "yara_rule",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting a YARA scanning rule.",
    },
    "yara_source.list": {
        "suite": "content",
        "tool": "lc_list_yara_sources",
        "action": "read",
        "resource_type": "yara_source_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists YARA source names through the YARA service.",
    },
    "yara_source.get": {
        "suite": "content",
        "tool": "lc_get_yara_source",
        "action": "read",
        "resource_type": "yara_source",
        "required_inputs": ["oid", "name"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches one YARA source through the YARA service.",
    },
    "yara_source.set.preview": {
        "suite": "content",
        "tool": "lc_preview_set_yara_source",
        "action": "preview",
        "resource_type": "yara_source",
        "required_inputs": ["oid", "name", "source"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating or updating a YARA source.",
    },
    "yara_source.delete.preview": {
        "suite": "content",
        "tool": "lc_preview_delete_yara_source",
        "action": "preview",
        "resource_type": "yara_source",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting a YARA source.",
    },
    "mutation.pending.list": {
        "suite": "response",
        "tool": "lc_list_pending_mutations",
        "action": "read",
        "resource_type": "mutation_preview_collection",
        "required_inputs": [],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Lists short-lived local mutation previews that can still be confirmed.",
    },
    "mutation.cancel": {
        "suite": "response",
        "tool": "lc_cancel_mutation",
        "action": "local_execute",
        "resource_type": "mutation_preview",
        "required_inputs": ["confirmation_token"],
        "optional_inputs": [],
        "side_effects": "local_preview_deleted",
        "notes": "Cancels one pending preview token without calling LimaCharlie.",
    },
    "mutation.confirm": {
        "suite": "response",
        "tool": "lc_confirm_mutation",
        "action": "execute",
        "resource_type": "mutation_preview",
        "required_inputs": ["confirmation_token"],
        "optional_inputs": [],
        "side_effects": "executes_exact_previewed_mutation",
        "notes": "Executes only the exact operation, target, and payload bound to a preview token.",
    },
    "sensor.tag.add.preview": {
        "suite": "response",
        "tool": "lc_preview_add_sensor_tag",
        "action": "preview",
        "resource_type": "sensor_tag",
        "required_inputs": ["oid", "sensor_id", "tag"],
        "optional_inputs": ["ttl_seconds", "token_ttl_seconds"],
        "bounds": {"ttl_min": 0, "ttl_max": 2592000, "token_ttl_min": 30, "token_ttl_max": 900},
        "side_effects": "none_until_confirmed",
        "notes": "Previews POST /v1/{sid}/tags. Requires lc_confirm_mutation before any remote write.",
    },
    "sensor.tag.remove.preview": {
        "suite": "response",
        "tool": "lc_preview_remove_sensor_tag",
        "action": "preview",
        "resource_type": "sensor_tag",
        "required_inputs": ["oid", "sensor_id", "tag"],
        "optional_inputs": ["token_ttl_seconds"],
        "bounds": {"token_ttl_min": 30, "token_ttl_max": 900},
        "side_effects": "none_until_confirmed",
        "notes": "Previews DELETE /v1/{sid}/tags. Requires lc_confirm_mutation before any remote write.",
    },
}

OPERATION_CATALOG.update(
    {
        "case.create.preview": {
            "suite": "investigation",
            "tool": "lc_preview_create_case",
            "action": "preview",
            "resource_type": "case",
            "required_inputs": ["oid"],
            "optional_inputs": ["detection", "severity", "summary", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews ext-cases create_case request. Confirmation creates the case.",
        },
        "case.update.preview": {
            "suite": "investigation",
            "tool": "lc_preview_update_case",
            "action": "preview",
            "resource_type": "case",
            "required_inputs": ["oid", "case_number"],
            "optional_inputs": ["status", "severity", "assignees", "classification", "summary", "conclusion", "tags", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews PATCH /cases/{case_number} against the Cases API.",
        },
        "case.note.add.preview": {
            "suite": "investigation",
            "tool": "lc_preview_add_case_note",
            "action": "preview",
            "resource_type": "case_note",
            "required_inputs": ["oid", "case_number", "content"],
            "optional_inputs": ["note_type", "is_public", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews adding an analyst note to a case.",
        },
        "case.note.visibility.preview": {
            "suite": "investigation",
            "tool": "lc_preview_update_case_note_visibility",
            "action": "preview",
            "resource_type": "case_note",
            "required_inputs": ["oid", "case_number", "event_id", "is_public"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews toggling note stakeholder visibility.",
        },
        "case.bulk_update.preview": {
            "suite": "investigation",
            "tool": "lc_preview_bulk_update_cases",
            "action": "preview",
            "resource_type": "case_collection",
            "required_inputs": ["oid", "case_numbers"],
            "optional_inputs": ["status", "severity", "assignees", "classification", "summary", "conclusion", "tags", "token_ttl_seconds"],
            "bounds": {"case_numbers_max": 200},
            "side_effects": "none_until_confirmed",
            "notes": "Previews a Cases bulk-update request.",
        },
        "case.merge.preview": {
            "suite": "investigation",
            "tool": "lc_preview_merge_cases",
            "action": "preview",
            "resource_type": "case_merge",
            "required_inputs": ["oid", "target_case_number", "source_case_numbers"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews merging source cases into a target case.",
        },
        "case.detection.list": {
            "suite": "investigation",
            "tool": "lc_list_case_detections",
            "action": "read",
            "resource_type": "case_detection_collection",
            "required_inputs": ["oid", "case_number"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Lists detections linked to a case.",
        },
        "case.detection.add.preview": {
            "suite": "investigation",
            "tool": "lc_preview_add_case_detection",
            "action": "preview",
            "resource_type": "case_detection",
            "required_inputs": ["oid", "case_number", "detection"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews linking a full LC detection object to a case.",
        },
        "case.detection.remove.preview": {
            "suite": "investigation",
            "tool": "lc_preview_remove_case_detection",
            "action": "preview",
            "resource_type": "case_detection",
            "required_inputs": ["oid", "case_number", "detection_id"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews removing a detection link from a case.",
        },
        "case.entity.list": {
            "suite": "investigation",
            "tool": "lc_list_case_entities",
            "action": "read",
            "resource_type": "case_entity_collection",
            "required_inputs": ["oid", "case_number"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Lists entities/IOCs attached to a case.",
        },
        "case.entity.search": {
            "suite": "investigation",
            "tool": "lc_search_case_entities",
            "action": "read",
            "resource_type": "case_entity_collection",
            "required_inputs": ["oid", "entity_type", "entity_value"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Searches case entities across an org.",
        },
        "case.entity.add.preview": {
            "suite": "investigation",
            "tool": "lc_preview_add_case_entity",
            "action": "preview",
            "resource_type": "case_entity",
            "required_inputs": ["oid", "case_number", "entity_type", "entity_value"],
            "optional_inputs": ["note", "verdict", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews adding an IOC/entity to a case.",
        },
        "case.entity.update.preview": {
            "suite": "investigation",
            "tool": "lc_preview_update_case_entity",
            "action": "preview",
            "resource_type": "case_entity",
            "required_inputs": ["oid", "case_number", "entity_id"],
            "optional_inputs": ["note", "verdict", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews updating an entity's note or verdict.",
        },
        "case.entity.remove.preview": {
            "suite": "investigation",
            "tool": "lc_preview_remove_case_entity",
            "action": "preview",
            "resource_type": "case_entity",
            "required_inputs": ["oid", "case_number", "entity_id"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews removing an entity from a case.",
        },
        "case.telemetry.list": {
            "suite": "investigation",
            "tool": "lc_list_case_telemetry",
            "action": "read",
            "resource_type": "case_telemetry_collection",
            "required_inputs": ["oid", "case_number"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Lists telemetry references linked to a case.",
        },
        "case.telemetry.add.preview": {
            "suite": "investigation",
            "tool": "lc_preview_add_case_telemetry",
            "action": "preview",
            "resource_type": "case_telemetry",
            "required_inputs": ["oid", "case_number", "event"],
            "optional_inputs": ["note", "verdict", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews linking a full LC event object to a case.",
        },
        "case.telemetry.update.preview": {
            "suite": "investigation",
            "tool": "lc_preview_update_case_telemetry",
            "action": "preview",
            "resource_type": "case_telemetry",
            "required_inputs": ["oid", "case_number", "telemetry_id"],
            "optional_inputs": ["note", "verdict", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews updating a telemetry note or verdict.",
        },
        "case.telemetry.remove.preview": {
            "suite": "investigation",
            "tool": "lc_preview_remove_case_telemetry",
            "action": "preview",
            "resource_type": "case_telemetry",
            "required_inputs": ["oid", "case_number", "telemetry_id"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews removing a telemetry reference from a case.",
        },
        "case.artifact.list": {
            "suite": "investigation",
            "tool": "lc_list_case_artifacts",
            "action": "read",
            "resource_type": "case_artifact_collection",
            "required_inputs": ["oid", "case_number"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Lists forensic artifact references attached to a case.",
        },
        "case.artifact.add.preview": {
            "suite": "investigation",
            "tool": "lc_preview_add_case_artifact",
            "action": "preview",
            "resource_type": "case_artifact",
            "required_inputs": ["oid", "case_number", "path", "source"],
            "optional_inputs": ["artifact_type", "note", "verdict", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews adding a forensic artifact reference to a case.",
        },
        "case.artifact.remove.preview": {
            "suite": "investigation",
            "tool": "lc_preview_remove_case_artifact",
            "action": "preview",
            "resource_type": "case_artifact",
            "required_inputs": ["oid", "case_number", "artifact_id"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews removing a forensic artifact from a case.",
        },
        "case.export": {
            "suite": "investigation",
            "tool": "lc_export_case",
            "action": "read",
            "resource_type": "case_export",
            "required_inputs": ["oid", "case_number"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Fetches a case plus detections, entities, telemetry, and artifacts.",
        },
        "case.report": {
            "suite": "investigation",
            "tool": "lc_get_cases_report_summary",
            "action": "read",
            "resource_type": "case_report",
            "required_inputs": ["oid", "time_from", "time_to"],
            "optional_inputs": ["group_by"],
            "side_effects": "none",
            "notes": "Gets SOC report summary metrics from the Cases API.",
        },
        "case.dashboard": {
            "suite": "investigation",
            "tool": "lc_get_cases_dashboard_counts",
            "action": "read",
            "resource_type": "case_dashboard",
            "required_inputs": ["oid"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Gets real-time case counts by status/severity and SLA breach state.",
        },
        "case.config.get": {
            "suite": "administration",
            "tool": "lc_get_cases_config",
            "action": "read",
            "resource_type": "case_config",
            "required_inputs": ["oid"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Fetches Cases configuration for an org.",
        },
        "case.config.set.preview": {
            "suite": "administration",
            "tool": "lc_preview_set_cases_config",
            "action": "preview",
            "resource_type": "case_config",
            "required_inputs": ["oid", "config"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews replacing Cases configuration for an org.",
        },
        "case.assignees.list": {
            "suite": "investigation",
            "tool": "lc_list_case_assignees",
            "action": "read",
            "resource_type": "case_assignee_collection",
            "required_inputs": ["oid"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Lists unique assignees across cases in an org.",
        },
        "case.org.list": {
            "suite": "administration",
            "tool": "lc_list_case_orgs",
            "action": "read",
            "resource_type": "case_org_collection",
            "required_inputs": [],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Lists orgs subscribed to ext-cases that the caller can access.",
        },
        "case.tag.set.preview": {
            "suite": "investigation",
            "tool": "lc_preview_set_case_tags",
            "action": "preview",
            "resource_type": "case_tag_collection",
            "required_inputs": ["oid", "case_number", "tags"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews replacing all tags on a case.",
        },
        "case.tag.add.preview": {
            "suite": "investigation",
            "tool": "lc_preview_add_case_tags",
            "action": "preview",
            "resource_type": "case_tag_collection",
            "required_inputs": ["oid", "case_number", "tags"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Reads current tags, then previews the exact replacement tag list.",
        },
        "case.tag.remove.preview": {
            "suite": "investigation",
            "tool": "lc_preview_remove_case_tags",
            "action": "preview",
            "resource_type": "case_tag_collection",
            "required_inputs": ["oid", "case_number", "tags"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Reads current tags, then previews the exact replacement tag list.",
        },
    }
)

OPERATION_CATALOG.update(
    {
        "org.name.check": {
            "suite": "administration",
            "tool": "lc_check_org_name",
            "action": "read",
            "resource_type": "organization_name",
            "required_inputs": ["name"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Checks whether an organization name is available.",
        },
        "org.create.preview": {
            "suite": "administration",
            "tool": "lc_preview_create_org",
            "action": "preview",
            "resource_type": "organization",
            "required_inputs": ["name"],
            "optional_inputs": ["location", "template", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews creating a new LimaCharlie org.",
        },
        "org.config.get": {
            "suite": "administration",
            "tool": "lc_get_org_config_value",
            "action": "read",
            "resource_type": "organization_config_value",
            "required_inputs": ["oid", "config_name"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Gets one org config value by name.",
        },
        "org.config.set.preview": {
            "suite": "administration",
            "tool": "lc_preview_set_org_config_value",
            "action": "preview",
            "resource_type": "organization_config_value",
            "required_inputs": ["oid", "config_name", "value"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews setting one org config value.",
        },
        "org.error.dismiss.preview": {
            "suite": "administration",
            "tool": "lc_preview_dismiss_org_error",
            "action": "preview",
            "resource_type": "organization_error",
            "required_inputs": ["oid", "component"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews dismissing one org component error.",
        },
        "org.delete.confirmation": {
            "suite": "administration",
            "tool": "lc_get_org_delete_confirmation",
            "action": "read",
            "resource_type": "organization_delete_confirmation",
            "required_inputs": ["oid"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Requests the LimaCharlie delete confirmation token for an org.",
        },
        "org.delete.preview": {
            "suite": "administration",
            "tool": "lc_preview_delete_org",
            "action": "preview",
            "resource_type": "organization",
            "required_inputs": ["oid", "confirmation"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews deleting an org using the confirmation returned by lc_get_org_delete_confirmation.",
        },
        "sensor.export": {
            "suite": "administration",
            "tool": "lc_export_sensors",
            "action": "read",
            "resource_type": "sensor_export",
            "required_inputs": ["oid"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Exports the full sensor manifest through the org export endpoint.",
        },
        "sensor.version.set.preview": {
            "suite": "administration",
            "tool": "lc_preview_set_sensor_version",
            "action": "preview",
            "resource_type": "sensor_version_policy",
            "required_inputs": ["oid"],
            "optional_inputs": ["version", "is_fallback", "is_sleep", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews changing org sensor version/branch policy.",
        },
        "service.list": {
            "suite": "administration",
            "tool": "lc_list_available_services",
            "action": "read",
            "resource_type": "service_collection",
            "required_inputs": ["oid"],
            "optional_inputs": ["limit"],
            "bounds": {"limit_min": 1, "limit_max": 500},
            "side_effects": "none",
            "notes": "Lists available services/replicants for an org.",
        },
        "service.request.preview": {
            "suite": "administration",
            "tool": "lc_preview_service_request",
            "action": "preview",
            "resource_type": "service_request",
            "required_inputs": ["oid", "service_name", "request_data"],
            "optional_inputs": ["is_async", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews a generic non-impersonated service request. JWT impersonation is intentionally not exposed.",
        },
        "config.fetch": {
            "suite": "administration",
            "tool": "lc_fetch_config",
            "action": "read",
            "resource_type": "infrastructure_config",
            "required_inputs": ["oid"],
            "optional_inputs": ["sync_outputs", "sync_integrity", "sync_artifact", "sync_exfil", "sync_resources", "sync_extensions", "sync_org_values", "sync_hives", "sync_installation_keys", "sync_yara"],
            "side_effects": "none",
            "notes": "Fetches org IaC configuration via ext-infrastructure without exposing JWTs in tool output.",
        },
        "config.push.preview": {
            "suite": "administration",
            "tool": "lc_preview_push_config",
            "action": "preview",
            "resource_type": "infrastructure_config",
            "required_inputs": ["oid", "config"],
            "optional_inputs": ["is_force", "is_dry_run", "ignore_inaccessible", "sync_outputs", "sync_integrity", "sync_artifact", "sync_exfil", "sync_resources", "sync_extensions", "sync_org_values", "sync_hives", "sync_installation_keys", "sync_yara", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews an ext-infrastructure config push request. Use is_dry_run for backend simulation.",
        },
        "exfil_rule.list": {
            "suite": "content",
            "tool": "lc_list_exfil_rules",
            "action": "read",
            "resource_type": "exfil_rule_collection",
            "required_inputs": ["oid"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Lists exfil prevention rules through the exfil service.",
        },
        "exfil_watch.create.preview": {
            "suite": "content",
            "tool": "lc_preview_create_exfil_watch",
            "action": "preview",
            "resource_type": "exfil_watch",
            "required_inputs": ["oid", "name", "event", "value", "operator", "path"],
            "optional_inputs": ["tags", "platforms", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews creating an exfil watch rule.",
        },
        "exfil_event.create.preview": {
            "suite": "content",
            "tool": "lc_preview_create_exfil_event",
            "action": "preview",
            "resource_type": "exfil_event_rule",
            "required_inputs": ["oid", "name", "events"],
            "optional_inputs": ["tags", "platforms", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews creating an exfil event rule.",
        },
        "exfil_event.delete.preview": {
            "suite": "content",
            "tool": "lc_preview_delete_exfil_event",
            "action": "preview",
            "resource_type": "exfil_event_rule",
            "required_inputs": ["oid", "name"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews deleting an exfil event rule.",
        },
        "exfil_watch.delete.preview": {
            "suite": "content",
            "tool": "lc_preview_delete_exfil_watch",
            "action": "preview",
            "resource_type": "exfil_watch",
            "required_inputs": ["oid", "name"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews deleting an exfil watch rule.",
        },
    }
)

OPERATION_CATALOG.update(
    {
        "feedback.channel.list": {
            "suite": "administration",
            "tool": "lc_list_feedback_channels",
            "action": "read",
            "resource_type": "feedback_channel_collection",
            "required_inputs": ["oid"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Reads ext-feedback channel configuration from the extension_config hive.",
        },
        "feedback.channel.set.preview": {
            "suite": "administration",
            "tool": "lc_preview_set_feedback_channels",
            "action": "preview",
            "resource_type": "feedback_channel_collection",
            "required_inputs": ["oid", "channels"],
            "optional_inputs": ["etag", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews replacing ext-feedback channel configuration.",
        },
        "feedback.approval.preview": {
            "suite": "response",
            "tool": "lc_preview_feedback_simple_approval",
            "action": "preview",
            "resource_type": "feedback_request",
            "required_inputs": ["oid", "channel", "question", "feedback_destination"],
            "optional_inputs": ["case_id", "playbook_name", "approved_content", "denied_content", "timeout_seconds", "timeout_choice", "timeout_content", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews sending an external approval request through ext-feedback.",
        },
        "feedback.acknowledgement.preview": {
            "suite": "response",
            "tool": "lc_preview_feedback_acknowledgement",
            "action": "preview",
            "resource_type": "feedback_request",
            "required_inputs": ["oid", "channel", "question", "feedback_destination"],
            "optional_inputs": ["case_id", "playbook_name", "acknowledged_content", "timeout_seconds", "timeout_content", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews sending an external acknowledgement request through ext-feedback.",
        },
        "feedback.question.preview": {
            "suite": "response",
            "tool": "lc_preview_feedback_question",
            "action": "preview",
            "resource_type": "feedback_request",
            "required_inputs": ["oid", "channel", "question", "feedback_destination"],
            "optional_inputs": ["case_id", "playbook_name", "timeout_seconds", "timeout_content", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews sending an external free-form question through ext-feedback.",
        },
    }
)


_SAFE_DETECT_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
_SAFE_CASE_NUMBER = re.compile(r"^[0-9]{1,20}$")
_SAFE_PERMISSION = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.:/@+=% -]{1,300}$")
_SAFE_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9_.:@+=%-]{1,300}$")
_SAFE_EXTENSION_NAME = re.compile(r"^[A-Za-z0-9_.:/@+=%-]{1,300}$")
_UNSAFE_SELECTOR = re.compile(r"[\x00-\x1f;&|`$]")
_IOC_TYPES = {"domain", "ip", "file_hash", "file_path", "file_name", "user", "service_name", "package_name"}
_INFO_TYPES = {"summary", "locations"}
_DR_NAMESPACES = {"general", "managed", "service"}
_SEARCH_STREAMS = {"event", "detect", "audit"}
_INVOICE_FORMATS = {"pdf", "csv"}
_SAFE_CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.IGNORECASE)
_VULN_SEARCH_OPS = {"is", "contains"}
_VULN_RESOLUTIONS = {"mitigated", "accepted", "false_positive"}
_VULN_SCOPES = {"org", "host"}
_VULN_SEVERITIES = {"critical", "high", "medium", "low"}
_ORG_USER_ROLES = {"Owner", "Administrator", "Operator", "Viewer", "Basic"}
_CASE_STATUSES = {"new", "in_progress", "resolved", "closed"}
_CASE_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_CASE_CLASSIFICATIONS = {"pending", "true_positive", "false_positive"}
_CASE_NOTE_TYPES = {"general", "analysis", "remediation", "escalation", "handoff", "to_stakeholder", "from_stakeholder"}
_CASE_ENTITY_TYPES = {"ip", "domain", "hash", "url", "user", "email", "file", "process", "registry", "other"}
_CASE_VERDICTS = {"malicious", "suspicious", "benign", "unknown", "informational"}
_CASE_ORDERS = {"asc", "desc"}
_EMAIL_RE = re.compile(r"^[^@\s\x00]{1,254}@[^@\s\x00]{1,253}\.[^@\s\x00]{1,63}$")
_SENSOR_DOWNLOAD_TARGETS: dict[tuple[str, str], str] = {
    ("windows", "64"): "sensor/windows/64",
    ("windows", "32"): "sensor/windows/32",
    ("windows", "arm64"): "sensor/windows/arm64",
    ("windows", "msi64"): "sensor/windows/msi64",
    ("windows", "msi32"): "sensor/windows/msi32",
    ("linux", "64"): "sensor/linux/64",
    ("linux", "deb64"): "sensor/linux/deb64",
    ("linux", "debarm64"): "sensor/linux/debarm64",
    ("linux", "alpine64"): "sensor/linux/alpine64",
    ("mac", "64"): "sensor/mac/64",
    ("mac", "arm64"): "sensor/mac/arm64",
    ("chrome", ""): "sensor/chrome",
}
_ADAPTER_DOWNLOAD_TARGETS: dict[tuple[str, str], str] = {
    ("linux", "64"): "adapter/linux/64",
    ("linux", "arm"): "adapter/linux/arm",
    ("linux", "arm64"): "adapter/linux/arm64",
    ("windows", "64"): "adapter/windows/64",
    ("mac", "64"): "adapter/mac/64",
    ("mac", "arm64"): "adapter/mac/arm64",
    ("aix", "ppc64"): "adapter/aix/ppc64",
    ("freebsd", "64"): "adapter/freebsd/64",
    ("openbsd", "64"): "adapter/openbsd/64",
    ("netbsd", "64"): "adapter/netbsd/64",
    ("solaris", "64"): "adapter/solaris/64",
}
_SUMMARY_LIST_KEYS = (
    "data",
    "items",
    "sensors",
    "detects",
    "detections",
    "cases",
    "orgs",
    "events",
    "endpoints",
    "artifacts",
    "history",
    "jobs",
    "packages",
    "users",
    "api_keys",
    "keys",
    "outputs",
    "resources",
    "extensions",
    "groups",
    "logs",
    "rules",
    "records",
    "resolutions",
    "results",
    "snapshots",
    "urls",
)
REDACTED = "[redacted]"
_SENSITIVE_RESPONSE_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "client_secret",
        "clientsecret",
        "credential",
        "credentials",
        "jwt",
        "key",
        "key_material",
        "keymaterial",
        "lc_api_key",
        "lcapikey",
        "new_key",
        "newkey",
        "one_time_key",
        "onetimekey",
        "password",
        "private_key",
        "privatekey",
        "refresh_token",
        "refreshtoken",
        "secret",
        "session_token",
        "sessiontoken",
        "token",
    }
)
_AUDIT_ONLY_SENSITIVE_KEYS = frozenset({"confirmation", "confirmation_token", "confirmationtoken"})
_SENSITIVE_TEXT_RE = re.compile(
    r"(?i)\b(api[_-]?key|authorization|client[_-]?secret|credential|jwt|password|private[_-]?key|refresh[_-]?token|secret|session[_-]?token|token)"
    r"([\"']?\s*[:=]\s*[\"']?)([^\"'\s,}]+)"
)


def default_audit_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    if base:
        return Path(base) / "limacharlie-mcp" / "audit.jsonl"
    return Path.home() / ".cache" / "limacharlie-mcp" / "audit.jsonl"


def require_oid(oid: str) -> str:
    try:
        return str(uuid.UUID(oid))
    except (TypeError, ValueError) as exc:
        raise ValidationError("oid must be a LimaCharlie organization UUID") from exc


def require_limit(limit: int, *, maximum: int = 500) -> int:
    if not isinstance(limit, int):
        raise ValidationError("limit must be an integer")
    if limit < 1 or limit > maximum:
        raise ValidationError(f"limit must be between 1 and {maximum}")
    return limit


def require_seconds(value: int, name: str, *, minimum: int, maximum: int) -> int:
    if not isinstance(value, int):
        raise ValidationError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise ValidationError(f"{name} must be between {minimum} and {maximum}")
    return value


def require_ttl_seconds(value: int) -> int:
    if not isinstance(value, int):
        raise ValidationError("ttl_seconds must be an integer")
    if value < 0 or value > 2_592_000:
        raise ValidationError("ttl_seconds must be between 0 and 2592000")
    return value


def require_unix_seconds(value: int, name: str) -> int:
    if not isinstance(value, int):
        raise ValidationError(f"{name} must be an integer unix timestamp in seconds")
    if value < 0 or value > 4_102_444_800:
        raise ValidationError(f"{name} is outside the accepted unix timestamp range")
    return value


def require_detect_id(detect_id: str) -> str:
    if not isinstance(detect_id, str) or not _SAFE_DETECT_ID.match(detect_id):
        raise ValidationError("detect_id contains unsupported characters")
    return detect_id


def require_case_number(case_number: str | int) -> str:
    if isinstance(case_number, bool):
        raise ValidationError("case_number must be a numeric case number")
    value = str(case_number)
    if not _SAFE_CASE_NUMBER.match(value):
        raise ValidationError("case_number must be a numeric case number")
    return value


def require_case_number_int(case_number: str | int) -> int:
    value = int(require_case_number(case_number))
    if value < 1:
        raise ValidationError("case_number must be greater than zero")
    return value


def require_case_numbers(case_numbers: list[str | int] | str, *, maximum: int = 200) -> list[int]:
    if isinstance(case_numbers, str):
        raw_values: list[str | int] = [value.strip() for value in case_numbers.split(",") if value.strip()]
    else:
        raw_values = case_numbers
    if not isinstance(raw_values, list) or not raw_values or len(raw_values) > maximum:
        raise ValidationError(f"case_numbers must contain between 1 and {maximum} case numbers")
    checked = [require_case_number_int(value) for value in raw_values]
    if len(set(checked)) != len(checked):
        raise ValidationError("case_numbers must not contain duplicates")
    return checked


def require_permission(permission: str) -> str:
    if not isinstance(permission, str) or not _SAFE_PERMISSION.match(permission):
        raise ValidationError("permission contains unsupported characters")
    return permission


def require_path_segment(value: str, name: str) -> str:
    if not isinstance(value, str) or not _SAFE_PATH_SEGMENT.match(value):
        raise ValidationError(f"{name} contains unsupported characters")
    return value


def require_extension_name(value: str) -> str:
    if not isinstance(value, str) or not _SAFE_EXTENSION_NAME.match(value):
        raise ValidationError("extension_name contains unsupported characters")
    return value


def require_token(value: str, name: str) -> str:
    if not isinstance(value, str) or not _SAFE_TOKEN.match(value):
        raise ValidationError(f"{name} contains unsupported characters")
    return value


def require_case_text(value: str | None, name: str, *, maximum: int = 8192, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise ValidationError(f"{name} is required")
        return None
    if not isinstance(value, str) or "\x00" in value:
        raise ValidationError(f"{name} must be a string without NUL bytes")
    stripped = value.strip()
    if required and not stripped:
        raise ValidationError(f"{name} must be non-empty")
    if len(value) > maximum:
        raise ValidationError(f"{name} must be {maximum} characters or less")
    return value


def require_case_choice(value: str | None, name: str, choices: set[str]) -> str | None:
    if value is None:
        return None
    checked = str(value).lower()
    if checked not in choices:
        raise ValidationError(f"{name} must be one of: {', '.join(sorted(choices))}")
    return checked


def require_case_choice_list(values: list[str] | str | None, name: str, choices: set[str], *, maximum: int = 20) -> list[str] | None:
    if values is None:
        return None
    raw_values = [value.strip() for value in values.split(",") if value.strip()] if isinstance(values, str) else values
    if not isinstance(raw_values, list) or not raw_values or len(raw_values) > maximum:
        raise ValidationError(f"{name} must be a non-empty list with at most {maximum} entries")
    checked = [require_case_choice(str(value), name, choices) for value in raw_values]
    return [value for value in checked if value is not None]


def require_case_tag_list(values: list[str] | str | None, name: str = "tags", *, maximum: int = 50) -> list[str] | None:
    raw_values = require_string_list(values, name, maximum=maximum)
    if raw_values is None:
        return None
    checked: list[str] = []
    seen: set[str] = set()
    for value in raw_values:
        tag = value.strip()
        if not tag:
            raise ValidationError(f"{name} entries must be non-empty")
        if len(tag) > 120:
            raise ValidationError(f"{name} entries must be 120 characters or less")
        key = tag.lower()
        if key not in seen:
            checked.append(tag)
            seen.add(key)
    return checked


def require_case_email_list(values: list[str] | str | None, name: str = "assignees", *, maximum: int = 50) -> list[str] | None:
    raw_values = require_string_list(values, name, maximum=maximum)
    if raw_values is None:
        return None
    return [require_email(value) for value in raw_values]


def require_email(value: str) -> str:
    if not isinstance(value, str) or not _EMAIL_RE.match(value):
        raise ValidationError("email must be a valid email address")
    return value


def require_org_name(value: str) -> str:
    checked = require_case_text(value, "name", maximum=120, required=True)
    assert checked is not None
    return checked


def require_config_value(value: str) -> str:
    checked = require_case_text(value, "value", maximum=20_000, required=True)
    assert checked is not None
    return checked


def require_exfil_path(path: str | list[str]) -> list[str]:
    raw_segments = path.split("/") if isinstance(path, str) else path
    if not isinstance(raw_segments, list) or not raw_segments or len(raw_segments) > 32:
        raise ValidationError("path must be a string or list with 1 to 32 segments")
    checked: list[str] = []
    for segment in raw_segments:
        if not isinstance(segment, str) or not segment or len(segment) > 120 or "\x00" in segment:
            raise ValidationError("path segments must be non-empty strings under 120 characters")
        checked.append(segment)
    return checked


def require_org_role(value: str) -> str:
    if value not in _ORG_USER_ROLES:
        raise ValidationError("role must be one of: Owner, Administrator, Operator, Viewer, Basic")
    return value


def require_quota(value: int) -> int:
    if not isinstance(value, int) or value < 0 or value > 10_000_000:
        raise ValidationError("quota must be an integer between 0 and 10000000")
    return value


def require_confirmation_token(value: str) -> str:
    if not isinstance(value, str) or not re.match(r"^mut_[a-f0-9]{32}$", value):
        raise ValidationError("confirmation_token is not a valid mutation preview token")
    return value


def require_ioc_type(obj_type: str) -> str:
    if obj_type not in _IOC_TYPES:
        raise ValidationError(f"obj_type must be one of: {', '.join(sorted(_IOC_TYPES))}")
    return obj_type


def require_info_type(info: str) -> str:
    if info not in _INFO_TYPES:
        raise ValidationError("info must be 'summary' or 'locations'")
    return info


def require_invoice_year(value: int) -> int:
    if not isinstance(value, int):
        raise ValidationError("year must be an integer")
    if value < 2020 or value > 2100:
        raise ValidationError("year must be between 2020 and 2100")
    return value


def require_invoice_month(value: int) -> int:
    if not isinstance(value, int):
        raise ValidationError("month must be an integer")
    if value < 1 or value > 12:
        raise ValidationError("month must be between 1 and 12")
    return value


def require_invoice_format(value: str | None) -> str | None:
    if value is None:
        return None
    fmt = str(value).lower()
    if fmt not in _INVOICE_FORMATS:
        raise ValidationError("fmt must be pdf or csv")
    return fmt


def require_search_query(query: str) -> str:
    if not isinstance(query, str):
        raise ValidationError("query must be a string")
    stripped = query.strip()
    if not stripped:
        raise ValidationError("query must be non-empty")
    if len(stripped) > 20_000 or "\x00" in stripped:
        raise ValidationError("query must be under 20000 characters and cannot contain NUL bytes")
    return stripped


def require_search_stream(stream: str | None) -> str | None:
    if stream is None:
        return None
    value = str(stream).lower()
    if value not in _SEARCH_STREAMS:
        raise ValidationError("stream must be event, detect, or audit")
    return value


def require_json_size(value: Any, name: str, *, maximum: int = 200_000) -> Any:
    try:
        size = len(json.dumps(value).encode())
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{name} must be JSON-serializable") from exc
    if size > maximum:
        raise ValidationError(f"{name} must serialize to {maximum} bytes or less")
    return value


def require_dict(value: dict[str, Any] | None, name: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValidationError(f"{name} must be an object")
    return require_json_size(value, name)


def require_dict_list(value: list[dict[str, Any]] | None, name: str, *, maximum: int = 100) -> list[dict[str, Any]] | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > maximum:
        raise ValidationError(f"{name} must be a list with at most {maximum} objects")
    if any(not isinstance(item, dict) for item in value):
        raise ValidationError(f"{name} must contain only objects")
    return require_json_size(value, name)


def require_ioc_batch(objects: dict[str, list[str]]) -> dict[str, list[str]]:
    if not isinstance(objects, dict) or not objects:
        raise ValidationError("objects must be a non-empty object of IOC type to string list")
    checked: dict[str, list[str]] = {}
    total = 0
    for key, values in objects.items():
        obj_type = require_ioc_type(str(key))
        if not isinstance(values, list) or not values:
            raise ValidationError("each objects entry must be a non-empty list")
        if len(values) > 100:
            raise ValidationError("each objects entry may contain at most 100 indicators")
        checked_values: list[str] = []
        for value in values:
            if not isinstance(value, str) or not value or len(value) > 500 or "\x00" in value:
                raise ValidationError("IOC values must be non-empty strings under 500 characters")
            checked_values.append(value)
        checked[obj_type] = checked_values
        total += len(checked_values)
    if total > 500:
        raise ValidationError("objects may contain at most 500 total indicators")
    return checked


def require_arl(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 2000 or "\x00" in value:
        raise ValidationError("arl_url must be a non-empty string under 2000 characters")
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value):
        raise ValidationError("arl_url must include a URL scheme")
    return value


def require_sensor_tasks(tasks: str | list[str]) -> list[str]:
    raw_tasks = [tasks] if isinstance(tasks, str) else tasks
    if not isinstance(raw_tasks, list) or not raw_tasks:
        raise ValidationError("tasks must be a non-empty string or list of strings")
    if len(raw_tasks) > 20:
        raise ValidationError("tasks may contain at most 20 commands")
    checked: list[str] = []
    total = 0
    for task in raw_tasks:
        if not isinstance(task, str) or not task.strip() or "\x00" in task:
            raise ValidationError("each task must be a non-empty string without NUL bytes")
        encoded_size = len(task.encode())
        if encoded_size > 4000:
            raise ValidationError("each task must be 4000 bytes or less")
        total += encoded_size
        checked.append(task)
    if total > 20_000:
        raise ValidationError("tasks must be 20000 total bytes or less")
    return checked


def require_string_list(values: list[str] | str | None, name: str, *, maximum: int = 100) -> list[str] | None:
    if values is None:
        return None
    raw_values = [values] if isinstance(values, str) else values
    if not isinstance(raw_values, list) or len(raw_values) > maximum:
        raise ValidationError(f"{name} must be a string or list of at most {maximum} strings")
    checked: list[str] = []
    for value in raw_values:
        if not isinstance(value, str) or not value or len(value) > 1000 or "\x00" in value:
            raise ValidationError(f"{name} entries must be non-empty strings under 1000 characters")
        checked.append(value)
    return checked


def require_permission_list(values: list[str] | str, name: str = "permissions", *, maximum: int = 100) -> list[str]:
    checked = require_string_list(values, name, maximum=maximum)
    if not checked:
        raise ValidationError(f"{name} must include at least one permission")
    return [require_permission(value) for value in checked]


def require_retention_days(value: int | None) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or value < 1 or value > 3650:
        raise ValidationError("retention_days must be between 1 and 3650")
    return value


def require_cve(value: str) -> str:
    if not isinstance(value, str) or not _SAFE_CVE.match(value):
        raise ValidationError("cve must look like CVE-YYYY-NNNN")
    return value.upper()


def require_days(value: int, *, maximum: int = 365) -> int:
    if not isinstance(value, int):
        raise ValidationError("days must be an integer")
    if value < 1 or value > maximum:
        raise ValidationError(f"days must be between 1 and {maximum}")
    return value


def require_bool_or_none(value: bool | None, name: str) -> bool | None:
    if value is None or isinstance(value, bool):
        return value
    raise ValidationError(f"{name} must be a boolean")


def require_vuln_search(search: dict[str, Any] | None) -> dict[str, Any] | None:
    if search is None:
        return None
    if not isinstance(search, dict):
        raise ValidationError("search must be an object")
    field = require_token(str(search.get("field", "")), "search.field")
    op = str(search.get("op", "")).lower()
    if op not in _VULN_SEARCH_OPS:
        raise ValidationError("search.op must be is or contains")
    value = search.get("value")
    if not isinstance(value, str) or not value or len(value) > 300 or "\x00" in value:
        raise ValidationError("search.value must be a non-empty string under 300 characters")
    return {"field": field, "op": op, "value": value}


def require_vuln_filters(filters: dict[str, list[str]] | None) -> dict[str, list[str]] | None:
    if filters is None:
        return None
    if not isinstance(filters, dict):
        raise ValidationError("filters must be an object of field names to string arrays")
    checked: dict[str, list[str]] = {}
    for key, values in filters.items():
        safe_key = require_token(str(key), "filter key")
        if not isinstance(values, list) or not values:
            raise ValidationError("each filter value must be a non-empty list")
        checked[safe_key] = [require_token(str(value), f"filter {safe_key}") for value in values]
    return checked


def require_vuln_resolutions(resolutions: list[str] | None) -> list[str] | None:
    if resolutions is None:
        return None
    if not isinstance(resolutions, list) or not resolutions:
        raise ValidationError("resolutions must be a non-empty list")
    checked = [str(value).lower() for value in resolutions]
    if any(value not in _VULN_RESOLUTIONS for value in checked):
        raise ValidationError("resolutions must contain only mitigated, accepted, or false_positive")
    return checked


def require_vuln_severities(severities: list[str] | None) -> list[str] | None:
    if severities is None:
        return None
    if not isinstance(severities, list) or not severities:
        raise ValidationError("severities must be a non-empty list")
    checked = [str(value).lower() for value in severities]
    if any(value not in _VULN_SEVERITIES for value in checked):
        raise ValidationError("severities must contain only critical, high, medium, or low")
    return checked


def require_dr_namespace(namespace: str | None) -> str:
    value = namespace or "general"
    if value not in _DR_NAMESPACES:
        raise ValidationError("namespace must be general, managed, or service")
    return value


def require_selector(selector: str | None) -> str | None:
    if selector is None:
        return None
    if not isinstance(selector, str) or not selector or len(selector) > 300 or _UNSAFE_SELECTOR.search(selector):
        raise ValidationError("selector contains unsupported characters")
    return selector


def require_time_window(start: int, end: int) -> tuple[int, int]:
    start_ts = require_unix_seconds(start, "start")
    end_ts = require_unix_seconds(end, "end")
    if end_ts <= start_ts:
        raise ValidationError("end must be greater than start")
    return start_ts, end_ts


def bool_param(value: bool) -> str:
    return "true" if value else "false"


def service_request_params(data: dict[str, Any], *, is_async: bool = False) -> dict[str, Any]:
    return {
        "request_data": base64.b64encode(json.dumps(data).encode()).decode(),
        "is_async": is_async,
    }


def extension_request_params(oid: str, action: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "oid": oid,
        "action": action,
        "gzdata": base64.b64encode(gzip.compress(json.dumps(data).encode())).decode(),
    }


def bound_output(data: Any, limit: int) -> tuple[Any, bool]:
    if isinstance(data, list):
        return data[:limit], len(data) > limit
    if isinstance(data, dict):
        bounded = dict(data)
        truncated = False
        for key in _SUMMARY_LIST_KEYS:
            value = bounded.get(key)
            if isinstance(value, list) and len(value) > limit:
                bounded[key] = value[:limit]
                truncated = True
        return bounded, truncated
    return data, False


def _sensitive_key_variants(key: str) -> tuple[str, str]:
    normalized = re.sub(r"[^a-z0-9]+", "_", key.strip().lower()).strip("_")
    return normalized, normalized.replace("_", "")


def is_sensitive_response_key(key: str, *, extra_keys: frozenset[str] = frozenset()) -> bool:
    normalized, compact = _sensitive_key_variants(key)
    if normalized in extra_keys or compact in extra_keys:
        return True
    if normalized in _SENSITIVE_RESPONSE_KEYS or compact in _SENSITIVE_RESPONSE_KEYS:
        return True
    return normalized.endswith("_secret") or normalized.endswith("_api_key") or normalized.endswith("_private_key")


def redact_sensitive(data: Any, *, extra_keys: frozenset[str] = frozenset()) -> Any:
    if isinstance(data, dict):
        redacted: dict[str, Any] = {}
        for key, value in data.items():
            if is_sensitive_response_key(str(key), extra_keys=extra_keys) and value is not None:
                redacted[key] = REDACTED
            else:
                redacted[key] = redact_sensitive(value, extra_keys=extra_keys)
        return redacted
    if isinstance(data, list):
        return [redact_sensitive(item, extra_keys=extra_keys) for item in data]
    return data


def redact_text(text: str) -> str:
    return _SENSITIVE_TEXT_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", text)


def redacted_response_excerpt(data: Any, raw_text: str) -> str:
    redacted = redact_sensitive(data, extra_keys=_AUDIT_ONLY_SENSITIVE_KEYS)
    if redacted is not None and not isinstance(redacted, str):
        try:
            return json.dumps(redacted, sort_keys=True, default=str)[:500]
        except (TypeError, ValueError):
            pass
    return redact_text(raw_text or str(redacted or ""))[:500]


def observed_at() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def summarize_data(data: Any) -> dict[str, Any]:
    if isinstance(data, list):
        return {"shape": "list", "count": len(data)}
    if isinstance(data, dict):
        summary: dict[str, Any] = {"shape": "object"}
        for key in _SUMMARY_LIST_KEYS:
            value = data.get(key)
            if isinstance(value, list):
                summary[f"{key}_count"] = len(value)
            elif isinstance(value, dict):
                summary[f"{key}_count"] = len(value)
        for key in ("detect_id", "sid", "case_number", "uid", "next_cursor", "job_id", "iid"):
            if key in data:
                summary[key] = data[key]
        return summary
    if data is None:
        return {"shape": "empty"}
    return {"shape": type(data).__name__}


def normalize_api_data(data: Any) -> Any:
    if not isinstance(data, dict):
        return data
    normalized = dict(data)
    for key in ("events", "detects", "jobs"):
        value = normalized.get(key)
        if isinstance(value, str) and value:
            try:
                normalized[key] = json.loads(zlib.decompress(base64.b64decode(value), 16 + zlib.MAX_WBITS).decode())
            except Exception:
                normalized.setdefault("warnings", [])
                if isinstance(normalized["warnings"], list):
                    normalized["warnings"].append(f"{key} field could not be decompressed")
    return normalized


def normalize_job_state(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {"current": "unknown", "terminal": False}
    raw_state = str(data.get("state") or data.get("status") or "").lower()
    is_done = bool(data.get("is_done") or data.get("completed") or data.get("done"))
    error = data.get("error") or data.get("last_error")
    if error or raw_state in {"failed", "failure", "error", "errored"}:
        current = "failed"
        terminal = True
    elif is_done or raw_state in {"succeeded", "success", "complete", "completed", "done"}:
        current = "succeeded"
        terminal = True
    elif raw_state in {"pending", "queued"}:
        current = "pending"
        terminal = False
    elif raw_state in {"running", "started", "in_progress"}:
        current = "running"
        terminal = False
    else:
        current = "unknown"
        terminal = False
    return {"current": current, "terminal": terminal}


def classify_error(status_code: int | None, data: Any, raw_text: str) -> dict[str, Any]:
    message = error_text(data, raw_text)
    if status_code in (401, 403):
        error_class = "auth" if status_code == 401 else "policy"
        code = "unauthorized" if status_code == 401 else "forbidden"
        retryable = False
        next_actions = ["Verify LC_API_KEY and org scope.", "Check the required LimaCharlie permission for this operation."]
    elif status_code == 404:
        error_class = "not_found"
        code = "resource_not_found"
        retryable = False
        next_actions = ["List the resource collection.", "Retry with a valid resource id in the same org."]
    elif status_code == 409:
        error_class = "conflict"
        code = "resource_conflict"
        retryable = False
        next_actions = ["Inspect current resource state.", "Retry only after resolving the conflicting state."]
    elif status_code == 429:
        error_class = "capacity"
        code = "rate_limited"
        retryable = True
        next_actions = ["Wait before retrying.", "Reduce limit or query window size."]
    elif status_code is not None and 500 <= status_code <= 599:
        error_class = "transient"
        code = "upstream_error"
        retryable = True
        next_actions = ["Retry with the same input after a short delay.", "If repeated, narrow the query or check LimaCharlie service status."]
    else:
        error_class = "internal"
        code = "request_failed"
        retryable = False
        next_actions = ["Inspect the returned message.", "Retry only after changing the input or credentials if indicated."]
    return {
        "code": code,
        "class": error_class,
        "message": message,
        "retryable": retryable,
        "same_input_retryable": retryable,
        "suggested_next_actions": next_actions,
    }


def error_text(data: Any, raw_text: str) -> str:
    if isinstance(data, dict):
        for key in ("error", "message", "error_message"):
            value = data.get(key)
            if value:
                return str(value)
    if isinstance(data, str) and data:
        return data
    return raw_text or "LimaCharlie API returned an error"


class LimaCharlieAPI:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        uid: str | None = None,
        api_root: str | None = None,
        jwt_root: str | None = None,
        cases_root: str | None = None,
        timeout_seconds: float | None = None,
        audit_path: Path | None = None,
        http_client: HttpClient | None = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("LC_API_KEY")
        self.uid = uid or os.environ.get("LC_UID")
        self.api_root = (api_root or os.environ.get("LC_API_ROOT") or "https://api.limacharlie.io").rstrip("/")
        self.jwt_root = (jwt_root or os.environ.get("LC_JWT_ROOT") or "https://jwt.limacharlie.io").rstrip("/")
        self.cases_root = (cases_root or os.environ.get("LC_CASES_API_ROOT") or "https://cases.limacharlie.io").rstrip("/")
        self.timeout_seconds = timeout_seconds or float(os.environ.get("LC_MCP_TIMEOUT_SECONDS", "30"))
        self.audit_path = audit_path or Path(os.environ.get("LC_MCP_AUDIT_LOG", default_audit_path()))
        self.http: HttpClient = http_client or httpx.Client()
        self._tokens: dict[str, Token] = {}
        self._pending_mutations: dict[str, PendingMutation] = {}
        self._search_roots: dict[str, str] = {}

    def auth_whoami(self, oid: str | None = None, check_perm: str | None = None) -> dict[str, Any]:
        scoped_oid = require_oid(oid) if oid else "-"
        if check_perm:
            if not scoped_oid:
                raise ValidationError("check_perm requires an explicit oid")
            if scoped_oid == "-":
                raise ValidationError("check_perm requires an explicit oid")
            safe_perm = require_permission(check_perm)
        response = self._request(
            "GET",
            "who",
            operation="auth.whoami",
            oid=scoped_oid,
            resource={"type": "identity", "id": scoped_oid},
        ).as_dict()
        if check_perm and response["ok"]:
            data = response.get("data") or {}
            all_perms: list[str] = []
            raw = data.get("perms", []) if isinstance(data, dict) else []
            if isinstance(raw, list):
                all_perms.extend(str(perm) for perm in raw)
            raw_user = data.get("user_perms", {}) if isinstance(data, dict) else {}
            if isinstance(raw_user, dict):
                for value in raw_user.values():
                    if isinstance(value, list):
                        all_perms.extend(str(perm) for perm in value)
            response["data"] = {"perm": safe_perm, "has_perm": safe_perm in all_perms}
        return response

    def auth_status(self, oid: str | None = None) -> dict[str, Any]:
        scoped_oid = require_oid(oid) if oid else "-"
        token = self._tokens.get(scoped_oid)
        now = time.time()
        expires_in = int(token.expires_at - now) if token else None
        credential_mode = "user_api_key" if self.uid else "org_api_key"
        warnings: list[str] = []
        if not self.api_key:
            warnings.append("LC_API_KEY is not configured.")
        if self.uid and scoped_oid == "-":
            warnings.append("User API key mode can produce large multi-org JWTs; pass oid for org-scoped refresh if needed.")
        return ToolResponse(
            ok=bool(self.api_key),
            operation="auth.status",
            request_id=f"req_{uuid.uuid4().hex}",
            resource={"type": "auth_session", "id": scoped_oid},
            state={
                "current": "configured" if self.api_key else "missing_credentials",
                "credential_mode": credential_mode,
                "jwt_cached": token is not None,
                "jwt_expires_in_seconds": max(0, expires_in) if expires_in is not None else None,
            },
            data={
                "credential_mode": credential_mode,
                "uses_limacharlie_jwt_exchange": True,
                "jwt_managed_by_server": True,
                "jwt_cached": token is not None,
                "jwt_expires_in_seconds": max(0, expires_in) if expires_in is not None else None,
                "configured": {
                    "api_key": bool(self.api_key),
                    "uid": bool(self.uid),
                    "api_root": self.api_root,
                    "jwt_root": self.jwt_root,
                    "cases_root": self.cases_root,
                },
            },
            side_effects=[],
            warnings=warnings,
            meta={
                "summary": {
                    "credential_mode": credential_mode,
                    "jwt_cached": token is not None,
                    "configured": bool(self.api_key),
                },
                "truncated": False,
            },
            observed_at=observed_at(),
            error=None
            if self.api_key
            else {
                "code": "missing_credentials",
                "class": "auth",
                "message": "LC_API_KEY is required for direct API authentication.",
                "retryable": False,
                "same_input_retryable": False,
                "suggested_next_actions": [
                    "Set LC_API_KEY to an organization API key for single-org use.",
                    "Set LC_UID plus LC_API_KEY for user API key mode.",
                ],
            },
        ).as_dict()

    def auth_refresh(self, oid: str | None = None) -> dict[str, Any]:
        scoped_oid = require_oid(oid) if oid else "-"
        started = time.time()
        request_id = f"req_{uuid.uuid4().hex}"
        self._tokens.pop(scoped_oid, None)
        try:
            self._get_jwt(scoped_oid, force_refresh=True)
        except Exception as exc:
            duration_ms = int((time.time() - started) * 1000)
            return ToolResponse(
                ok=False,
                operation="auth.refresh",
                request_id=request_id,
                resource={"type": "auth_session", "id": scoped_oid},
                state={"current": "refresh_failed"},
                data=None,
                side_effects=[],
                warnings=[],
                meta={"duration_ms": duration_ms, "summary": {"shape": "empty"}, "truncated": False},
                observed_at=observed_at(),
                error=classify_error(None, None, str(exc)),
            ).as_dict()
        token = self._tokens[scoped_oid]
        duration_ms = int((time.time() - started) * 1000)
        return ToolResponse(
            ok=True,
            operation="auth.refresh",
            request_id=request_id,
            resource={"type": "auth_session", "id": scoped_oid},
            state={"previous": "unknown_or_expiring", "current": "refreshed"},
            data={
                "credential_mode": "user_api_key" if self.uid else "org_api_key",
                "jwt_managed_by_server": True,
                "jwt_cached": True,
                "jwt_expires_in_seconds": max(0, int(token.expires_at - time.time())),
            },
            side_effects=[{"type": "local_jwt_cache_refresh", "resource": {"type": "auth_session", "id": scoped_oid}}],
            warnings=[],
            meta={
                "duration_ms": duration_ms,
                "summary": {"jwt_cached": True, "credential_mode": "user_api_key" if self.uid else "org_api_key"},
                "truncated": False,
            },
            observed_at=observed_at(),
        ).as_dict()

    def list_orgs(self) -> dict[str, Any]:
        return self._request(
            "GET",
            "user/orgs",
            operation="org.list",
            oid="-",
            resource={"type": "organization_collection", "id": "-"},
        ).as_dict()

    def tool_catalog(self) -> dict[str, Any]:
        return ToolResponse(
            ok=True,
            operation="tool.catalog",
            request_id=f"req_{uuid.uuid4().hex}",
            resource={"type": "tool_surface", "id": "limacharlie-mcp"},
            state={},
            data={
                "server": "limacharlie-mcp",
                "transport": "stdio",
                "auth": "direct_api_jwt_exchange",
                "default_mode": "read_only",
                "operations": OPERATION_CATALOG,
            },
            side_effects=[],
            warnings=[],
            meta={
                "summary": {"operation_count": len(OPERATION_CATALOG)},
                "truncated": False,
            },
            observed_at=observed_at(),
        ).as_dict()

    def list_sensor_download_targets(self) -> dict[str, Any]:
        return self._local_response(
            "download.sensor_targets.list",
            {"targets": self._download_targets(_SENSOR_DOWNLOAD_TARGETS)},
            resource={"type": "download_target_collection", "id": "sensor"},
        )

    def list_adapter_download_targets(self) -> dict[str, Any]:
        return self._local_response(
            "download.adapter_targets.list",
            {"targets": self._download_targets(_ADAPTER_DOWNLOAD_TARGETS)},
            resource={"type": "download_target_collection", "id": "adapter"},
        )

    def list_sensors(self, oid: str, selector: str | None = None, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        params: dict[str, Any] = {"limit": bounded_limit}
        safe_selector = require_selector(selector)
        if safe_selector:
            params["selector"] = safe_selector
        return self._request(
            "GET",
            f"sensors/{scoped_oid}",
            operation="sensor.list",
            oid=scoped_oid,
            resource={"type": "sensor_collection", "id": scoped_oid},
            params=params,
            limit=bounded_limit,
        ).as_dict()

    def get_sensor(self, oid: str, sensor_id: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        return self._request(
            "GET",
            safe_sensor_id,
            operation="sensor.get",
            oid=scoped_oid,
            resource={"type": "sensor", "id": safe_sensor_id, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def preview_sensor_task(
        self,
        oid: str,
        sensor_id: str,
        tasks: str | list[str],
        investigation_id: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        checked_tasks = require_sensor_tasks(tasks)
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        data: dict[str, Any] = {"tasks": checked_tasks}
        if investigation_id:
            data["investigation_id"] = require_token(investigation_id, "investigation_id")
        return self._create_mutation_preview(
            operation="sensor.task",
            oid=scoped_oid,
            method="POST",
            path=safe_sensor_id,
            resource={"type": "sensor_task", "id": safe_sensor_id, "parent": {"type": "organization", "id": scoped_oid}},
            params=data,
            data=None,
            json_body=None,
            expected_effect=f"Queue {len(checked_tasks)} task command(s) on sensor {safe_sensor_id}.",
            reversibility="Tasking is not generally reversible; inspect job/task output and issue compensating commands if needed.",
            side_effects=[{"type": "sensor_task_queued", "resource": {"type": "sensor", "id": safe_sensor_id}, "task_count": len(checked_tasks)}],
            token_ttl_seconds=token_ttl,
        )

    def preview_isolate_sensor(self, oid: str, sensor_id: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._sensor_state_preview(
            operation="sensor.isolate",
            oid=oid,
            sensor_id=sensor_id,
            method="POST",
            path_suffix="isolation",
            resource_type="sensor_isolation",
            expected_effect="Enable network isolation on the sensor.",
            reversibility="Call lc_preview_rejoin_sensor and confirm it to remove isolation.",
            side_effect_type="sensor_isolated",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_rejoin_sensor(self, oid: str, sensor_id: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._sensor_state_preview(
            operation="sensor.rejoin",
            oid=oid,
            sensor_id=sensor_id,
            method="DELETE",
            path_suffix="isolation",
            resource_type="sensor_isolation",
            expected_effect="Remove network isolation from the sensor.",
            reversibility="Call lc_preview_isolate_sensor and confirm it to isolate again.",
            side_effect_type="sensor_rejoined",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_seal_sensor(self, oid: str, sensor_id: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._sensor_state_preview(
            operation="sensor.seal",
            oid=oid,
            sensor_id=sensor_id,
            method="POST",
            path_suffix="seal",
            resource_type="sensor_seal",
            expected_effect="Seal the sensor against uninstall.",
            reversibility="Call lc_preview_unseal_sensor and confirm it to unseal.",
            side_effect_type="sensor_sealed",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_unseal_sensor(self, oid: str, sensor_id: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._sensor_state_preview(
            operation="sensor.unseal",
            oid=oid,
            sensor_id=sensor_id,
            method="DELETE",
            path_suffix="seal",
            resource_type="sensor_seal",
            expected_effect="Unseal the sensor.",
            reversibility="Call lc_preview_seal_sensor and confirm it to seal again.",
            side_effect_type="sensor_unsealed",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_sensor(self, oid: str, sensor_id: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation="sensor.delete",
            oid=scoped_oid,
            method="DELETE",
            path=safe_sensor_id,
            resource={"type": "sensor", "id": safe_sensor_id, "parent": {"type": "organization", "id": scoped_oid}},
            data=None,
            json_body=None,
            expected_effect=f"Delete sensor record {safe_sensor_id}.",
            reversibility="Deletion may require reinstalling or re-enrolling the sensor.",
            side_effects=[{"type": "sensor_deleted", "resource": {"type": "sensor", "id": safe_sensor_id}}],
            token_ttl_seconds=token_ttl,
        )

    def list_online_sensors(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"online/{scoped_oid}",
            operation="sensor.online.list",
            oid=scoped_oid,
            resource={"type": "online_sensor_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def list_detections(
        self,
        oid: str,
        start: int,
        end: int,
        limit: int = 100,
        cursor: str = "-",
        category: str | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        start_ts, end_ts = require_time_window(start, end)
        params: dict[str, Any] = {
            "start": start_ts,
            "end": end_ts,
            "cursor": require_token(cursor, "cursor"),
            "is_compressed": "true",
            "limit": bounded_limit,
        }
        if category:
            params["cat"] = require_token(category, "category")
        return self._request(
            "GET",
            f"insight/{scoped_oid}/detections",
            operation="detection.list",
            oid=scoped_oid,
            resource={"type": "detection_collection", "id": scoped_oid},
            params=params,
            limit=bounded_limit,
        ).as_dict()

    def get_detection(self, oid: str, detect_id: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_detect_id = require_detect_id(detect_id)
        return self._request(
            "GET",
            f"insight/{scoped_oid}/detections/{safe_detect_id}",
            operation="detection.get",
            oid=scoped_oid,
            resource={"type": "detection", "id": safe_detect_id, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def _case_resource(self, oid: str, case_number: str | int, resource_type: str = "case") -> dict[str, Any]:
        return {"type": resource_type, "id": require_case_number(case_number), "parent": {"type": "organization", "id": oid}}

    def _case_update_body(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        assignees: list[str] | str | None = None,
        classification: str | None = None,
        summary: str | None = None,
        conclusion: str | None = None,
        tags: list[str] | str | None = None,
        require_non_empty: bool = True,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        checked_status = require_case_choice(status, "status", _CASE_STATUSES)
        if checked_status is not None:
            body["status"] = checked_status
        checked_severity = require_case_choice(severity, "severity", _CASE_SEVERITIES)
        if checked_severity is not None:
            body["severity"] = checked_severity
        checked_assignees = require_case_email_list(assignees)
        if checked_assignees is not None:
            body["assignees"] = checked_assignees
        checked_classification = require_case_choice(classification, "classification", _CASE_CLASSIFICATIONS)
        if checked_classification is not None:
            body["classification"] = checked_classification
        checked_summary = require_case_text(summary, "summary")
        if checked_summary is not None:
            body["summary"] = checked_summary
        checked_conclusion = require_case_text(conclusion, "conclusion")
        if checked_conclusion is not None:
            body["conclusion"] = checked_conclusion
        checked_tags = require_case_tag_list(tags)
        if checked_tags is not None:
            body["tags"] = checked_tags
        if require_non_empty and not body:
            raise ValidationError("at least one case update field is required")
        return body

    def _preview_case_api_mutation(
        self,
        *,
        operation: str,
        oid: str,
        method: str,
        path: str,
        resource_type: str,
        resource_id: str,
        params: dict[str, Any] | None = None,
        json_body: Any | None = None,
        expected_effect: str,
        reversibility: str,
        side_effect_type: str,
        token_ttl_seconds: int,
    ) -> dict[str, Any]:
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation=operation,
            oid=oid,
            method=method,
            path=f"api/v1/{path.lstrip('/')}",
            resource={"type": resource_type, "id": resource_id, "parent": {"type": "organization", "id": oid}},
            params=params,
            data=None,
            json_body=json_body,
            expected_effect=expected_effect,
            reversibility=reversibility,
            side_effects=[{"type": side_effect_type, "resource": {"type": resource_type, "id": resource_id}}],
            token_ttl_seconds=token_ttl,
            base_url=self.cases_root,
        )

    def list_cases(
        self,
        oid: str,
        status: list[str] | str | None = None,
        severity: list[str] | str | None = None,
        classification: list[str] | str | None = None,
        assignee: str | None = None,
        search: str | None = None,
        sensor_id: str | None = None,
        tags: list[str] | str | None = None,
        sort: str | None = None,
        order: str | None = None,
        limit: int = 100,
        page_token: str | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit, maximum=200)
        params: dict[str, Any] = {"oids": scoped_oid, "page_size": bounded_limit}
        checked_status = require_case_choice_list(status, "status", _CASE_STATUSES)
        if checked_status:
            params["status"] = ",".join(checked_status)
        checked_severity = require_case_choice_list(severity, "severity", _CASE_SEVERITIES)
        if checked_severity:
            params["severity"] = ",".join(checked_severity)
        checked_classification = require_case_choice_list(classification, "classification", _CASE_CLASSIFICATIONS)
        if checked_classification:
            params["classification"] = ",".join(checked_classification)
        if assignee:
            params["assignee"] = require_email(assignee)
        checked_search = require_case_text(search, "search", maximum=500)
        if checked_search:
            params["search"] = checked_search
        if sensor_id:
            params["sid"] = require_oid(sensor_id)
        checked_tags = require_case_tag_list(tags, "tags")
        if checked_tags:
            params["tag"] = ",".join(checked_tags)
        if sort:
            params["sort"] = require_token(sort, "sort")
        if order:
            params["order"] = require_case_choice(order, "order", _CASE_ORDERS)
        if page_token:
            params["page_token"] = require_token(page_token, "page_token")
        return self._request(
            "GET",
            "api/v1/cases",
            operation="case.list",
            oid=scoped_oid,
            resource={"type": "case_collection", "id": scoped_oid},
            params=params,
            limit=bounded_limit,
            base_url=self.cases_root,
        ).as_dict()

    def get_case(self, oid: str, case_number: str | int) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        return self._request(
            "GET",
            f"api/v1/cases/{safe_case_number}",
            operation="case.get",
            oid=scoped_oid,
            resource=self._case_resource(scoped_oid, safe_case_number),
            params={"oid": scoped_oid},
            base_url=self.cases_root,
        ).as_dict()

    def preview_create_case(
        self,
        oid: str,
        detection: dict[str, Any] | None = None,
        severity: str | None = None,
        summary: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        data: dict[str, Any] = {}
        checked_detection = require_dict(detection, "detection")
        if checked_detection is not None:
            data["detection"] = checked_detection
        checked_severity = require_case_choice(severity, "severity", _CASE_SEVERITIES)
        if checked_severity is not None:
            data["severity"] = checked_severity
        checked_summary = require_case_text(summary, "summary")
        if checked_summary is not None:
            data["summary"] = checked_summary
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation="case.create",
            oid=scoped_oid,
            method="POST",
            path="extension/request/ext-cases",
            resource={"type": "case", "id": "new", "parent": {"type": "organization", "id": scoped_oid}},
            params=extension_request_params(scoped_oid, "create_case", data),
            data=None,
            json_body=None,
            expected_effect="Create a new LimaCharlie case through ext-cases.",
            reversibility="Close or merge the case if it was created unintentionally.",
            side_effects=[{"type": "case_created", "resource": {"type": "case", "id": "new"}}],
            token_ttl_seconds=token_ttl,
        )

    def preview_update_case(
        self,
        oid: str,
        case_number: str | int,
        status: str | None = None,
        severity: str | None = None,
        assignees: list[str] | str | None = None,
        classification: str | None = None,
        summary: str | None = None,
        conclusion: str | None = None,
        tags: list[str] | str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        body = self._case_update_body(
            status=status,
            severity=severity,
            assignees=assignees,
            classification=classification,
            summary=summary,
            conclusion=conclusion,
            tags=tags,
        )
        return self._preview_case_api_mutation(
            operation="case.update",
            oid=scoped_oid,
            method="PATCH",
            path=f"cases/{safe_case_number}",
            resource_type="case",
            resource_id=safe_case_number,
            params={"oid": scoped_oid},
            json_body=body,
            expected_effect=f"Update case {safe_case_number}.",
            reversibility="Apply another case update to restore the previous values if needed.",
            side_effect_type="case_updated",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_add_case_note(
        self,
        oid: str,
        case_number: str | int,
        content: str,
        note_type: str | None = None,
        is_public: bool | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        body: dict[str, Any] = {"content": require_case_text(content, "content", required=True)}
        checked_note_type = require_case_choice(note_type, "note_type", _CASE_NOTE_TYPES)
        if checked_note_type is not None:
            body["note_type"] = checked_note_type
        if is_public is not None:
            body["is_public"] = require_bool_or_none(is_public, "is_public")
        return self._preview_case_api_mutation(
            operation="case.note.add",
            oid=scoped_oid,
            method="POST",
            path=f"cases/{safe_case_number}/notes",
            resource_type="case_note",
            resource_id=safe_case_number,
            params={"oid": scoped_oid},
            json_body=body,
            expected_effect=f"Add a note to case {safe_case_number}.",
            reversibility="Delete or update the note visibility through the Cases UI/API if it was unintended.",
            side_effect_type="case_note_added",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_update_case_note_visibility(
        self,
        oid: str,
        case_number: str | int,
        event_id: str,
        is_public: bool,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        safe_event_id = require_path_segment(event_id, "event_id")
        return self._preview_case_api_mutation(
            operation="case.note.visibility",
            oid=scoped_oid,
            method="PATCH",
            path=f"cases/{safe_case_number}/notes/{quote(safe_event_id, safe='')}",
            resource_type="case_note",
            resource_id=safe_event_id,
            params={"oid": scoped_oid},
            json_body={"is_public": require_bool_or_none(is_public, "is_public")},
            expected_effect=f"Set public visibility on note {safe_event_id} for case {safe_case_number}.",
            reversibility="Run the same preview with the opposite is_public value.",
            side_effect_type="case_note_visibility_updated",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_bulk_update_cases(
        self,
        oid: str,
        case_numbers: list[str | int] | str,
        status: str | None = None,
        severity: str | None = None,
        assignees: list[str] | str | None = None,
        classification: str | None = None,
        summary: str | None = None,
        conclusion: str | None = None,
        tags: list[str] | str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        checked_case_numbers = require_case_numbers(case_numbers)
        update = self._case_update_body(
            status=status,
            severity=severity,
            assignees=assignees,
            classification=classification,
            summary=summary,
            conclusion=conclusion,
            tags=tags,
        )
        return self._preview_case_api_mutation(
            operation="case.bulk_update",
            oid=scoped_oid,
            method="POST",
            path="cases/bulk-update",
            resource_type="case_collection",
            resource_id=scoped_oid,
            json_body={"oid": scoped_oid, "case_numbers": checked_case_numbers, "update": update},
            expected_effect=f"Bulk update {len(checked_case_numbers)} cases.",
            reversibility="Bulk apply another update with prior values if needed.",
            side_effect_type="case_collection_updated",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_merge_cases(
        self,
        oid: str,
        target_case_number: str | int,
        source_case_numbers: list[str | int] | str,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        target = require_case_number_int(target_case_number)
        sources = require_case_numbers(source_case_numbers)
        if target in sources:
            raise ValidationError("target_case_number must not also be in source_case_numbers")
        return self._preview_case_api_mutation(
            operation="case.merge",
            oid=scoped_oid,
            method="POST",
            path="cases/merge",
            resource_type="case_merge",
            resource_id=str(target),
            json_body={"oid": scoped_oid, "target_case_number": target, "source_case_numbers": sources},
            expected_effect=f"Merge {len(sources)} source cases into case {target}.",
            reversibility="Case merge is not generally reversible; export source cases first if preservation is needed.",
            side_effect_type="cases_merged",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_case_detections(self, oid: str, case_number: str | int) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        return self._request(
            "GET",
            f"api/v1/cases/{safe_case_number}/detections",
            operation="case.detection.list",
            oid=scoped_oid,
            resource=self._case_resource(scoped_oid, safe_case_number, "case_detection_collection"),
            params={"oid": scoped_oid},
            base_url=self.cases_root,
        ).as_dict()

    def preview_add_case_detection(
        self,
        oid: str,
        case_number: str | int,
        detection: dict[str, Any],
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        checked_detection = require_dict(detection, "detection")
        if checked_detection is None:
            raise ValidationError("detection is required")
        return self._preview_case_api_mutation(
            operation="case.detection.add",
            oid=scoped_oid,
            method="POST",
            path=f"cases/{safe_case_number}/detections",
            resource_type="case_detection",
            resource_id=safe_case_number,
            params={"oid": scoped_oid},
            json_body={"detection": checked_detection},
            expected_effect=f"Link a detection to case {safe_case_number}.",
            reversibility="Remove the detection link from the case if it was unintended.",
            side_effect_type="case_detection_added",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_remove_case_detection(
        self,
        oid: str,
        case_number: str | int,
        detection_id: str,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        safe_detection_id = require_detect_id(detection_id)
        return self._preview_case_api_mutation(
            operation="case.detection.remove",
            oid=scoped_oid,
            method="DELETE",
            path=f"cases/{safe_case_number}/detections/{quote(safe_detection_id, safe='')}",
            resource_type="case_detection",
            resource_id=safe_detection_id,
            params={"oid": scoped_oid},
            expected_effect=f"Remove detection {safe_detection_id} from case {safe_case_number}.",
            reversibility="Add the detection to the case again if removal was unintended.",
            side_effect_type="case_detection_removed",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_case_entities(self, oid: str, case_number: str | int) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        return self._request(
            "GET",
            f"api/v1/cases/{safe_case_number}/entities",
            operation="case.entity.list",
            oid=scoped_oid,
            resource=self._case_resource(scoped_oid, safe_case_number, "case_entity_collection"),
            params={"oid": scoped_oid},
            base_url=self.cases_root,
        ).as_dict()

    def search_case_entities(self, oid: str, entity_type: str, entity_value: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        checked_entity_type = require_case_choice(entity_type, "entity_type", _CASE_ENTITY_TYPES)
        checked_entity_value = require_case_text(entity_value, "entity_value", maximum=1024, required=True)
        return self._request(
            "GET",
            "api/v1/entities/search",
            operation="case.entity.search",
            oid=scoped_oid,
            resource={"type": "case_entity_collection", "id": scoped_oid},
            params={"oids": scoped_oid, "entity_type": checked_entity_type, "entity_value": checked_entity_value},
            base_url=self.cases_root,
        ).as_dict()

    def preview_add_case_entity(
        self,
        oid: str,
        case_number: str | int,
        entity_type: str,
        entity_value: str,
        note: str | None = None,
        verdict: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        body: dict[str, Any] = {
            "entity_type": require_case_choice(entity_type, "entity_type", _CASE_ENTITY_TYPES),
            "entity_value": require_case_text(entity_value, "entity_value", maximum=1024, required=True),
        }
        checked_note = require_case_text(note, "note", maximum=2048)
        if checked_note is not None:
            body["note"] = checked_note
        checked_verdict = require_case_choice(verdict, "verdict", _CASE_VERDICTS)
        if checked_verdict is not None:
            body["verdict"] = checked_verdict
        return self._preview_case_api_mutation(
            operation="case.entity.add",
            oid=scoped_oid,
            method="POST",
            path=f"cases/{safe_case_number}/entities",
            resource_type="case_entity",
            resource_id=safe_case_number,
            params={"oid": scoped_oid},
            json_body=body,
            expected_effect=f"Add an entity to case {safe_case_number}.",
            reversibility="Remove the entity from the case if it was unintended.",
            side_effect_type="case_entity_added",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_update_case_entity(
        self,
        oid: str,
        case_number: str | int,
        entity_id: str,
        note: str | None = None,
        verdict: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        safe_entity_id = require_path_segment(entity_id, "entity_id")
        body: dict[str, Any] = {}
        checked_note = require_case_text(note, "note", maximum=2048)
        if checked_note is not None:
            body["note"] = checked_note
        checked_verdict = require_case_choice(verdict, "verdict", _CASE_VERDICTS)
        if checked_verdict is not None:
            body["verdict"] = checked_verdict
        if not body:
            raise ValidationError("note or verdict is required")
        return self._preview_case_api_mutation(
            operation="case.entity.update",
            oid=scoped_oid,
            method="PATCH",
            path=f"cases/{safe_case_number}/entities/{quote(safe_entity_id, safe='')}",
            resource_type="case_entity",
            resource_id=safe_entity_id,
            params={"oid": scoped_oid},
            json_body=body,
            expected_effect=f"Update entity {safe_entity_id} on case {safe_case_number}.",
            reversibility="Apply another entity update with prior note/verdict if needed.",
            side_effect_type="case_entity_updated",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_remove_case_entity(
        self,
        oid: str,
        case_number: str | int,
        entity_id: str,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        safe_entity_id = require_path_segment(entity_id, "entity_id")
        return self._preview_case_api_mutation(
            operation="case.entity.remove",
            oid=scoped_oid,
            method="DELETE",
            path=f"cases/{safe_case_number}/entities/{quote(safe_entity_id, safe='')}",
            resource_type="case_entity",
            resource_id=safe_entity_id,
            params={"oid": scoped_oid},
            expected_effect=f"Remove entity {safe_entity_id} from case {safe_case_number}.",
            reversibility="Add the entity to the case again if removal was unintended.",
            side_effect_type="case_entity_removed",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_case_telemetry(self, oid: str, case_number: str | int) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        return self._request(
            "GET",
            f"api/v1/cases/{safe_case_number}/telemetry",
            operation="case.telemetry.list",
            oid=scoped_oid,
            resource=self._case_resource(scoped_oid, safe_case_number, "case_telemetry_collection"),
            params={"oid": scoped_oid},
            base_url=self.cases_root,
        ).as_dict()

    def preview_add_case_telemetry(
        self,
        oid: str,
        case_number: str | int,
        event: dict[str, Any],
        note: str | None = None,
        verdict: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        checked_event = require_dict(event, "event")
        if checked_event is None:
            raise ValidationError("event is required")
        body: dict[str, Any] = {"event": checked_event}
        checked_note = require_case_text(note, "note", maximum=2048)
        if checked_note is not None:
            body["note"] = checked_note
        checked_verdict = require_case_choice(verdict, "verdict", _CASE_VERDICTS)
        if checked_verdict is not None:
            body["verdict"] = checked_verdict
        return self._preview_case_api_mutation(
            operation="case.telemetry.add",
            oid=scoped_oid,
            method="POST",
            path=f"cases/{safe_case_number}/telemetry",
            resource_type="case_telemetry",
            resource_id=safe_case_number,
            params={"oid": scoped_oid},
            json_body=body,
            expected_effect=f"Add telemetry to case {safe_case_number}.",
            reversibility="Remove the telemetry reference if it was unintended.",
            side_effect_type="case_telemetry_added",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_update_case_telemetry(
        self,
        oid: str,
        case_number: str | int,
        telemetry_id: str,
        note: str | None = None,
        verdict: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        safe_telemetry_id = require_path_segment(telemetry_id, "telemetry_id")
        body: dict[str, Any] = {}
        checked_note = require_case_text(note, "note", maximum=2048)
        if checked_note is not None:
            body["note"] = checked_note
        checked_verdict = require_case_choice(verdict, "verdict", _CASE_VERDICTS)
        if checked_verdict is not None:
            body["verdict"] = checked_verdict
        if not body:
            raise ValidationError("note or verdict is required")
        return self._preview_case_api_mutation(
            operation="case.telemetry.update",
            oid=scoped_oid,
            method="PATCH",
            path=f"cases/{safe_case_number}/telemetry/{quote(safe_telemetry_id, safe='')}",
            resource_type="case_telemetry",
            resource_id=safe_telemetry_id,
            params={"oid": scoped_oid},
            json_body=body,
            expected_effect=f"Update telemetry {safe_telemetry_id} on case {safe_case_number}.",
            reversibility="Apply another telemetry update with prior note/verdict if needed.",
            side_effect_type="case_telemetry_updated",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_remove_case_telemetry(
        self,
        oid: str,
        case_number: str | int,
        telemetry_id: str,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        safe_telemetry_id = require_path_segment(telemetry_id, "telemetry_id")
        return self._preview_case_api_mutation(
            operation="case.telemetry.remove",
            oid=scoped_oid,
            method="DELETE",
            path=f"cases/{safe_case_number}/telemetry/{quote(safe_telemetry_id, safe='')}",
            resource_type="case_telemetry",
            resource_id=safe_telemetry_id,
            params={"oid": scoped_oid},
            expected_effect=f"Remove telemetry {safe_telemetry_id} from case {safe_case_number}.",
            reversibility="Add the telemetry reference again if removal was unintended.",
            side_effect_type="case_telemetry_removed",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_case_artifacts(self, oid: str, case_number: str | int) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        return self._request(
            "GET",
            f"api/v1/cases/{safe_case_number}/artifacts",
            operation="case.artifact.list",
            oid=scoped_oid,
            resource=self._case_resource(scoped_oid, safe_case_number, "case_artifact_collection"),
            params={"oid": scoped_oid},
            base_url=self.cases_root,
        ).as_dict()

    def preview_add_case_artifact(
        self,
        oid: str,
        case_number: str | int,
        path: str,
        source: str,
        artifact_type: str | None = None,
        note: str | None = None,
        verdict: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        body: dict[str, Any] = {
            "path": require_case_text(path, "path", maximum=2048, required=True),
            "source": require_case_text(source, "source", maximum=1024, required=True),
        }
        if artifact_type is not None:
            body["artifact_type"] = require_token(artifact_type, "artifact_type")
        checked_note = require_case_text(note, "note", maximum=2048)
        if checked_note is not None:
            body["note"] = checked_note
        checked_verdict = require_case_choice(verdict, "verdict", _CASE_VERDICTS)
        if checked_verdict is not None:
            body["verdict"] = checked_verdict
        return self._preview_case_api_mutation(
            operation="case.artifact.add",
            oid=scoped_oid,
            method="POST",
            path=f"cases/{safe_case_number}/artifacts",
            resource_type="case_artifact",
            resource_id=safe_case_number,
            params={"oid": scoped_oid},
            json_body=body,
            expected_effect=f"Add an artifact reference to case {safe_case_number}.",
            reversibility="Remove the artifact reference if it was unintended.",
            side_effect_type="case_artifact_added",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_remove_case_artifact(
        self,
        oid: str,
        case_number: str | int,
        artifact_id: str,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        safe_artifact_id = require_path_segment(artifact_id, "artifact_id")
        return self._preview_case_api_mutation(
            operation="case.artifact.remove",
            oid=scoped_oid,
            method="DELETE",
            path=f"cases/{safe_case_number}/artifacts/{quote(safe_artifact_id, safe='')}",
            resource_type="case_artifact",
            resource_id=safe_artifact_id,
            params={"oid": scoped_oid},
            expected_effect=f"Remove artifact {safe_artifact_id} from case {safe_case_number}.",
            reversibility="Add the artifact reference again if removal was unintended.",
            side_effect_type="case_artifact_removed",
            token_ttl_seconds=token_ttl_seconds,
        )

    def export_case(self, oid: str, case_number: str | int) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        resource = self._case_resource(scoped_oid, safe_case_number, "case_export")
        components: dict[str, Any] = {}
        requests = [
            ("case", self.get_case),
            ("detections", self.list_case_detections),
            ("entities", self.list_case_entities),
            ("telemetry", self.list_case_telemetry),
            ("artifacts", self.list_case_artifacts),
        ]
        for name, fn in requests:
            result = fn(scoped_oid, safe_case_number)
            if not result.get("ok"):
                return ToolResponse(
                    ok=False,
                    operation="case.export",
                    request_id=f"req_{uuid.uuid4().hex}",
                    resource=resource,
                    state={"current": "partial"},
                    data={"components": components, "failed_component": name, "failure": result.get("data")},
                    side_effects=[],
                    warnings=[],
                    meta={"summary": {"shape": "object", "failed_component": name}, "truncated": False},
                    observed_at=observed_at(),
                    error=result.get("error") or classify_error(None, None, f"case export failed while fetching {name}"),
                ).as_dict()
            components[name] = result.get("data")
        return ToolResponse(
            ok=True,
            operation="case.export",
            request_id=f"req_{uuid.uuid4().hex}",
            resource=resource,
            state={},
            data=components,
            side_effects=[],
            warnings=[],
            meta={"summary": {"shape": "object", "components": len(components)}, "truncated": False},
            observed_at=observed_at(),
        ).as_dict()

    def get_cases_report_summary(self, oid: str, time_from: str, time_to: str, group_by: str | None = None) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        params: dict[str, Any] = {
            "oids": scoped_oid,
            "from": require_case_text(time_from, "time_from", maximum=100, required=True),
            "to": require_case_text(time_to, "time_to", maximum=100, required=True),
        }
        if group_by:
            params["group_by"] = require_token(group_by, "group_by")
        return self._request(
            "GET",
            "api/v1/reports/summary",
            operation="case.report",
            oid=scoped_oid,
            resource={"type": "case_report", "id": scoped_oid},
            params=params,
            base_url=self.cases_root,
        ).as_dict()

    def get_cases_dashboard_counts(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            "api/v1/dashboard/counts",
            operation="case.dashboard",
            oid=scoped_oid,
            resource={"type": "case_dashboard", "id": scoped_oid},
            params={"oids": scoped_oid},
            base_url=self.cases_root,
        ).as_dict()

    def get_cases_config(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"api/v1/config/{scoped_oid}",
            operation="case.config.get",
            oid=scoped_oid,
            resource={"type": "case_config", "id": scoped_oid},
            base_url=self.cases_root,
        ).as_dict()

    def preview_set_cases_config(self, oid: str, config: dict[str, Any], token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        checked_config = require_dict(config, "config")
        if checked_config is None:
            raise ValidationError("config is required")
        return self._preview_case_api_mutation(
            operation="case.config.set",
            oid=scoped_oid,
            method="PUT",
            path=f"config/{scoped_oid}",
            resource_type="case_config",
            resource_id=scoped_oid,
            json_body=checked_config,
            expected_effect="Replace Cases configuration for the org.",
            reversibility="Restore the previous Cases configuration from a known-good export.",
            side_effect_type="case_config_updated",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_case_assignees(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            "api/v1/assignees",
            operation="case.assignees.list",
            oid=scoped_oid,
            resource={"type": "case_assignee_collection", "id": scoped_oid},
            params={"oids": scoped_oid},
            base_url=self.cases_root,
        ).as_dict()

    def list_case_orgs(self) -> dict[str, Any]:
        return self._request(
            "GET",
            "api/v1/orgs",
            operation="case.org.list",
            oid="-",
            resource={"type": "case_org_collection", "id": "-"},
            base_url=self.cases_root,
        ).as_dict()

    def preview_set_case_tags(
        self,
        oid: str,
        case_number: str | int,
        tags: list[str] | str,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        checked_tags = require_case_tag_list(tags)
        if checked_tags is None:
            raise ValidationError("tags are required")
        return self._preview_case_api_mutation(
            operation="case.tag.set",
            oid=scoped_oid,
            method="PATCH",
            path=f"cases/{safe_case_number}",
            resource_type="case_tag_collection",
            resource_id=safe_case_number,
            params={"oid": scoped_oid},
            json_body={"tags": checked_tags},
            expected_effect=f"Replace all tags on case {safe_case_number}.",
            reversibility="Run another tag set preview with the prior complete tag list.",
            side_effect_type="case_tags_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_add_case_tags(
        self,
        oid: str,
        case_number: str | int,
        tags: list[str] | str,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        requested_tags = require_case_tag_list(tags)
        if requested_tags is None:
            raise ValidationError("tags are required")
        current = self.get_case(scoped_oid, safe_case_number)
        if not current.get("ok"):
            current["operation"] = "case.tag.add.preview"
            return current
        existing = self._case_tags_from_data(current.get("data"))
        seen = {tag.lower(): tag for tag in existing}
        for tag in requested_tags:
            seen.setdefault(tag.lower(), tag)
        merged = list(seen.values())
        return self._preview_case_api_mutation(
            operation="case.tag.add",
            oid=scoped_oid,
            method="PATCH",
            path=f"cases/{safe_case_number}",
            resource_type="case_tag_collection",
            resource_id=safe_case_number,
            params={"oid": scoped_oid},
            json_body={"tags": merged},
            expected_effect=f"Add tags to case {safe_case_number} by replacing tags with the merged set.",
            reversibility="Run tag set with the prior complete tag list.",
            side_effect_type="case_tags_added",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_remove_case_tags(
        self,
        oid: str,
        case_number: str | int,
        tags: list[str] | str,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        requested_tags = require_case_tag_list(tags)
        if requested_tags is None:
            raise ValidationError("tags are required")
        current = self.get_case(scoped_oid, safe_case_number)
        if not current.get("ok"):
            current["operation"] = "case.tag.remove.preview"
            return current
        remove_set = {tag.lower() for tag in requested_tags}
        remaining = [tag for tag in self._case_tags_from_data(current.get("data")) if tag.lower() not in remove_set]
        return self._preview_case_api_mutation(
            operation="case.tag.remove",
            oid=scoped_oid,
            method="PATCH",
            path=f"cases/{safe_case_number}",
            resource_type="case_tag_collection",
            resource_id=safe_case_number,
            params={"oid": scoped_oid},
            json_body={"tags": remaining},
            expected_effect=f"Remove tags from case {safe_case_number} by replacing tags with the remaining set.",
            reversibility="Run tag set with the prior complete tag list.",
            side_effect_type="case_tags_removed",
            token_ttl_seconds=token_ttl_seconds,
        )

    @staticmethod
    def _case_tags_from_data(data: Any) -> list[str]:
        if not isinstance(data, dict):
            return []
        case_data = data.get("case") if isinstance(data.get("case"), dict) else data
        raw_tags = case_data.get("tags") if isinstance(case_data, dict) else None
        if not isinstance(raw_tags, list):
            return []
        return [str(tag) for tag in raw_tags if isinstance(tag, str) and tag]

    def list_sensor_events(
        self,
        oid: str,
        sensor_id: str,
        start: int,
        end: int,
        event_type: str | None = None,
        limit: int = 100,
        cursor: str = "-",
        is_forward: bool = True,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        bounded_limit = require_limit(limit)
        start_ts, end_ts = require_time_window(start, end)
        params: dict[str, Any] = {
            "start": start_ts,
            "end": end_ts,
            "is_compressed": "true",
            "is_forward": bool_param(is_forward),
            "cursor": require_token(cursor, "cursor"),
            "limit": bounded_limit,
        }
        if event_type:
            params["event_type"] = require_token(event_type, "event_type")
        return self._request(
            "GET",
            f"insight/{scoped_oid}/{safe_sensor_id}",
            operation="event.list",
            oid=scoped_oid,
            resource={
                "type": "event_collection",
                "id": safe_sensor_id,
                "parent": {"type": "organization", "id": scoped_oid},
            },
            params=params,
            limit=bounded_limit,
        ).as_dict()

    def get_sensor_event_overview(self, oid: str, sensor_id: str, start: int, end: int) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        start_ts, end_ts = require_time_window(start, end)
        return self._request(
            "GET",
            f"insight/{scoped_oid}/{safe_sensor_id}/overview",
            operation="event.overview",
            oid=scoped_oid,
            resource={
                "type": "event_overview",
                "id": safe_sensor_id,
                "parent": {"type": "organization", "id": scoped_oid},
            },
            params={"start": start_ts, "end": end_ts},
        ).as_dict()

    def get_event(self, oid: str, sensor_id: str, atom: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        safe_atom = require_path_segment(atom, "atom")
        return self._request(
            "GET",
            f"insight/{scoped_oid}/{safe_sensor_id}/{quote(safe_atom, safe='')}",
            operation="event.get",
            oid=scoped_oid,
            resource={
                "type": "event",
                "id": safe_atom,
                "parent": {"type": "sensor", "id": safe_sensor_id},
            },
        ).as_dict()

    def list_child_events(self, oid: str, sensor_id: str, atom: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        safe_atom = require_path_segment(atom, "atom")
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"insight/{scoped_oid}/{safe_sensor_id}/{quote(safe_atom, safe='')}/children",
            operation="event.children",
            oid=scoped_oid,
            resource={
                "type": "event_collection",
                "id": safe_atom,
                "parent": {"type": "sensor", "id": safe_sensor_id},
            },
            params={"is_compressed": "true"},
            limit=bounded_limit,
        ).as_dict()

    def get_event_retention(
        self,
        oid: str,
        sensor_id: str,
        start: int,
        end: int,
        is_detailed: bool = False,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        start_ts, end_ts = require_time_window(start, end)
        params: dict[str, Any] = {"start": start_ts, "end": end_ts}
        if is_detailed:
            params["is_detailed"] = "true"
        return self._request(
            "GET",
            f"insight/event_count/{scoped_oid}/{safe_sensor_id}",
            operation="event.retention",
            oid=scoped_oid,
            resource={
                "type": "event_retention",
                "id": safe_sensor_id,
                "parent": {"type": "organization", "id": scoped_oid},
            },
            params=params,
        ).as_dict()

    def search_ioc(
        self,
        oid: str,
        obj_type: str,
        obj_name: str,
        info: str = "summary",
        case_sensitive: bool = True,
        wildcards: bool = False,
        limit: int = 100,
        per_object: bool | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_obj_type = require_ioc_type(obj_type)
        safe_info = require_info_type(info)
        bounded_limit = require_limit(limit, maximum=1000)
        if not isinstance(obj_name, str) or not obj_name or len(obj_name) > 500 or "\x00" in obj_name:
            raise ValidationError("obj_name must be a non-empty indicator string under 500 characters")
        if per_object is None:
            per_object_value = wildcards and safe_info == "summary"
        else:
            per_object_value = per_object
        return self._request(
            "GET",
            f"insight/{scoped_oid}/objects/{quote(safe_obj_type, safe='')}",
            operation="ioc.search",
            oid=scoped_oid,
            resource={"type": "ioc_search", "id": safe_obj_type, "parent": {"type": "organization", "id": scoped_oid}},
            params={
                "name": obj_name,
                "info": safe_info,
                "case_sensitive": bool_param(case_sensitive),
                "with_wildcards": bool_param(wildcards),
                "per_object": bool_param(per_object_value),
                "limit": bounded_limit,
            },
            limit=bounded_limit,
        ).as_dict()

    def batch_search_iocs(
        self,
        oid: str,
        objects: dict[str, list[str]],
        info: str = "summary",
        case_sensitive: bool = True,
        limit: int = 100,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_objects = require_ioc_batch(objects)
        safe_info = require_info_type(info)
        bounded_limit = require_limit(limit, maximum=1000)
        params: dict[str, Any] = {
            "objects": json.dumps(safe_objects),
            "case_sensitive": bool_param(case_sensitive),
            "info": safe_info,
        }
        if safe_info == "locations":
            params["limit"] = bounded_limit
        return self._request(
            "POST",
            f"insight/{scoped_oid}/objects",
            operation="ioc.batch_search",
            oid=scoped_oid,
            resource={"type": "ioc_batch_search", "id": scoped_oid},
            params=params,
            limit=bounded_limit,
        ).as_dict()

    def get_object_information(
        self,
        oid: str,
        obj_type: str,
        obj_name: str,
        info: str = "summary",
        case_sensitive: bool = True,
        wildcards: bool = False,
        limit: int = 100,
    ) -> dict[str, Any]:
        result = self.search_ioc(
            oid,
            obj_type,
            obj_name,
            info=info,
            case_sensitive=case_sensitive,
            wildcards=wildcards,
            limit=limit,
        )
        result["operation"] = "ioc.object_info"
        return result

    def get_insight_status(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        result = self._request(
            "GET",
            f"insight/{scoped_oid}",
            operation="insight.status",
            oid=scoped_oid,
            resource={"type": "insight_status", "id": scoped_oid},
        ).as_dict()
        if result.get("ok") and isinstance(result.get("data"), dict):
            result["state"] = {
                "current": "enabled" if result["data"].get("insight_bucket") else "unknown_or_disabled",
                "enabled": bool(result["data"].get("insight_bucket")),
            }
            result["meta"]["summary"]["enabled"] = bool(result["data"].get("insight_bucket"))
        return result

    def validate_search_query(
        self,
        oid: str,
        query: str,
        start: int | None = None,
        end: int | None = None,
        stream: str | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_query = require_search_query(query)
        if start is None and end is None:
            end_ts = int(time.time())
            start_ts = end_ts - 86_400
        elif start is not None and end is not None:
            start_ts, end_ts = require_time_window(start, end)
        else:
            raise ValidationError("start and end must both be provided, or both omitted")
        body = self._search_body(scoped_oid, safe_query, start_ts, end_ts, stream)
        return self._request(
            "POST",
            "search/validate",
            operation="search.validate",
            oid=scoped_oid,
            resource={"type": "lcql_validation", "id": scoped_oid},
            json_body=body,
            base_url=self._search_root(scoped_oid),
        ).as_dict()

    def estimate_search_query(
        self,
        oid: str,
        query: str,
        start: int,
        end: int,
        stream: str | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_query = require_search_query(query)
        start_ts, end_ts = require_time_window(start, end)
        body = self._search_body(scoped_oid, safe_query, start_ts, end_ts, stream)
        result = self._request(
            "POST",
            "search/validate",
            operation="search.estimate",
            oid=scoped_oid,
            resource={"type": "lcql_estimate", "id": scoped_oid},
            json_body=body,
            base_url=self._search_root(scoped_oid),
        ).as_dict()
        if result.get("ok"):
            result["warnings"] = [
                "LimaCharlie exposes estimate data through the search validation endpoint for the supplied time window."
            ]
        return result

    def execute_search_query(
        self,
        oid: str,
        query: str,
        start: int,
        end: int,
        stream: str | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_query = require_search_query(query)
        start_ts, end_ts = require_time_window(start, end)
        body = self._search_body(scoped_oid, safe_query, start_ts, end_ts, stream)
        body["paginated"] = True
        result = self._request(
            "POST",
            "search",
            operation="search.execute",
            oid=scoped_oid,
            resource={"type": "lcql_search_job", "id": scoped_oid},
            json_body=body,
            base_url=self._search_root(scoped_oid),
            side_effects=[{"type": "search_query_started", "resource": {"type": "organization", "id": scoped_oid}}],
        ).as_dict()
        if result.get("ok") and isinstance(result.get("data"), dict):
            query_id = result["data"].get("queryId") or result["data"].get("query_id")
            result["state"] = {
                "current": "running" if query_id else "unknown",
                "terminal": False,
                "query_id": query_id,
                "checkpoint": {"next_token": None},
            }
            result["meta"]["summary"]["query_id"] = query_id
            result["meta"]["suggested_next_actions"] = [
                "Call lc_poll_search_query with query_id to retrieve one bounded result page.",
                "Call lc_cancel_search_query when the search is no longer needed.",
            ]
        return result

    def poll_search_query(
        self,
        oid: str,
        query_id: str,
        token: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_query_id = require_token(query_id, "query_id")
        bounded_limit = require_limit(limit)
        params = {"token": require_token(token, "token")} if token else None
        result = self._request(
            "GET",
            f"search/{quote(safe_query_id, safe='')}",
            operation="search.poll",
            oid=scoped_oid,
            resource={"type": "lcql_search_job", "id": safe_query_id, "parent": {"type": "organization", "id": scoped_oid}},
            params=params,
            base_url=self._search_root(scoped_oid),
            limit=bounded_limit,
        ).as_dict()
        if result.get("ok"):
            self._finalize_search_poll(result, safe_query_id, bounded_limit)
        return result

    def cancel_search_query(self, oid: str, query_id: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_query_id = require_token(query_id, "query_id")
        result = self._request(
            "DELETE",
            f"search/{quote(safe_query_id, safe='')}",
            operation="search.cancel",
            oid=scoped_oid,
            resource={"type": "lcql_search_job", "id": safe_query_id, "parent": {"type": "organization", "id": scoped_oid}},
            base_url=self._search_root(scoped_oid),
            side_effects=[{"type": "search_query_cancelled", "resource": {"type": "lcql_search_job", "id": safe_query_id}}],
        ).as_dict()
        if result.get("ok"):
            result["state"] = {"current": "cancelled", "terminal": True, "query_id": safe_query_id}
        return result

    def validate_replay_rule(
        self,
        oid: str,
        rule_content: dict[str, Any],
        trace: bool = False,
        limit_events: int = 1,
        limit_evals: int = 1000,
    ) -> dict[str, Any]:
        return self.replay_scan_events(
            oid=oid,
            events=[{"event": {}, "routing": {}}],
            rule_content=rule_content,
            trace=trace,
            limit_events=limit_events,
            limit_evals=limit_evals,
            stream="event",
            operation="replay.validate_rule",
            resource_type="replay_validation",
        )

    def replay_scan_events(
        self,
        oid: str,
        events: list[dict[str, Any]],
        rule_name: str | None = None,
        namespace: str | None = None,
        rule_content: dict[str, Any] | None = None,
        trace: bool = False,
        limit_events: int = 100,
        limit_evals: int = 1000,
        stream: str = "event",
        *,
        operation: str = "replay.scan_events",
        resource_type: str = "replay_result",
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        checked_events = require_dict_list(events, "events", maximum=100) or []
        checked_rule = require_dict(rule_content, "rule_content")
        if not rule_name and checked_rule is None:
            raise ValidationError("rule_name or rule_content is required")
        bounded_limit_events = require_seconds(limit_events, "limit_events", minimum=1, maximum=1000)
        bounded_limit_evals = require_seconds(limit_evals, "limit_evals", minimum=1, maximum=100_000)
        body = {
            "oid": scoped_oid,
            "rule_source": {
                "rule_name": require_token(rule_name, "rule_name") if rule_name else "",
                "namespace": require_dr_namespace(namespace) if namespace else "",
                "rule": checked_rule,
            },
            "event_source": {
                "stream": require_search_stream(stream) or "event",
                "sensor_events": {},
                "events": checked_events,
            },
            "trace": bool(trace),
            "limit_event": bounded_limit_events,
            "limit_eval": bounded_limit_evals,
            "is_dry_run": True,
        }
        return self._request(
            "POST",
            "",
            operation=operation,
            oid=scoped_oid,
            resource={"type": resource_type, "id": scoped_oid},
            json_body=body,
            base_url=self._replay_root(scoped_oid),
        ).as_dict()

    def replay_dry_run(
        self,
        oid: str,
        start: int,
        end: int,
        rule_name: str | None = None,
        detect: dict[str, Any] | None = None,
        respond: list[dict[str, Any]] | None = None,
        sensor_id: str | None = None,
        selector: str | None = None,
        stream: str = "event",
        trace: bool = False,
        limit_events: int = 1000,
        limit_evals: int = 10_000,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        start_ts, end_ts = require_time_window(start, end)
        safe_rule_name = require_token(rule_name, "rule_name") if rule_name else None
        checked_detect = require_dict(detect, "detect")
        checked_respond = require_dict_list(respond, "respond", maximum=100)
        if not safe_rule_name and checked_detect is None and checked_respond is None:
            raise ValidationError("rule_name or detect/respond rule content is required")
        sensor_events: dict[str, Any] = {"start_time": start_ts, "end_time": end_ts}
        if sensor_id:
            sensor_events["sid"] = require_oid(sensor_id)
        if selector:
            sensor_events["selector"] = require_selector(selector)
        rule_source: dict[str, Any] = {}
        if safe_rule_name:
            rule_source["rule_name"] = safe_rule_name
        if checked_detect is not None or checked_respond is not None:
            rule_source["rule"] = {}
            if checked_detect is not None:
                rule_source["rule"]["detect"] = checked_detect
            if checked_respond is not None:
                rule_source["rule"]["respond"] = checked_respond
        body = {
            "oid": scoped_oid,
            "rule_source": rule_source,
            "event_source": {
                "stream": require_search_stream(stream) or "event",
                "sensor_events": sensor_events,
            },
            "trace": bool(trace),
            "is_dry_run": True,
            "limit_event": require_seconds(limit_events, "limit_events", minimum=1, maximum=100_000),
            "limit_eval": require_seconds(limit_evals, "limit_evals", minimum=1, maximum=1_000_000),
        }
        return self._request(
            "POST",
            "",
            operation="replay.run_dry",
            oid=scoped_oid,
            resource={"type": "replay_result", "id": scoped_oid},
            json_body=body,
            base_url=self._replay_root(scoped_oid),
        ).as_dict()

    def list_artifacts(
        self,
        oid: str,
        sensor_id: str | None = None,
        start: int | None = None,
        end: int | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        params: dict[str, Any] = {}
        if sensor_id:
            params["sid"] = require_oid(sensor_id)
        if cursor:
            params["cursor"] = require_token(cursor, "cursor")
        else:
            if start is None or end is None:
                raise ValidationError("start and end are required when cursor is not provided")
            start_ts, end_ts = require_time_window(start, end)
            params["start"] = start_ts
            params["end"] = end_ts
        return self._request(
            "GET",
            f"insight/{scoped_oid}/artifacts",
            operation="artifact.list",
            oid=scoped_oid,
            resource={"type": "artifact_collection", "id": scoped_oid},
            params=params,
            limit=bounded_limit,
        ).as_dict()

    def get_artifact_url(self, oid: str, artifact_id: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_artifact_id = require_path_segment(artifact_id, "artifact_id")
        return self._request(
            "POST",
            f"insight/{scoped_oid}/artifacts/originals/{quote(safe_artifact_id, safe='')}",
            operation="artifact.get_url",
            oid=scoped_oid,
            resource={"type": "artifact", "id": safe_artifact_id, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def list_payloads(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"payload/{scoped_oid}",
            operation="payload.list",
            oid=scoped_oid,
            resource={"type": "payload_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def get_payload_download_url(self, oid: str, name: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        return self._request(
            "GET",
            f"payload/{scoped_oid}/{quote(safe_name, safe='')}",
            operation="payload.get_url",
            oid=scoped_oid,
            resource={"type": "payload", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def get_arl(self, oid: str, arl_url: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        safe_arl = require_arl(arl_url)
        return self._request(
            "GET",
            f"arl/{scoped_oid}",
            operation="arl.get",
            oid=scoped_oid,
            resource={"type": "authenticated_resource_locator", "id": scoped_oid},
            params={"arl": safe_arl},
            limit=bounded_limit,
        ).as_dict()

    def list_jobs(
        self,
        oid: str,
        start: int,
        end: int,
        sensor_id: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        start_ts, end_ts = require_time_window(start, end)
        params: dict[str, Any] = {
            "is_compressed": "true",
            "with_data": "false",
            "start": start_ts,
            "end": end_ts,
            "limit": bounded_limit,
        }
        if sensor_id:
            params["sid"] = require_oid(sensor_id)
        return self._request(
            "GET",
            f"job/{scoped_oid}",
            operation="job.list",
            oid=scoped_oid,
            resource={"type": "job_collection", "id": scoped_oid},
            params=params,
            limit=bounded_limit,
        ).as_dict()

    def get_job(self, oid: str, job_id: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_job_id = require_path_segment(job_id, "job_id")
        return self._request(
            "GET",
            f"job/{scoped_oid}/{quote(safe_job_id, safe='')}",
            operation="job.get",
            oid=scoped_oid,
            resource={"type": "job", "id": safe_job_id, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def wait_job(
        self,
        oid: str,
        job_id: str,
        timeout_seconds: int = 60,
        poll_interval_seconds: int = 5,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_job_id = require_path_segment(job_id, "job_id")
        timeout = require_seconds(timeout_seconds, "timeout_seconds", minimum=1, maximum=600)
        poll_interval = require_seconds(poll_interval_seconds, "poll_interval_seconds", minimum=1, maximum=30)
        started = time.time()
        request_id = f"req_{uuid.uuid4().hex}"
        attempts = 0
        last_result: dict[str, Any] | None = None
        last_state = {"current": "unknown", "terminal": False}
        while True:
            attempts += 1
            result = self._request(
                "GET",
                f"job/{scoped_oid}/{quote(safe_job_id, safe='')}",
                operation="job.wait",
                oid=scoped_oid,
                resource={"type": "job", "id": safe_job_id, "parent": {"type": "organization", "id": scoped_oid}},
            ).as_dict()
            last_result = result
            if not result["ok"]:
                result["meta"]["attempts"] = attempts
                return result
            last_state = normalize_job_state(result.get("data"))
            if last_state["terminal"]:
                duration_ms = int((time.time() - started) * 1000)
                result["request_id"] = request_id
                result["state"] = last_state
                result["meta"]["duration_ms"] = duration_ms
                result["meta"]["attempts"] = attempts
                result["meta"]["summary"]["job_state"] = last_state["current"]
                return result
            elapsed = time.time() - started
            if elapsed + poll_interval > timeout:
                break
            time.sleep(poll_interval)

        duration_ms = int((time.time() - started) * 1000)
        return ToolResponse(
            ok=False,
            operation="job.wait",
            request_id=request_id,
            resource={"type": "job", "id": safe_job_id, "parent": {"type": "organization", "id": scoped_oid}},
            state=last_state,
            data={"last_observation": last_result.get("data") if last_result else None},
            side_effects=[],
            warnings=[],
            meta={
                "duration_ms": duration_ms,
                "attempts": attempts,
                "summary": {"job_state": last_state["current"], "timed_out": True},
                "truncated": False,
            },
            observed_at=observed_at(),
            error={
                "code": "job_wait_timeout",
                "class": "transient",
                "message": f"Job {safe_job_id} did not reach a terminal state within {timeout} seconds.",
                "retryable": True,
                "same_input_retryable": True,
                "suggested_next_actions": [
                    "Call lc_get_job to inspect the latest job state.",
                    "Retry lc_wait_job with a longer timeout if the job is expected to continue.",
                ],
            },
        ).as_dict()

    def preview_delete_job(self, oid: str, job_id: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_job_id = require_path_segment(job_id, "job_id")
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation="job.delete",
            oid=scoped_oid,
            method="DELETE",
            path=f"job/{scoped_oid}/{quote(safe_job_id, safe='')}",
            resource={"type": "job", "id": safe_job_id, "parent": {"type": "organization", "id": scoped_oid}},
            data=None,
            json_body=None,
            expected_effect=f"Delete job record {safe_job_id}.",
            reversibility="Deletion is not generally reversible; list jobs again to verify current state.",
            side_effects=[{"type": "job_deleted", "resource": {"type": "job", "id": safe_job_id}}],
            token_ttl_seconds=token_ttl,
        )

    def list_audit_logs(
        self,
        oid: str,
        start: int,
        end: int,
        event_type: str | None = None,
        sensor_id: str | None = None,
        limit: int = 100,
        cursor: str = "-",
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        start_ts, end_ts = require_time_window(start, end)
        params: dict[str, Any] = {
            "start": start_ts,
            "end": end_ts,
            "cursor": require_token(cursor, "cursor"),
            "is_compressed": "true",
            "limit": bounded_limit,
        }
        if event_type:
            params["event_type"] = require_token(event_type, "event_type")
        if sensor_id:
            params["sid"] = require_oid(sensor_id)
        return self._request(
            "GET",
            f"insight/{scoped_oid}/audit",
            operation="audit.list",
            oid=scoped_oid,
            resource={"type": "audit_log_collection", "id": scoped_oid},
            params=params,
            limit=bounded_limit,
        ).as_dict()

    def list_tags(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"tags/{scoped_oid}",
            operation="tag.list",
            oid=scoped_oid,
            resource={"type": "tag_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def find_sensors_by_tag(self, oid: str, tag: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_tag = require_token(tag, "tag")
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"tags/{scoped_oid}/{quote(safe_tag, safe='')}",
            operation="tag.sensor_search",
            oid=scoped_oid,
            resource={"type": "sensor_collection", "id": safe_tag, "parent": {"type": "organization", "id": scoped_oid}},
            limit=bounded_limit,
        ).as_dict()

    def find_sensors_by_hostname(self, oid: str, hostname: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_hostname = require_token(hostname, "hostname")
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"hostnames/{scoped_oid}",
            operation="sensor.hostname_search",
            oid=scoped_oid,
            resource={"type": "sensor_collection", "id": safe_hostname, "parent": {"type": "organization", "id": scoped_oid}},
            params={"hostname": safe_hostname},
            limit=bounded_limit,
        ).as_dict()

    def export_sensors(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "POST",
            f"export/{scoped_oid}/sensors",
            operation="sensor.export",
            oid=scoped_oid,
            resource={"type": "sensor_export", "id": scoped_oid},
        ).as_dict()

    def preview_set_sensor_version(
        self,
        oid: str,
        version: str | None = None,
        is_fallback: bool = False,
        is_sleep: bool = False,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        params: dict[str, Any] = {}
        if version:
            params["specific_version"] = require_token(version, "version")
        if is_fallback:
            params["is_fallback"] = "true"
        if is_sleep:
            params["is_sleep"] = "true"
        if not params:
            raise ValidationError("version, is_fallback, or is_sleep is required")
        return self._preview_mutation(
            operation="sensor.version.set",
            oid=scoped_oid,
            method="POST",
            path=f"modules/{scoped_oid}",
            resource_type="sensor_version_policy",
            resource_id=scoped_oid,
            params=params,
            expected_effect="Change the organization's sensor version policy.",
            reversibility="Run another sensor version preview with the prior policy value.",
            side_effect_type="sensor_version_policy_set",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def list_available_services(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"service/{scoped_oid}",
            operation="service.list",
            oid=scoped_oid,
            resource={"type": "service_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def preview_service_request(
        self,
        oid: str,
        service_name: str,
        request_data: dict[str, Any],
        is_async: bool = False,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_service = require_path_segment(service_name, "service_name")
        checked_data = require_dict(request_data, "request_data")
        if checked_data is None:
            raise ValidationError("request_data is required")
        return self._preview_service_request(
            operation="service.request",
            oid=scoped_oid,
            service=safe_service,
            request_data=checked_data,
            resource_type="service_request",
            resource_id=safe_service,
            expected_effect=f"Send a request to service {safe_service!r}.",
            reversibility="Service request effects depend on the selected service/action.",
            side_effect_type="service_request_sent",
            token_ttl_seconds=token_ttl_seconds,
            is_async=is_async,
        )

    def _config_sync_options(
        self,
        *,
        sync_outputs: bool = False,
        sync_integrity: bool = False,
        sync_artifact: bool = False,
        sync_exfil: bool = False,
        sync_resources: bool = False,
        sync_extensions: bool = False,
        sync_org_values: bool = False,
        sync_hives: dict[str, bool] | None = None,
        sync_installation_keys: bool = False,
        sync_yara: bool = False,
    ) -> dict[str, Any]:
        if sync_hives is not None:
            if not isinstance(sync_hives, dict):
                raise ValidationError("sync_hives must be an object of hive names to booleans")
            checked_hives = {require_token(str(name), "hive_name"): bool(value) for name, value in sync_hives.items()}
        else:
            checked_hives = {}
        return {
            "sync_outputs": bool(sync_outputs),
            "sync_resources": bool(sync_resources),
            "sync_extensions": bool(sync_extensions),
            "sync_integrity": bool(sync_integrity),
            "sync_exfil": bool(sync_exfil),
            "sync_artifacts": bool(sync_artifact),
            "sync_org_values": bool(sync_org_values),
            "sync_hives": checked_hives,
            "sync_installation_keys": bool(sync_installation_keys),
            "sync_yara": bool(sync_yara),
        }

    def fetch_config(
        self,
        oid: str,
        sync_outputs: bool = False,
        sync_integrity: bool = False,
        sync_artifact: bool = False,
        sync_exfil: bool = False,
        sync_resources: bool = False,
        sync_extensions: bool = False,
        sync_org_values: bool = False,
        sync_hives: dict[str, bool] | None = None,
        sync_installation_keys: bool = False,
        sync_yara: bool = False,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        options = self._config_sync_options(
            sync_outputs=sync_outputs,
            sync_integrity=sync_integrity,
            sync_artifact=sync_artifact,
            sync_exfil=sync_exfil,
            sync_resources=sync_resources,
            sync_extensions=sync_extensions,
            sync_org_values=sync_org_values,
            sync_hives=sync_hives,
            sync_installation_keys=sync_installation_keys,
            sync_yara=sync_yara,
        )
        return self._request(
            "POST",
            "extension/request/ext-infrastructure",
            operation="config.fetch",
            oid=scoped_oid,
            resource={"type": "infrastructure_config", "id": scoped_oid},
            params=extension_request_params(scoped_oid, "fetch", {"options": options}),
        ).as_dict()

    def preview_push_config(
        self,
        oid: str,
        config: dict[str, Any],
        is_force: bool = False,
        is_dry_run: bool = False,
        ignore_inaccessible: bool = False,
        sync_outputs: bool = False,
        sync_integrity: bool = False,
        sync_artifact: bool = False,
        sync_exfil: bool = False,
        sync_resources: bool = False,
        sync_extensions: bool = False,
        sync_org_values: bool = False,
        sync_hives: dict[str, bool] | None = None,
        sync_installation_keys: bool = False,
        sync_yara: bool = False,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        checked_config = require_dict(config, "config")
        if checked_config is None:
            raise ValidationError("config is required")
        options = self._config_sync_options(
            sync_outputs=sync_outputs,
            sync_integrity=sync_integrity,
            sync_artifact=sync_artifact,
            sync_exfil=sync_exfil,
            sync_resources=sync_resources,
            sync_extensions=sync_extensions,
            sync_org_values=sync_org_values,
            sync_hives=sync_hives,
            sync_installation_keys=sync_installation_keys,
            sync_yara=sync_yara,
        )
        options.update(
            {
                "is_dry_run": bool(is_dry_run),
                "is_force": bool(is_force),
                "ignore_inaccessible": bool(ignore_inaccessible),
            }
        )
        params = extension_request_params(
            scoped_oid,
            "push",
            {"config": json.dumps(checked_config, sort_keys=True), "options": options},
        )
        return self._preview_mutation(
            operation="config.push",
            oid=scoped_oid,
            method="POST",
            path="extension/request/ext-infrastructure",
            resource_type="infrastructure_config",
            resource_id=scoped_oid,
            params=params,
            expected_effect="Push infrastructure configuration through ext-infrastructure.",
            reversibility="Restore from a prior config export, or use is_dry_run before applying.",
            side_effect_type="infrastructure_config_pushed",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def list_exfil_rules(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "POST",
            f"service/{scoped_oid}/exfil",
            operation="exfil_rule.list",
            oid=scoped_oid,
            resource={"type": "exfil_rule_collection", "id": scoped_oid},
            params=service_request_params({"action": "list_rules"}),
        ).as_dict()

    def preview_create_exfil_watch(
        self,
        oid: str,
        name: str,
        event: str,
        value: str,
        operator: str,
        path: str | list[str],
        tags: list[str] | str | None = None,
        platforms: list[str] | str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        request_data: dict[str, Any] = {
            "action": "add_watch",
            "name": safe_name,
            "event": require_token(event, "event"),
            "value": require_token(value, "value"),
            "operator": require_token(operator, "operator"),
            "path": require_exfil_path(path),
        }
        checked_tags = require_string_list(tags, "tags")
        if checked_tags:
            request_data["tags"] = checked_tags
        checked_platforms = require_string_list(platforms, "platforms")
        if checked_platforms:
            request_data["platforms"] = checked_platforms
        return self._preview_service_request(
            operation="exfil_watch.create",
            oid=oid,
            service="exfil",
            request_data=request_data,
            resource_type="exfil_watch",
            resource_id=safe_name,
            expected_effect=f"Create exfil watch rule {safe_name!r}.",
            reversibility="Delete the exfil watch rule if creation was unintended.",
            side_effect_type="exfil_watch_created",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_create_exfil_event(
        self,
        oid: str,
        name: str,
        events: list[str] | str,
        tags: list[str] | str | None = None,
        platforms: list[str] | str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        checked_events = require_string_list(events, "events")
        if not checked_events:
            raise ValidationError("events are required")
        request_data: dict[str, Any] = {"action": "add_event_rule", "name": safe_name, "events": checked_events}
        checked_tags = require_string_list(tags, "tags")
        if checked_tags:
            request_data["tags"] = checked_tags
        checked_platforms = require_string_list(platforms, "platforms")
        if checked_platforms:
            request_data["platforms"] = checked_platforms
        return self._preview_service_request(
            operation="exfil_event.create",
            oid=oid,
            service="exfil",
            request_data=request_data,
            resource_type="exfil_event_rule",
            resource_id=safe_name,
            expected_effect=f"Create exfil event rule {safe_name!r}.",
            reversibility="Delete the exfil event rule if creation was unintended.",
            side_effect_type="exfil_event_created",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_exfil_event(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        return self._preview_service_request(
            operation="exfil_event.delete",
            oid=oid,
            service="exfil",
            request_data={"action": "remove_event_rule", "name": safe_name},
            resource_type="exfil_event_rule",
            resource_id=safe_name,
            expected_effect=f"Delete exfil event rule {safe_name!r}.",
            reversibility="Recreate the exfil event rule from a known-good backup.",
            side_effect_type="exfil_event_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_exfil_watch(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        return self._preview_service_request(
            operation="exfil_watch.delete",
            oid=oid,
            service="exfil",
            request_data={"action": "remove_watch", "name": safe_name},
            resource_type="exfil_watch",
            resource_id=safe_name,
            expected_effect=f"Delete exfil watch rule {safe_name!r}.",
            reversibility="Recreate the exfil watch rule from a known-good backup.",
            side_effect_type="exfil_watch_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_feedback_channels(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"hive/extension_config/{scoped_oid}/ext-feedback/data",
            operation="feedback.channel.list",
            oid=scoped_oid,
            resource={"type": "feedback_channel_collection", "id": scoped_oid},
        ).as_dict()

    def preview_set_feedback_channels(
        self,
        oid: str,
        channels: list[dict[str, Any]],
        etag: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        checked_channels = require_dict_list(channels, "channels", maximum=50)
        if checked_channels is None:
            raise ValidationError("channels are required")
        for channel in checked_channels:
            require_token(str(channel.get("name", "")), "channel.name")
            channel_type = str(channel.get("channel_type", ""))
            if channel_type not in {"web", "slack", "email", "telegram", "ms_teams"}:
                raise ValidationError("channel_type must be one of: web, slack, email, telegram, ms_teams")
        return self._preview_hive_set(
            operation="feedback.channel.set",
            oid=oid,
            hive_name="extension_config",
            name="ext-feedback",
            data={"channels": checked_channels},
            resource_type="feedback_channel_collection",
            enabled=None,
            tags=None,
            comment=None,
            expiry=None,
            etag=etag,
            token_ttl_seconds=token_ttl_seconds,
        )

    def _feedback_request_data(
        self,
        *,
        channel: str,
        question: str,
        feedback_destination: str,
        case_id: str | None,
        playbook_name: str | None,
    ) -> dict[str, Any]:
        destination = str(feedback_destination)
        if destination not in {"case", "playbook"}:
            raise ValidationError("feedback_destination must be case or playbook")
        data: dict[str, Any] = {
            "channel": require_token(channel, "channel"),
            "question": require_case_text(question, "question", maximum=4000, required=True),
            "feedback_destination": destination,
        }
        if destination == "case":
            if case_id is None:
                raise ValidationError("case_id is required when feedback_destination is case")
            data["case_id"] = require_case_number(case_id)
        if destination == "playbook":
            if playbook_name is None:
                raise ValidationError("playbook_name is required when feedback_destination is playbook")
            data["playbook_name"] = require_token(playbook_name, "playbook_name")
        return data

    def _preview_feedback_request(
        self,
        *,
        oid: str,
        action: str,
        operation: str,
        data: dict[str, Any],
        resource_id: str,
        token_ttl_seconds: int,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation=operation,
            oid=scoped_oid,
            method="POST",
            path="extension/request/ext-feedback",
            resource={"type": "feedback_request", "id": resource_id, "parent": {"type": "organization", "id": scoped_oid}},
            params=extension_request_params(scoped_oid, action, data),
            data=None,
            json_body=None,
            expected_effect=f"Send ext-feedback {action} request to channel {data.get('channel')!r}.",
            reversibility="Feedback requests may notify external systems and cannot generally be withdrawn.",
            side_effects=[{"type": "feedback_request_sent", "resource": {"type": "feedback_request", "id": resource_id}}],
            token_ttl_seconds=token_ttl,
        )

    def preview_feedback_simple_approval(
        self,
        oid: str,
        channel: str,
        question: str,
        feedback_destination: str,
        case_id: str | None = None,
        playbook_name: str | None = None,
        approved_content: dict[str, Any] | None = None,
        denied_content: dict[str, Any] | None = None,
        timeout_seconds: int | None = None,
        timeout_choice: str | None = None,
        timeout_content: dict[str, Any] | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        data = self._feedback_request_data(
            channel=channel,
            question=question,
            feedback_destination=feedback_destination,
            case_id=case_id,
            playbook_name=playbook_name,
        )
        if approved_content is not None:
            data["approved_content"] = require_dict(approved_content, "approved_content")
        if denied_content is not None:
            data["denied_content"] = require_dict(denied_content, "denied_content")
        if timeout_seconds is not None:
            data["timeout_seconds"] = require_seconds(timeout_seconds, "timeout_seconds", minimum=60, maximum=2_592_000)
            if timeout_choice not in {"approved", "denied"}:
                raise ValidationError("timeout_choice must be approved or denied when timeout_seconds is set")
            data["timeout_choice"] = timeout_choice
        if timeout_content is not None:
            data["timeout_content"] = require_dict(timeout_content, "timeout_content")
        return self._preview_feedback_request(
            oid=oid,
            action="request_simple_approval",
            operation="feedback.approval",
            data=data,
            resource_id=f"{data['channel']}:approval",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_feedback_acknowledgement(
        self,
        oid: str,
        channel: str,
        question: str,
        feedback_destination: str,
        case_id: str | None = None,
        playbook_name: str | None = None,
        acknowledged_content: dict[str, Any] | None = None,
        timeout_seconds: int | None = None,
        timeout_content: dict[str, Any] | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        data = self._feedback_request_data(
            channel=channel,
            question=question,
            feedback_destination=feedback_destination,
            case_id=case_id,
            playbook_name=playbook_name,
        )
        if acknowledged_content is not None:
            data["acknowledged_content"] = require_dict(acknowledged_content, "acknowledged_content")
        if timeout_seconds is not None:
            data["timeout_seconds"] = require_seconds(timeout_seconds, "timeout_seconds", minimum=60, maximum=2_592_000)
        if timeout_content is not None:
            data["timeout_content"] = require_dict(timeout_content, "timeout_content")
        return self._preview_feedback_request(
            oid=oid,
            action="request_acknowledgement",
            operation="feedback.acknowledgement",
            data=data,
            resource_id=f"{data['channel']}:acknowledgement",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_feedback_question(
        self,
        oid: str,
        channel: str,
        question: str,
        feedback_destination: str,
        case_id: str | None = None,
        playbook_name: str | None = None,
        timeout_seconds: int | None = None,
        timeout_content: dict[str, Any] | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        data = self._feedback_request_data(
            channel=channel,
            question=question,
            feedback_destination=feedback_destination,
            case_id=case_id,
            playbook_name=playbook_name,
        )
        if timeout_seconds is not None:
            data["timeout_seconds"] = require_seconds(timeout_seconds, "timeout_seconds", minimum=60, maximum=2_592_000)
            if timeout_content is None:
                raise ValidationError("timeout_content is required when timeout_seconds is set for a question")
        if timeout_content is not None:
            data["timeout_content"] = require_dict(timeout_content, "timeout_content")
        return self._preview_feedback_request(
            oid=oid,
            action="request_question",
            operation="feedback.question",
            data=data,
            resource_id=f"{data['channel']}:question",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_schemas(self, oid: str, platform: str | None = None, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        params = {"platform": require_token(platform, "platform")} if platform else None
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/schema",
            operation="schema.list",
            oid=scoped_oid,
            resource={"type": "schema_collection", "id": scoped_oid},
            params=params,
            limit=bounded_limit,
        ).as_dict()

    def get_schema(self, oid: str, name: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/schema/{quote(safe_name, safe='')}",
            operation="schema.get",
            oid=scoped_oid,
            resource={"type": "schema", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def get_ontology(self, limit: int = 100) -> dict[str, Any]:
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            "ontology",
            operation="ontology.get",
            oid="-",
            resource={"type": "ontology", "id": "-"},
            limit=bounded_limit,
        ).as_dict()

    def list_event_types(self, limit: int = 100) -> dict[str, Any]:
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            "events",
            operation="event_type.list",
            oid="-",
            resource={"type": "event_type_collection", "id": "-"},
            limit=bounded_limit,
        ).as_dict()

    def get_mitre_report(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"mitre/{scoped_oid}",
            operation="mitre.get",
            oid=scoped_oid,
            resource={"type": "mitre_report", "id": scoped_oid},
        ).as_dict()

    def get_org_info(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"orgs/{scoped_oid}",
            operation="org.get",
            oid=scoped_oid,
            resource={"type": "organization", "id": scoped_oid},
        ).as_dict()

    def get_org_stats(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"usage/{scoped_oid}",
            operation="org.stats",
            oid=scoped_oid,
            resource={"type": "organization_stats", "id": scoped_oid},
        ).as_dict()

    def list_org_errors(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"errors/{scoped_oid}",
            operation="org.errors",
            oid=scoped_oid,
            resource={"type": "organization_error_collection", "id": scoped_oid},
        ).as_dict()

    def get_org_urls(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/url",
            operation="org.urls",
            oid=scoped_oid,
            resource={"type": "organization_urls", "id": scoped_oid},
            no_auth=True,
        ).as_dict()

    def get_runtime_metadata(
        self,
        oid: str,
        entity_type: str | None = None,
        entity_name: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        params: dict[str, Any] = {}
        if entity_type:
            params["entity_type"] = require_token(entity_type, "entity_type")
        if entity_name:
            params["entity_name"] = require_token(entity_name, "entity_name")
        return self._request(
            "GET",
            f"runtime_mtd/{scoped_oid}",
            operation="org.runtime_metadata",
            oid=scoped_oid,
            resource={"type": "runtime_metadata", "id": scoped_oid},
            params=params or None,
            limit=bounded_limit,
        ).as_dict()

    def get_quota_usage(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"quota_usage/{scoped_oid}",
            operation="org.quota_usage",
            oid=scoped_oid,
            resource={"type": "quota_usage", "id": scoped_oid},
        ).as_dict()

    def check_org_name(self, name: str) -> dict[str, Any]:
        safe_name = require_org_name(name)
        return self._request(
            "GET",
            "orgs/new",
            operation="org.name.check",
            oid="-",
            resource={"type": "organization_name", "id": safe_name},
            params={"name": safe_name},
        ).as_dict()

    def preview_create_org(
        self,
        name: str,
        location: str | None = None,
        template: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_name = require_org_name(name)
        params: dict[str, Any] = {"name": safe_name}
        if location:
            params["loc"] = require_token(location, "location")
        if template:
            params["template"] = require_token(template, "template")
        return self._preview_mutation(
            operation="org.create",
            oid="-",
            method="POST",
            path="orgs/new",
            resource_type="organization",
            resource_id=safe_name,
            params=params,
            expected_effect=f"Create organization {safe_name!r}.",
            reversibility="Delete the new organization if creation was unintended.",
            side_effect_type="org_created",
            token_ttl_seconds=token_ttl_seconds,
        )

    def get_org_config_value(self, oid: str, config_name: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_path_segment(config_name, "config_name")
        return self._request(
            "GET",
            f"configs/{scoped_oid}/{quote(safe_name, safe='')}",
            operation="org.config.get",
            oid=scoped_oid,
            resource={"type": "organization_config_value", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def preview_set_org_config_value(
        self,
        oid: str,
        config_name: str,
        value: str,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_path_segment(config_name, "config_name")
        safe_value = require_config_value(value)
        return self._preview_mutation(
            operation="org.config.set",
            oid=scoped_oid,
            method="POST",
            path=f"configs/{scoped_oid}/{quote(safe_name, safe='')}",
            resource_type="organization_config_value",
            resource_id=safe_name,
            params={"value": safe_value},
            expected_effect=f"Set org config value {safe_name!r}.",
            reversibility="Set the config value back to its prior value if needed.",
            side_effect_type="org_config_value_set",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_dismiss_org_error(self, oid: str, component: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_component = require_path_segment(component, "component")
        return self._preview_mutation(
            operation="org.error.dismiss",
            oid=scoped_oid,
            method="DELETE",
            path=f"errors/{scoped_oid}/{quote(safe_component, safe='')}",
            resource_type="organization_error",
            resource_id=safe_component,
            expected_effect=f"Dismiss org error component {safe_component!r}.",
            reversibility="Dismissal only affects the current error record; wait for the component to emit a new error if it recurs.",
            side_effect_type="org_error_dismissed",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def get_org_delete_confirmation(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/delete",
            operation="org.delete.confirmation",
            oid=scoped_oid,
            resource={"type": "organization_delete_confirmation", "id": scoped_oid},
        ).as_dict()

    def preview_delete_org(self, oid: str, confirmation: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_confirmation = require_token(confirmation, "confirmation")
        return self._preview_mutation(
            operation="org.delete",
            oid=scoped_oid,
            method="DELETE",
            path=f"orgs/{scoped_oid}/delete",
            resource_type="organization",
            resource_id=scoped_oid,
            params={"confirmation": safe_confirmation},
            expected_effect=f"Delete organization {scoped_oid}.",
            reversibility="Organization deletion is not generally reversible.",
            side_effect_type="org_deleted",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_set_org_quota(self, oid: str, quota: int, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_quota = require_quota(quota)
        return self._preview_mutation(
            operation="org.quota.set",
            oid=scoped_oid,
            method="POST",
            path=f"orgs/{scoped_oid}/quota",
            resource_type="organization_quota",
            resource_id=scoped_oid,
            params={"quota": safe_quota},
            expected_effect=f"Set organization sensor quota to {safe_quota}.",
            reversibility="Run another quota preview with the prior quota value.",
            side_effect_type="org_quota_set",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_rename_org(self, oid: str, new_name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(new_name, "new_name")
        return self._preview_mutation(
            operation="org.rename",
            oid=scoped_oid,
            method="POST",
            path=f"orgs/{scoped_oid}/name",
            resource_type="organization",
            resource_id=scoped_oid,
            params={"name": safe_name},
            expected_effect=f"Rename organization {scoped_oid} to {safe_name!r}.",
            reversibility="Run another rename preview with the previous organization name.",
            side_effect_type="org_renamed",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def get_billing_status(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/billing/status",
            operation="billing.status",
            oid=scoped_oid,
            resource={"type": "billing_status", "id": scoped_oid},
        ).as_dict()

    def get_billing_details(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/billing/details",
            operation="billing.details",
            oid=scoped_oid,
            resource={"type": "billing_details", "id": scoped_oid},
        ).as_dict()

    def get_billing_invoice_url(self, oid: str, year: int, month: int, fmt: str | None = None) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_year = require_invoice_year(year)
        safe_month = require_invoice_month(month)
        safe_fmt = require_invoice_format(fmt)
        params = {"format": safe_fmt} if safe_fmt else None
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/billing/invoice/{safe_year}/{safe_month:02d}",
            operation="billing.invoice_url",
            oid=scoped_oid,
            resource={"type": "billing_invoice", "id": f"{safe_year}-{safe_month:02d}", "parent": {"type": "organization", "id": scoped_oid}},
            params=params,
        ).as_dict()

    def list_billing_plans(self, limit: int = 100) -> dict[str, Any]:
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            "plans",
            operation="billing.plans",
            oid="-",
            resource={"type": "billing_plan_collection", "id": "-"},
            limit=bounded_limit,
        ).as_dict()

    def list_groups(self, limit: int = 100) -> dict[str, Any]:
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            "groups",
            operation="group.list",
            oid="-",
            resource={"type": "group_collection", "id": "-"},
            limit=bounded_limit,
        ).as_dict()

    def preview_create_group(self, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        return self._preview_mutation(
            operation="group.create",
            oid="-",
            method="POST",
            path="groups",
            resource_type="group",
            resource_id=safe_name,
            params={"name": safe_name},
            expected_effect=f"Create group {safe_name!r}.",
            reversibility="Delete the group if it was created unintentionally.",
            side_effect_type="group_created",
            token_ttl_seconds=token_ttl_seconds,
        )

    def get_group(self, group_id: str) -> dict[str, Any]:
        safe_group_id = require_path_segment(group_id, "group_id")
        return self._request(
            "GET",
            f"groups/{quote(safe_group_id, safe='')}",
            operation="group.get",
            oid="-",
            resource={"type": "group", "id": safe_group_id},
        ).as_dict()

    def list_group_logs(self, group_id: str, limit: int = 100) -> dict[str, Any]:
        safe_group_id = require_path_segment(group_id, "group_id")
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"groups/{quote(safe_group_id, safe='')}/logs",
            operation="group.logs",
            oid="-",
            resource={"type": "group_log_collection", "id": safe_group_id},
            limit=bounded_limit,
        ).as_dict()

    def preview_delete_group(self, group_id: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_group_id = require_path_segment(group_id, "group_id")
        return self._preview_mutation(
            operation="group.delete",
            oid="-",
            method="DELETE",
            path=f"groups/{quote(safe_group_id, safe='')}",
            resource_type="group",
            resource_id=safe_group_id,
            expected_effect=f"Delete group {safe_group_id}.",
            reversibility="Recreate the group and memberships from a known-good definition if deletion was unintended.",
            side_effect_type="group_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_add_group_member(self, group_id: str, email: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_group_email_mutation("group.member.add", "POST", group_id, email, "users", "group_member_added", token_ttl_seconds)

    def preview_remove_group_member(self, group_id: str, email: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_group_email_mutation("group.member.remove", "DELETE", group_id, email, "users", "group_member_removed", token_ttl_seconds)

    def preview_add_group_owner(self, group_id: str, email: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_group_email_mutation("group.owner.add", "POST", group_id, email, "owners", "group_owner_added", token_ttl_seconds)

    def preview_remove_group_owner(self, group_id: str, email: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_group_email_mutation("group.owner.remove", "DELETE", group_id, email, "owners", "group_owner_removed", token_ttl_seconds)

    def preview_set_group_permissions(self, group_id: str, permissions: list[str] | str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_group_id = require_path_segment(group_id, "group_id")
        safe_permissions = require_permission_list(permissions)
        return self._preview_mutation(
            operation="group.permissions.set",
            oid="-",
            method="POST",
            path=f"groups/{quote(safe_group_id, safe='')}/permissions",
            resource_type="group_permissions",
            resource_id=safe_group_id,
            params={"perm": safe_permissions},
            expected_effect=f"Replace permissions on group {safe_group_id}.",
            reversibility="Run another permissions preview with the previous permission list.",
            side_effect_type="group_permissions_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_add_group_org(self, group_id: str, member_oid: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_group_org_mutation("group.org.add", "POST", group_id, member_oid, "group_org_added", token_ttl_seconds)

    def preview_remove_group_org(self, group_id: str, member_oid: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_group_org_mutation("group.org.remove", "DELETE", group_id, member_oid, "group_org_removed", token_ttl_seconds)

    def list_users(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/users",
            operation="user.list",
            oid=scoped_oid,
            resource={"type": "user_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def preview_invite_user(self, oid: str, email: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_email = require_email(email)
        return self._preview_mutation(
            operation="user.invite",
            oid=scoped_oid,
            method="POST",
            path=f"orgs/{scoped_oid}/users",
            resource_type="user",
            resource_id=safe_email,
            params={"email": safe_email},
            expected_effect=f"Invite {safe_email} to organization {scoped_oid}.",
            reversibility="Remove the user from the org if the invitation was unintended.",
            side_effect_type="user_invited",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_remove_user(self, oid: str, email: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_email = require_email(email)
        return self._preview_mutation(
            operation="user.remove",
            oid=scoped_oid,
            method="DELETE",
            path=f"orgs/{scoped_oid}/users",
            resource_type="user",
            resource_id=safe_email,
            params={"email": safe_email},
            expected_effect=f"Remove {safe_email} from organization {scoped_oid}.",
            reversibility="Invite the user again and restore permissions if removal was unintended.",
            side_effect_type="user_removed",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def list_user_permissions(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/users/permissions",
            operation="user.permission.list",
            oid=scoped_oid,
            resource={"type": "user_permission_collection", "id": scoped_oid},
        ).as_dict()

    def preview_add_user_permission(self, oid: str, email: str, permission: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_email = require_email(email)
        safe_permission = require_permission(permission)
        return self._preview_mutation(
            operation="user.permission.add",
            oid=scoped_oid,
            method="POST",
            path=f"orgs/{scoped_oid}/users/permissions",
            resource_type="user_permission",
            resource_id=f"{safe_email}:{safe_permission}",
            params={"email": safe_email, "perm": safe_permission},
            expected_effect=f"Grant {safe_permission} to {safe_email}.",
            reversibility="Preview and confirm user.permission.remove for the same permission.",
            side_effect_type="user_permission_added",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_remove_user_permission(self, oid: str, email: str, permission: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_email = require_email(email)
        safe_permission = require_permission(permission)
        return self._preview_mutation(
            operation="user.permission.remove",
            oid=scoped_oid,
            method="DELETE",
            path=f"orgs/{scoped_oid}/users/permissions",
            resource_type="user_permission",
            resource_id=f"{safe_email}:{safe_permission}",
            params={"email": safe_email, "perm": safe_permission},
            expected_effect=f"Revoke {safe_permission} from {safe_email}.",
            reversibility="Preview and confirm user.permission.add for the same permission.",
            side_effect_type="user_permission_removed",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_set_user_role(self, oid: str, email: str, role: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_email = require_email(email)
        safe_role = require_org_role(role)
        return self._preview_mutation(
            operation="user.role.set",
            oid=scoped_oid,
            method="PUT",
            path=f"orgs/{scoped_oid}/users/role",
            resource_type="user_role",
            resource_id=safe_email,
            json_body={"email": safe_email, "role": safe_role},
            expected_effect=f"Replace {safe_email}'s permissions with role {safe_role}.",
            reversibility="Restore the previous explicit permissions or role from audit evidence.",
            side_effect_type="user_role_set",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def list_api_keys(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/keys",
            operation="api_key.list",
            oid=scoped_oid,
            resource={"type": "api_key_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def preview_create_api_key(
        self,
        oid: str,
        name: str,
        permissions: list[str] | str,
        ip_range: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        safe_permissions = require_permission_list(permissions)
        params: dict[str, Any] = {"key_name": safe_name, "perms": ",".join(safe_permissions)}
        if ip_range:
            params["allowed_ip_range"] = require_token(ip_range, "ip_range")
        return self._preview_mutation(
            operation="api_key.create",
            oid=scoped_oid,
            method="POST",
            path=f"orgs/{scoped_oid}/keys",
            resource_type="api_key",
            resource_id=safe_name,
            params=params,
            expected_effect=f"Create API key {safe_name!r}.",
            reversibility="Delete the API key by key hash if creation was unintended.",
            side_effect_type="api_key_created",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_delete_api_key(self, oid: str, key_hash: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_key_hash = require_path_segment(key_hash, "key_hash")
        return self._preview_mutation(
            operation="api_key.delete",
            oid=scoped_oid,
            method="DELETE",
            path=f"orgs/{scoped_oid}/keys",
            resource_type="api_key",
            resource_id=safe_key_hash,
            params={"key_hash": safe_key_hash},
            expected_effect=f"Delete API key {safe_key_hash}.",
            reversibility="Create a replacement API key with equivalent permissions if deletion was unintended.",
            side_effect_type="api_key_deleted",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def list_installation_keys(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"installationkeys/{scoped_oid}",
            operation="installation_key.list",
            oid=scoped_oid,
            resource={"type": "installation_key_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def get_installation_key(self, oid: str, installation_key_id: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_iid = require_path_segment(installation_key_id, "installation_key_id")
        return self._request(
            "GET",
            f"installationkeys/{scoped_oid}/{quote(safe_iid, safe='')}",
            operation="installation_key.get",
            oid=scoped_oid,
            resource={"type": "installation_key", "id": safe_iid, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def preview_create_installation_key(
        self,
        oid: str,
        description: str,
        tags: list[str] | str | None = None,
        use_public_ca: bool = False,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_description = require_token(description, "description")
        params: dict[str, Any] = {
            "desc": safe_description,
            "use_public_root_ca": bool_param(bool(use_public_ca)),
        }
        checked_tags = require_string_list(tags, "tags")
        if checked_tags:
            params["tags"] = ",".join(checked_tags)
        return self._preview_mutation(
            operation="installation_key.create",
            oid=scoped_oid,
            method="POST",
            path=f"installationkeys/{scoped_oid}",
            resource_type="installation_key",
            resource_id=safe_description,
            params=params,
            expected_effect=f"Create installation key {safe_description!r}.",
            reversibility="Delete the installation key if creation was unintended.",
            side_effect_type="installation_key_created",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_delete_installation_key(self, oid: str, installation_key_id: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_iid = require_path_segment(installation_key_id, "installation_key_id")
        return self._preview_mutation(
            operation="installation_key.delete",
            oid=scoped_oid,
            method="DELETE",
            path=f"installationkeys/{scoped_oid}",
            resource_type="installation_key",
            resource_id=safe_iid,
            params={"iid": safe_iid},
            expected_effect=f"Delete installation key {safe_iid}.",
            reversibility="Create a replacement installation key if deletion was unintended.",
            side_effect_type="installation_key_deleted",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def list_outputs(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"outputs/{scoped_oid}",
            operation="output.list",
            oid=scoped_oid,
            resource={"type": "output_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def preview_create_ingestion_key(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        return self._preview_mutation(
            operation="ingestion_key.create",
            oid=scoped_oid,
            method="POST",
            path=f"insight/{scoped_oid}/ingestion_keys",
            resource_type="ingestion_key",
            resource_id=safe_name,
            params={"name": safe_name},
            expected_effect=f"Create ingestion key {safe_name!r}.",
            reversibility="Delete the ingestion key if creation was unintended.",
            side_effect_type="ingestion_key_created",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_delete_ingestion_key(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        return self._preview_mutation(
            operation="ingestion_key.delete",
            oid=scoped_oid,
            method="DELETE",
            path=f"insight/{scoped_oid}/ingestion_keys",
            resource_type="ingestion_key",
            resource_id=safe_name,
            params={"name": safe_name},
            expected_effect=f"Delete ingestion key {safe_name!r}.",
            reversibility="Create a replacement ingestion key if deletion was unintended.",
            side_effect_type="ingestion_key_deleted",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_create_output(
        self,
        oid: str,
        name: str,
        module: str,
        data_type: str,
        config: dict[str, Any] | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        params: dict[str, Any] = {
            "name": safe_name,
            "module": require_token(module, "module"),
            "type": require_token(data_type, "data_type"),
        }
        checked_config = require_dict(config, "config") or {}
        params.update(checked_config)
        return self._preview_mutation(
            operation="output.create",
            oid=scoped_oid,
            method="POST",
            path=f"outputs/{scoped_oid}",
            resource_type="output",
            resource_id=safe_name,
            params=params,
            expected_effect=f"Create output {safe_name!r}.",
            reversibility="Delete the output if creation was unintended.",
            side_effect_type="output_created",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_delete_output(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        return self._preview_mutation(
            operation="output.delete",
            oid=scoped_oid,
            method="DELETE",
            path=f"outputs/{scoped_oid}",
            resource_type="output",
            resource_id=safe_name,
            params={"name": safe_name},
            expected_effect=f"Delete output {safe_name!r}.",
            reversibility="Recreate the output from its previous configuration if deletion was unintended.",
            side_effect_type="output_deleted",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def list_extension_subscriptions(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/subscriptions",
            operation="extension.list_subscribed",
            oid=scoped_oid,
            resource={"type": "extension_subscription_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def preview_subscribe_extension(self, oid: str, extension_name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_extension_name(extension_name)
        return self._preview_mutation(
            operation="extension.subscribe",
            oid=scoped_oid,
            method="POST",
            path=f"orgs/{scoped_oid}/subscription/extension/{quote(safe_name, safe='')}",
            resource_type="extension_subscription",
            resource_id=safe_name,
            params={},
            expected_effect=f"Subscribe organization {scoped_oid} to extension {safe_name}.",
            reversibility="Preview and confirm extension.unsubscribe for the same extension.",
            side_effect_type="extension_subscribed",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_unsubscribe_extension(self, oid: str, extension_name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_extension_name(extension_name)
        return self._preview_mutation(
            operation="extension.unsubscribe",
            oid=scoped_oid,
            method="DELETE",
            path=f"orgs/{scoped_oid}/subscription/extension/{quote(safe_name, safe='')}",
            resource_type="extension_subscription",
            resource_id=safe_name,
            params={},
            expected_effect=f"Unsubscribe organization {scoped_oid} from extension {safe_name}.",
            reversibility="Preview and confirm extension.subscribe for the same extension.",
            side_effect_type="extension_unsubscribed",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_rekey_extension(self, oid: str, extension_name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_extension_name(extension_name)
        return self._preview_mutation(
            operation="extension.rekey",
            oid=scoped_oid,
            method="PATCH",
            path=f"orgs/{scoped_oid}/subscription/extension/{quote(safe_name, safe='')}",
            resource_type="extension_subscription",
            resource_id=safe_name,
            params={},
            expected_effect=f"Rotate the API key for extension subscription {safe_name}.",
            reversibility="Rekeying is not reversible; update dependent systems with the newly returned key material if applicable.",
            side_effect_type="extension_rekeyed",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def list_available_extensions(self, limit: int = 100) -> dict[str, Any]:
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            "extension/definition",
            operation="extension.list_available",
            oid="-",
            resource={"type": "extension_definition_collection", "id": "-"},
            params={},
            limit=bounded_limit,
        ).as_dict()

    def get_extension(self, extension_name: str) -> dict[str, Any]:
        safe_name = require_extension_name(extension_name)
        return self._request(
            "GET",
            f"extension/definition/{quote(safe_name, safe='')}",
            operation="extension.get",
            oid="-",
            resource={"type": "extension_definition", "id": safe_name},
        ).as_dict()

    def preview_create_extension(
        self,
        extension_definition: dict[str, Any],
        extension_name: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_definition = require_dict(extension_definition, "extension_definition") or {}
        safe_name = self._extension_definition_id(safe_definition, extension_name)
        return self._preview_mutation(
            operation="extension.create",
            oid="-",
            method="POST",
            path="extension/definition",
            resource_type="extension_definition",
            resource_id=safe_name,
            params={},
            json_body=safe_definition,
            expected_effect=f"Create extension definition {safe_name}.",
            reversibility="Delete the extension definition if creation was unintended.",
            side_effect_type="extension_created",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_update_extension(
        self,
        extension_definition: dict[str, Any],
        extension_name: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_definition = require_dict(extension_definition, "extension_definition") or {}
        safe_name = self._extension_definition_id(safe_definition, extension_name)
        return self._preview_mutation(
            operation="extension.update",
            oid="-",
            method="PUT",
            path="extension/definition",
            resource_type="extension_definition",
            resource_id=safe_name,
            params={},
            json_body=safe_definition,
            expected_effect=f"Update extension definition {safe_name}.",
            reversibility="Restore the previous extension definition body if the update was unintended.",
            side_effect_type="extension_updated",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_extension(self, extension_name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_name = require_extension_name(extension_name)
        return self._preview_mutation(
            operation="extension.delete",
            oid="-",
            method="DELETE",
            path=f"extension/definition/{quote(safe_name, safe='')}",
            resource_type="extension_definition",
            resource_id=safe_name,
            expected_effect=f"Delete extension definition {safe_name}.",
            reversibility="Recreate the extension definition from a known-good body if deletion was unintended.",
            side_effect_type="extension_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def get_extension_schema(self, oid: str, extension_name: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_extension_name(extension_name)
        return self._request(
            "GET",
            f"extension/schema/{quote(safe_name, safe='')}",
            operation="extension.schema.get",
            oid=scoped_oid,
            resource={"type": "extension_schema", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
            params={"oid": scoped_oid},
        ).as_dict()

    def preview_extension_request(
        self,
        oid: str,
        extension_name: str,
        action: str,
        data: dict[str, Any] | None = None,
        impersonate: bool = False,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        if impersonate:
            raise ValidationError("impersonate is not supported because it would expose a JWT in preview data")
        scoped_oid = require_oid(oid)
        safe_name = require_extension_name(extension_name)
        safe_action = require_token(action, "action")
        safe_data = require_dict(data, "data") or {}
        return self._preview_mutation(
            operation="extension.request",
            oid=scoped_oid,
            method="POST",
            path=f"extension/request/{quote(safe_name, safe='')}",
            resource_type="extension_request",
            resource_id=f"{safe_name}:{safe_action}",
            params=extension_request_params(scoped_oid, safe_action, safe_data),
            expected_effect=f"Call extension {safe_name} action {safe_action}.",
            reversibility="Extension request side effects are action-specific; inspect the extension action documentation before confirming.",
            side_effect_type="extension_request_executed",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def list_vulnerability_cves(
        self,
        oid: str,
        cursor: str | None = None,
        limit: int = 100,
        sort_by: str | None = None,
        sort_asc: bool | None = None,
        filters: dict[str, list[str]] | None = None,
        search: dict[str, Any] | None = None,
        include_tags: bool | None = None,
        include_enrichment: bool | None = None,
        filter_via_state: bool | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        data = self._vulnerability_query(
            cursor=cursor,
            limit=bounded_limit,
            sort_by=sort_by,
            sort_asc=sort_asc,
            filters=filters,
            search=search,
            include_tags=include_tags,
            include_enrichment=include_enrichment,
            filter_via_state=filter_via_state,
        )
        return self._extension_request(
            scoped_oid,
            "query_cves",
            data,
            operation="vulnerability.cve.list",
            resource={"type": "vulnerability_cve_collection", "id": scoped_oid},
            limit=bounded_limit,
        )

    def get_vulnerability_cve(
        self,
        oid: str,
        cve: str,
        include_enrichment: bool | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        data: dict[str, Any] = {"cve_id": require_cve(cve)}
        if include_enrichment is not None:
            data["include_enrichment"] = require_bool_or_none(include_enrichment, "include_enrichment")
        return self._extension_request(
            scoped_oid,
            "query_cve",
            data,
            operation="vulnerability.cve.get",
            resource={"type": "vulnerability_cve", "id": data["cve_id"], "parent": {"type": "organization", "id": scoped_oid}},
        )

    def list_vulnerability_cve_hosts(
        self,
        oid: str,
        cve: str,
        cursor: str | None = None,
        limit: int = 100,
        sort_by: str | None = None,
        sort_asc: bool | None = None,
        filters: dict[str, list[str]] | None = None,
        search: dict[str, Any] | None = None,
        include_tags: bool | None = None,
        filter_via_state: bool | None = None,
        normalized_package_name: str | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        safe_cve = require_cve(cve)
        data = self._vulnerability_query(
            cursor=cursor,
            limit=bounded_limit,
            sort_by=sort_by,
            sort_asc=sort_asc,
            filters=filters,
            search=search,
            include_tags=include_tags,
            filter_via_state=filter_via_state,
        )
        data["cve"] = safe_cve
        if normalized_package_name:
            data["normalized_package_name"] = require_token(normalized_package_name, "normalized_package_name")
        return self._extension_request(
            scoped_oid,
            "query_cve_vuln_hosts",
            data,
            operation="vulnerability.cve.hosts",
            resource={"type": "vulnerability_host_collection", "id": safe_cve, "parent": {"type": "organization", "id": scoped_oid}},
            limit=bounded_limit,
        )

    def list_vulnerability_cve_packages(
        self,
        oid: str,
        cve: str,
        cursor: str | None = None,
        limit: int = 100,
        sort_by: str | None = None,
        sort_asc: bool | None = None,
        include_enrichment: bool | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        safe_cve = require_cve(cve)
        data: dict[str, Any] = {"cve": safe_cve, "limit": bounded_limit}
        if cursor is not None:
            data["cursor"] = require_token(cursor, "cursor")
        if sort_by is not None:
            data["sort_by"] = require_token(sort_by, "sort_by")
        if sort_asc is not None:
            data["sort_asc"] = require_bool_or_none(sort_asc, "sort_asc")
        if include_enrichment is not None:
            data["include_enrichment"] = require_bool_or_none(include_enrichment, "include_enrichment")
        return self._extension_request(
            scoped_oid,
            "query_cve_vuln_packages",
            data,
            operation="vulnerability.cve.packages",
            resource={"type": "vulnerability_package_collection", "id": safe_cve, "parent": {"type": "organization", "id": scoped_oid}},
            limit=bounded_limit,
        )

    def list_vulnerability_endpoints(
        self,
        oid: str,
        cursor: str | None = None,
        limit: int = 100,
        sort_by: str | None = None,
        sort_asc: bool | None = None,
        filters: dict[str, list[str]] | None = None,
        search: dict[str, Any] | None = None,
        include_tags: bool | None = None,
        filter_via_state: bool | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        data = self._vulnerability_query(
            cursor=cursor,
            limit=bounded_limit,
            sort_by=sort_by,
            sort_asc=sort_asc,
            filters=filters,
            search=search,
            include_tags=include_tags,
            filter_via_state=filter_via_state,
        )
        return self._extension_request(
            scoped_oid,
            "query_endpoints",
            data,
            operation="vulnerability.endpoint.list",
            resource={"type": "vulnerability_endpoint_collection", "id": scoped_oid},
            limit=bounded_limit,
        )

    def list_vulnerability_host_packages(
        self,
        oid: str,
        sensor_id: str,
        cursor: str | None = None,
        limit: int = 100,
        sort_by: str | None = None,
        sort_asc: bool | None = None,
        filters: dict[str, list[str]] | None = None,
        search: dict[str, Any] | None = None,
        include_tags: bool | None = None,
        include_enrichment: bool | None = None,
        filter_via_state: bool | None = None,
        rollup_subpackages: bool | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        bounded_limit = require_limit(limit)
        data = self._vulnerability_query(
            cursor=cursor,
            limit=bounded_limit,
            sort_by=sort_by,
            sort_asc=sort_asc,
            filters=filters,
            search=search,
            include_tags=include_tags,
            include_enrichment=include_enrichment,
            filter_via_state=filter_via_state,
        )
        data["sid"] = safe_sensor_id
        if rollup_subpackages is not None:
            data["rollup_subpackages"] = require_bool_or_none(rollup_subpackages, "rollup_subpackages")
        return self._extension_request(
            scoped_oid,
            "query_host_vuln_packages",
            data,
            operation="vulnerability.host.packages",
            resource={"type": "vulnerability_package_collection", "id": safe_sensor_id, "parent": {"type": "organization", "id": scoped_oid}},
            limit=bounded_limit,
        )

    def get_vulnerability_dashboard(self, oid: str, sort_asc: bool | None = None) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        data: dict[str, Any] = {}
        if sort_asc is not None:
            data["sort_asc"] = require_bool_or_none(sort_asc, "sort_asc")
        return self._extension_request(
            scoped_oid,
            "query_dashboard",
            data,
            operation="vulnerability.dashboard",
            resource={"type": "vulnerability_dashboard", "id": scoped_oid},
        )

    def list_vulnerability_resolutions(
        self,
        oid: str,
        scope: str | None = None,
        resolutions: list[str] | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        data: dict[str, Any] = {"limit": bounded_limit}
        if scope is not None:
            checked_scope = str(scope).lower()
            if checked_scope not in _VULN_SCOPES:
                raise ValidationError("scope must be org or host")
            data["scope"] = checked_scope
        checked_resolutions = require_vuln_resolutions(resolutions)
        if checked_resolutions is not None:
            data["resolutions"] = checked_resolutions
        if cursor is not None:
            data["cursor"] = require_token(cursor, "cursor")
        return self._extension_request(
            scoped_oid,
            "list_finding_resolutions",
            data,
            operation="vulnerability.resolution.list",
            resource={"type": "vulnerability_resolution_collection", "id": scoped_oid},
            limit=bounded_limit,
        )

    def list_vulnerability_snapshots(
        self,
        oid: str,
        days: int = 30,
        severities: list[str] | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        data: dict[str, Any] = {"days": require_days(days)}
        checked_severities = require_vuln_severities(severities)
        if checked_severities is not None:
            data["severities"] = checked_severities
        return self._extension_request(
            scoped_oid,
            "query_daily_snapshots",
            data,
            operation="vulnerability.snapshot.list",
            resource={"type": "vulnerability_snapshot_collection", "id": scoped_oid},
        )

    def get_vulnerability_epss_history(self, oid: str, cve: str, days: int = 90) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_cve = require_cve(cve)
        data = {"cve": safe_cve, "days": require_days(days)}
        return self._extension_request(
            scoped_oid,
            "query_epss_history",
            data,
            operation="vulnerability.epss_history",
            resource={"type": "vulnerability_epss_history", "id": safe_cve, "parent": {"type": "organization", "id": scoped_oid}},
        )

    def list_artifact_rules(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"insight/{scoped_oid}/artifacts/rules",
            operation="artifact_rule.list",
            oid=scoped_oid,
            resource={"type": "artifact_rule_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def preview_set_artifact_rule(
        self,
        oid: str,
        name: str,
        platforms: list[str] | str,
        patterns: list[str] | str,
        is_delete_after: bool = False,
        retention_days: int = 30,
        tags: list[str] | str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        body: dict[str, Any] = {
            "name": safe_name,
            "platforms": require_string_list(platforms, "platforms") or [],
            "patterns": require_string_list(patterns, "patterns") or [],
            "is_delete_after": bool(is_delete_after),
            "days_retention": require_retention_days(retention_days) or 30,
        }
        checked_tags = require_string_list(tags, "tags")
        if checked_tags is not None:
            body["tags"] = checked_tags
        return self._create_mutation_preview(
            operation="artifact_rule.set",
            oid=scoped_oid,
            method="POST",
            path=f"insight/{scoped_oid}/artifacts/rules",
            resource={"type": "artifact_rule", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
            data=None,
            json_body=body,
            expected_effect=f"Create or update artifact collection rule {safe_name!r}.",
            reversibility="Restore the previous artifact rule body or delete the rule if it was newly created.",
            side_effects=[{"type": "artifact_rule_set", "resource": {"type": "artifact_rule", "id": safe_name}}],
            token_ttl_seconds=token_ttl,
        )

    def preview_delete_artifact_rule(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation="artifact_rule.delete",
            oid=scoped_oid,
            method="DELETE",
            path=f"insight/{scoped_oid}/artifacts/rules",
            resource={"type": "artifact_rule", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
            params={"name": safe_name},
            data=None,
            json_body=None,
            expected_effect=f"Delete artifact collection rule {safe_name!r}.",
            reversibility="Recreate the artifact rule from a known-good definition if deletion was unintended.",
            side_effects=[{"type": "artifact_rule_deleted", "resource": {"type": "artifact_rule", "id": safe_name}}],
            token_ttl_seconds=token_ttl,
        )

    def list_ingestion_keys(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"insight/{scoped_oid}/ingestion_keys",
            operation="ingestion_key.list",
            oid=scoped_oid,
            resource={"type": "ingestion_key_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def list_logging_rules(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "POST",
            f"service/{scoped_oid}/logging",
            operation="logging_rule.list",
            oid=scoped_oid,
            resource={"type": "logging_rule_collection", "id": scoped_oid},
            params=service_request_params({"action": "list_rules"}),
            limit=bounded_limit,
        ).as_dict()

    def preview_set_logging_rule(
        self,
        oid: str,
        name: str,
        patterns: list[str] | str,
        tags: list[str] | str | None = None,
        platforms: list[str] | str | None = None,
        retention_days: int | None = None,
        delete_after: bool = False,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        request_data: dict[str, Any] = {
            "action": "add_rule",
            "name": safe_name,
            "patterns": require_string_list(patterns, "patterns") or [],
        }
        checked_tags = require_string_list(tags, "tags")
        if checked_tags is not None:
            request_data["tags"] = checked_tags
        checked_platforms = require_string_list(platforms, "platforms")
        if checked_platforms is not None:
            request_data["platforms"] = checked_platforms
        checked_retention = require_retention_days(retention_days)
        if checked_retention is not None:
            request_data["days_retention"] = str(checked_retention)
        if delete_after:
            request_data["is_delete_after"] = "true"
        return self._preview_service_request(
            operation="logging_rule.set",
            oid=oid,
            service="logging",
            request_data=request_data,
            resource_type="logging_rule",
            resource_id=safe_name,
            expected_effect=f"Create or update logging rule {safe_name!r}.",
            reversibility="Restore the prior logging rule or delete this rule if it was newly created.",
            side_effect_type="logging_rule_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_logging_rule(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        return self._preview_service_request(
            operation="logging_rule.delete",
            oid=oid,
            service="logging",
            request_data={"action": "remove_rule", "name": safe_name},
            resource_type="logging_rule",
            resource_id=safe_name,
            expected_effect=f"Delete logging rule {safe_name!r}.",
            reversibility="Recreate the logging rule from a known-good definition if deletion was unintended.",
            side_effect_type="logging_rule_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_dr_rules(self, oid: str, namespace: str | None = None, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_namespace = require_dr_namespace(namespace)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"hive/dr-{safe_namespace}/{scoped_oid}",
            operation="dr_rule.list",
            oid=scoped_oid,
            resource={"type": "dr_rule_collection", "id": f"dr-{safe_namespace}", "parent": {"type": "organization", "id": scoped_oid}},
            limit=bounded_limit,
        ).as_dict()

    def get_dr_rule(self, oid: str, name: str, namespace: str | None = None) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_namespace = require_dr_namespace(namespace)
        safe_name = require_token(name, "name")
        return self._request(
            "GET",
            f"hive/dr-{safe_namespace}/{scoped_oid}/{quote(safe_name, safe='')}/data",
            operation="dr_rule.get",
            oid=scoped_oid,
            resource={"type": "dr_rule", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def preview_set_dr_rule(
        self,
        oid: str,
        name: str,
        data: dict[str, Any],
        namespace: str | None = None,
        enabled: bool | None = None,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        expiry: int | None = None,
        etag: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_namespace = require_dr_namespace(namespace)
        return self._preview_hive_set(
            operation="dr_rule.set",
            oid=oid,
            hive_name=f"dr-{safe_namespace}",
            name=name,
            data=data,
            resource_type="dr_rule",
            enabled=enabled,
            tags=tags,
            comment=comment,
            expiry=expiry,
            etag=etag,
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_dr_rule(self, oid: str, name: str, namespace: str | None = None, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_namespace = require_dr_namespace(namespace)
        return self._preview_hive_delete(
            operation="dr_rule.delete",
            oid=oid,
            hive_name=f"dr-{safe_namespace}",
            name=name,
            resource_type="dr_rule",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_fp_rules(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"hive/fp/{scoped_oid}",
            operation="fp_rule.list",
            oid=scoped_oid,
            resource={"type": "fp_rule_collection", "id": "fp", "parent": {"type": "organization", "id": scoped_oid}},
            limit=bounded_limit,
        ).as_dict()

    def get_fp_rule(self, oid: str, name: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        return self._request(
            "GET",
            f"hive/fp/{scoped_oid}/{quote(safe_name, safe='')}/data",
            operation="fp_rule.get",
            oid=scoped_oid,
            resource={"type": "fp_rule", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def preview_set_fp_rule(
        self,
        oid: str,
        name: str,
        data: dict[str, Any],
        enabled: bool | None = None,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        expiry: int | None = None,
        etag: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        return self._preview_hive_set(
            operation="fp_rule.set",
            oid=oid,
            hive_name="fp",
            name=name,
            data=data,
            resource_type="fp_rule",
            enabled=enabled,
            tags=tags,
            comment=comment,
            expiry=expiry,
            etag=etag,
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_fp_rule(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_hive_delete(
            operation="fp_rule.delete",
            oid=oid,
            hive_name="fp",
            name=name,
            resource_type="fp_rule",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_integrity_rules(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "POST",
            f"service/{scoped_oid}/integrity",
            operation="integrity_rule.list",
            oid=scoped_oid,
            resource={"type": "integrity_rule_collection", "id": scoped_oid},
            params=service_request_params({"action": "list_rules"}),
            limit=bounded_limit,
        ).as_dict()

    def get_integrity_rule(self, oid: str, name: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        result = self._request(
            "POST",
            f"service/{scoped_oid}/integrity",
            operation="integrity_rule.get",
            oid=scoped_oid,
            resource={"type": "integrity_rule", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
            params=service_request_params({"action": "list_rules"}),
        ).as_dict()
        if result.get("ok") and isinstance(result.get("data"), dict):
            rules = result["data"]
            if safe_name in rules:
                result["data"] = rules[safe_name]
                result["meta"]["summary"] = summarize_data(result["data"])
            else:
                result["ok"] = False
                result["data"] = None
                result["error"] = {
                    "code": "resource_not_found",
                    "class": "not_found",
                    "message": f"Integrity rule {safe_name!r} was not found.",
                    "retryable": False,
                    "same_input_retryable": False,
                    "suggested_next_actions": ["Call lc_list_integrity_rules to inspect available rule names."],
                }
                result["meta"]["summary"] = {"shape": "empty"}
        return result

    def preview_set_integrity_rule(
        self,
        oid: str,
        name: str,
        patterns: list[str] | str,
        tags: list[str] | str | None = None,
        platforms: list[str] | str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        request_data: dict[str, Any] = {
            "action": "add_rule",
            "name": safe_name,
            "patterns": require_string_list(patterns, "patterns") or [],
        }
        checked_tags = require_string_list(tags, "tags")
        if checked_tags is not None:
            request_data["tags"] = checked_tags
        checked_platforms = require_string_list(platforms, "platforms")
        if checked_platforms is not None:
            request_data["platforms"] = checked_platforms
        return self._preview_service_request(
            operation="integrity_rule.set",
            oid=oid,
            service="integrity",
            request_data=request_data,
            resource_type="integrity_rule",
            resource_id=safe_name,
            expected_effect=f"Create or update integrity rule {safe_name!r}.",
            reversibility="Restore the prior integrity rule or delete this rule if it was newly created.",
            side_effect_type="integrity_rule_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_integrity_rule(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        return self._preview_service_request(
            operation="integrity_rule.delete",
            oid=oid,
            service="integrity",
            request_data={"action": "remove_rule", "name": safe_name},
            resource_type="integrity_rule",
            resource_id=safe_name,
            expected_effect=f"Delete integrity rule {safe_name!r}.",
            reversibility="Recreate the integrity rule from a known-good definition if deletion was unintended.",
            side_effect_type="integrity_rule_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def validate_usp_mapping(
        self,
        oid: str,
        platform: str,
        mapping: dict[str, Any] | None = None,
        mappings: list[dict[str, Any]] | None = None,
        text_input: str | None = None,
        json_input: dict[str, Any] | list[dict[str, Any]] | None = None,
        hostname: str | None = None,
        indexing: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        body: dict[str, Any] = {"platform": require_token(platform, "platform")}
        checked_mapping = require_dict(mapping, "mapping")
        if checked_mapping is not None:
            body["mapping"] = checked_mapping
        checked_mappings = require_dict_list(mappings, "mappings", maximum=100)
        if checked_mappings is not None:
            body["mappings"] = checked_mappings
        if text_input is not None:
            if not isinstance(text_input, str) or len(text_input.encode()) > 100_000 or "\x00" in text_input:
                raise ValidationError("text_input must be a string under 100000 bytes without NUL bytes")
            body["text_input"] = text_input
        if json_input is not None:
            if isinstance(json_input, dict):
                body["json_input"] = [require_json_size(json_input, "json_input")]
            elif isinstance(json_input, list) and all(isinstance(item, dict) for item in json_input):
                body["json_input"] = require_json_size(json_input, "json_input")
            else:
                raise ValidationError("json_input must be an object or list of objects")
        if hostname is not None:
            body["hostname"] = require_token(hostname, "hostname")
        checked_indexing = require_dict(indexing, "indexing")
        if checked_indexing is not None:
            body["indexing"] = checked_indexing
        require_json_size(body, "USP validation payload")
        return self._request(
            "POST",
            f"usp/validate/{scoped_oid}",
            operation="usp.validate",
            oid=scoped_oid,
            resource={"type": "usp_validation", "id": scoped_oid},
            json_body=body,
        ).as_dict()

    def list_yara_rules(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "POST",
            f"service/{scoped_oid}/yara",
            operation="yara_rule.list",
            oid=scoped_oid,
            resource={"type": "yara_rule_collection", "id": scoped_oid},
            params=service_request_params({"action": "list_rules"}),
            limit=bounded_limit,
        ).as_dict()

    def preview_yara_scan(
        self,
        oid: str,
        sensor_id: str,
        rule: str,
        timeout_seconds: int | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_sensor_id = require_oid(sensor_id)
        if not isinstance(rule, str) or not rule.strip() or len(rule.encode()) > 200_000 or "\x00" in rule:
            raise ValidationError("rule must be a non-empty YARA source string under 200000 bytes")
        request_data: dict[str, Any] = {"action": "scan", "sid": safe_sensor_id, "rule": rule}
        if timeout_seconds is not None:
            request_data["timeout"] = str(require_seconds(timeout_seconds, "timeout_seconds", minimum=1, maximum=3600))
        return self._preview_service_request(
            operation="yara.scan",
            oid=oid,
            service="yara",
            request_data=request_data,
            resource_type="yara_scan",
            resource_id=safe_sensor_id,
            expected_effect=f"Run an ad-hoc YARA scan on sensor {safe_sensor_id}.",
            reversibility="YARA scan execution is not reversible; inspect returned job/results and take compensating action if needed.",
            side_effect_type="yara_scan_started",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_set_yara_rule(
        self,
        oid: str,
        name: str,
        sources: list[str] | str,
        tags: list[str] | str | None = None,
        platforms: list[str] | str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        request_data: dict[str, Any] = {
            "action": "add_rule",
            "name": safe_name,
            "sources": json.dumps(require_string_list(sources, "sources") or []),
        }
        checked_tags = require_string_list(tags, "tags")
        if checked_tags is not None:
            request_data["tags"] = json.dumps(checked_tags)
        checked_platforms = require_string_list(platforms, "platforms")
        if checked_platforms is not None:
            request_data["platforms"] = json.dumps(checked_platforms)
        return self._preview_service_request(
            operation="yara_rule.set",
            oid=oid,
            service="yara",
            request_data=request_data,
            resource_type="yara_rule",
            resource_id=safe_name,
            expected_effect=f"Create or update YARA rule {safe_name!r}.",
            reversibility="Restore the prior YARA rule or delete this rule if it was newly created.",
            side_effect_type="yara_rule_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_yara_rule(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        return self._preview_service_request(
            operation="yara_rule.delete",
            oid=oid,
            service="yara",
            request_data={"action": "remove_rule", "name": safe_name},
            resource_type="yara_rule",
            resource_id=safe_name,
            expected_effect=f"Delete YARA rule {safe_name!r}.",
            reversibility="Recreate the YARA rule from a known-good definition if deletion was unintended.",
            side_effect_type="yara_rule_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_yara_sources(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "POST",
            f"service/{scoped_oid}/yara",
            operation="yara_source.list",
            oid=scoped_oid,
            resource={"type": "yara_source_collection", "id": scoped_oid},
            params=service_request_params({"action": "list_sources"}),
            limit=bounded_limit,
        ).as_dict()

    def get_yara_source(self, oid: str, name: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        return self._request(
            "POST",
            f"service/{scoped_oid}/yara",
            operation="yara_source.get",
            oid=scoped_oid,
            resource={"type": "yara_source", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
            params=service_request_params({"action": "get_source", "name": safe_name}),
        ).as_dict()

    def preview_set_yara_source(self, oid: str, name: str, source: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        if not isinstance(source, str) or not source.strip() or len(source.encode()) > 200_000 or "\x00" in source:
            raise ValidationError("source must be a non-empty YARA source string under 200000 bytes")
        return self._preview_service_request(
            operation="yara_source.set",
            oid=oid,
            service="yara",
            request_data={"action": "add_source", "name": safe_name, "source": source},
            resource_type="yara_source",
            resource_id=safe_name,
            expected_effect=f"Create or update YARA source {safe_name!r}.",
            reversibility="Restore the prior YARA source or delete this source if it was newly created.",
            side_effect_type="yara_source_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_yara_source(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        return self._preview_service_request(
            operation="yara_source.delete",
            oid=oid,
            service="yara",
            request_data={"action": "remove_source", "name": safe_name},
            resource_type="yara_source",
            resource_id=safe_name,
            expected_effect=f"Delete YARA source {safe_name!r}.",
            reversibility="Recreate the YARA source from a known-good definition if deletion was unintended.",
            side_effect_type="yara_source_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_pending_mutations(self) -> dict[str, Any]:
        self._prune_expired_mutations()
        now = time.time()
        previews = [self._preview_data(mutation, now) for mutation in self._pending_mutations.values()]
        return ToolResponse(
            ok=True,
            operation="mutation.pending.list",
            request_id=f"req_{uuid.uuid4().hex}",
            resource={"type": "mutation_preview_collection", "id": "local"},
            state={"current": "ready"},
            data={"previews": previews},
            side_effects=[],
            warnings=[],
            meta={"summary": {"shape": "object", "previews_count": len(previews)}, "truncated": False},
            observed_at=observed_at(),
        ).as_dict()

    def cancel_mutation(self, confirmation_token: str) -> dict[str, Any]:
        token = require_confirmation_token(confirmation_token)
        self._prune_expired_mutations()
        mutation = self._pending_mutations.pop(token, None)
        if mutation is None:
            return self._mutation_token_error(
                "mutation.cancel",
                token,
                "mutation_preview_not_found",
                "No active mutation preview exists for that confirmation token.",
            )
        return ToolResponse(
            ok=True,
            operation="mutation.cancel",
            request_id=f"req_{uuid.uuid4().hex}",
            resource=mutation.resource,
            state={"previous": "pending", "current": "cancelled"},
            data={"cancelled_operation": mutation.operation, "confirmation_token": token},
            side_effects=[{"type": "local_preview_deleted", "resource": mutation.resource}],
            warnings=[],
            meta={"summary": {"cancelled": True, "operation": mutation.operation}, "truncated": False},
            observed_at=observed_at(),
        ).as_dict()

    def preview_add_sensor_tag(
        self,
        oid: str,
        sensor_id: str,
        tag: str,
        ttl_seconds: int = 0,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        safe_tag = require_token(tag, "tag")
        ttl = require_ttl_seconds(ttl_seconds)
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        data = {"tags": safe_tag, "ttl": ttl}
        return self._create_mutation_preview(
            operation="sensor.tag.add",
            oid=scoped_oid,
            method="POST",
            path=f"{safe_sensor_id}/tags",
            resource={
                "type": "sensor_tag",
                "id": safe_tag,
                "parent": {"type": "sensor", "id": safe_sensor_id, "parent": {"type": "organization", "id": scoped_oid}},
            },
            params=data,
            data=None,
            json_body=None,
            expected_effect=f"Add tag {safe_tag!r} to sensor {safe_sensor_id}.",
            reversibility="Remove the same tag from the sensor. TTL 0 means no automatic expiry.",
            side_effects=[
                {
                    "type": "sensor_tag_added",
                    "resource": {"type": "sensor", "id": safe_sensor_id},
                    "tag": safe_tag,
                    "ttl_seconds": ttl,
                }
            ],
            token_ttl_seconds=token_ttl,
        )

    def preview_remove_sensor_tag(
        self,
        oid: str,
        sensor_id: str,
        tag: str,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        safe_tag = require_token(tag, "tag")
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation="sensor.tag.remove",
            oid=scoped_oid,
            method="DELETE",
            path=f"{safe_sensor_id}/tags",
            resource={
                "type": "sensor_tag",
                "id": safe_tag,
                "parent": {"type": "sensor", "id": safe_sensor_id, "parent": {"type": "organization", "id": scoped_oid}},
            },
            params={"tag": safe_tag},
            data=None,
            json_body=None,
            expected_effect=f"Remove tag {safe_tag!r} from sensor {safe_sensor_id}.",
            reversibility="Add the same tag back to the sensor if removal was unintended.",
            side_effects=[
                {
                    "type": "sensor_tag_removed",
                    "resource": {"type": "sensor", "id": safe_sensor_id},
                    "tag": safe_tag,
                }
            ],
            token_ttl_seconds=token_ttl,
        )

    def confirm_mutation(self, confirmation_token: str) -> dict[str, Any]:
        token = require_confirmation_token(confirmation_token)
        self._prune_expired_mutations()
        mutation = self._pending_mutations.pop(token, None)
        if mutation is None:
            return self._mutation_token_error(
                "mutation.confirm",
                token,
                "mutation_preview_not_found",
                "No active mutation preview exists for that confirmation token.",
            )
        response = self._request(
            mutation.method,
            mutation.path,
            operation="mutation.confirm",
            oid=mutation.oid,
            resource=mutation.resource,
            base_url=mutation.base_url,
            params=mutation.params,
            data=mutation.data,
            json_body=mutation.json_body,
            side_effects=mutation.side_effects,
        ).as_dict()
        response["data"] = {
            "confirmed_operation": mutation.operation,
            "confirmed_preview": self._preview_data(mutation, time.time(), include_token=False),
            "result": response.get("data"),
        }
        response["meta"]["summary"]["confirmed_operation"] = mutation.operation
        return response

    def _vulnerability_query(
        self,
        *,
        cursor: str | None = None,
        limit: int | None = None,
        sort_by: str | None = None,
        sort_asc: bool | None = None,
        filters: dict[str, list[str]] | None = None,
        search: dict[str, Any] | None = None,
        include_tags: bool | None = None,
        include_enrichment: bool | None = None,
        filter_via_state: bool | None = None,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {}
        if cursor is not None:
            data["cursor"] = require_token(cursor, "cursor")
        if limit is not None:
            data["limit"] = limit
        if sort_by is not None:
            data["sort_by"] = require_token(sort_by, "sort_by")
        if sort_asc is not None:
            data["sort_asc"] = require_bool_or_none(sort_asc, "sort_asc")
        checked_filters = require_vuln_filters(filters)
        if checked_filters is not None:
            data["filters"] = checked_filters
        checked_search = require_vuln_search(search)
        if checked_search is not None:
            data["search"] = checked_search
        if include_tags is not None:
            data["include_tags"] = require_bool_or_none(include_tags, "include_tags")
        if include_enrichment is not None:
            data["include_enrichment"] = require_bool_or_none(include_enrichment, "include_enrichment")
        if filter_via_state is not None:
            data["filter_via_state"] = require_bool_or_none(filter_via_state, "filter_via_state")
        return data

    def _extension_request(
        self,
        oid: str,
        action: str,
        data: dict[str, Any],
        *,
        operation: str,
        resource: dict[str, Any],
        limit: int = 100,
    ) -> dict[str, Any]:
        result = self._request(
            "POST",
            "extension/request/ext-vulnerability-reporting",
            operation=operation,
            oid=oid,
            resource=resource,
            params=extension_request_params(oid, action, data),
            limit=limit,
        ).as_dict()
        payload = result.get("data")
        if result.get("ok") and isinstance(payload, dict) and "data" in payload:
            unwrapped, truncated = bound_output(payload["data"], limit)
            result["data"] = unwrapped
            result["meta"]["truncated"] = bool(result["meta"].get("truncated") or truncated)
            result["meta"]["summary"] = summarize_data(unwrapped)
            if truncated:
                result["meta"]["suggested_next_actions"] = [
                    "Repeat with a lower limit, narrower filters, or a pagination cursor."
                ]
        return result

    def _request(
        self,
        method: str,
        path: str,
        *,
        operation: str,
        oid: str | None = None,
        resource: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_body: Any | None = None,
        limit: int = 100,
        base_url: str | None = None,
        side_effects: list[dict[str, Any]] | None = None,
        no_auth: bool = False,
    ) -> ToolResponse:
        started = time.time()
        request_id = f"req_{uuid.uuid4().hex}"
        root = (base_url or f"{self.api_root}/v1").rstrip("/")
        url = f"{root}/{path.lstrip('/')}"
        headers = {"User-Agent": "limacharlie-mcp/0.1.0"}
        try:
            if not no_auth:
                token_oid = oid or os.environ.get("LC_OID")
                token = self._get_jwt(token_oid)
                headers["Authorization"] = f"Bearer {token}"
            response = self.http.request(
                method,
                url,
                headers=headers,
                params=params,
                data=data,
                json=json_body,
                timeout=self.timeout_seconds,
            )
            duration_ms = int((time.time() - started) * 1000)
        except (httpx.HTTPError, TimeoutError) as exc:
            duration_ms = int((time.time() - started) * 1000)
            self._audit(operation, oid, method, url, params, None, duration_ms, 0, str(exc)[:500])
            return ToolResponse(
                ok=False,
                operation=operation,
                data=None,
                error=classify_error(None, None, f"LimaCharlie API request failed: {exc}"),
                meta={"duration_ms": duration_ms, "summary": {"shape": "empty"}, "truncated": False},
                request_id=request_id,
                resource=resource,
                observed_at=observed_at(),
            )
        except ValidationError as exc:
            raise exc
        except Exception as exc:
            duration_ms = int((time.time() - started) * 1000)
            self._audit(operation, oid, method, url, params, None, duration_ms, 0, str(exc)[:500])
            return ToolResponse(
                ok=False,
                operation=operation,
                data=None,
                error=classify_error(None, None, str(exc)),
                meta={"duration_ms": duration_ms, "summary": {"shape": "empty"}, "truncated": False},
                request_id=request_id,
                resource=resource,
                observed_at=observed_at(),
            )

        raw_text = response.text or ""
        parsed_response = self._parse_response(response)
        data = redact_sensitive(normalize_api_data(parsed_response))
        safe_excerpt = redacted_response_excerpt(data, raw_text)
        self._audit(operation, oid, method, url, params, response.status_code, duration_ms, len(raw_text), safe_excerpt)
        meta = {
            "duration_ms": duration_ms,
            "status_code": response.status_code,
            "truncated": False,
        }
        if response.status_code < 200 or response.status_code >= 300:
            meta["summary"] = summarize_data(data)
            return ToolResponse(
                ok=False,
                operation=operation,
                data=data,
                error=classify_error(response.status_code, data, safe_excerpt),
                meta=meta,
                request_id=request_id,
                resource=resource,
                observed_at=observed_at(),
            )
        data, truncated = bound_output(data, limit)
        meta["truncated"] = truncated
        meta["summary"] = summarize_data(data)
        if truncated:
            meta["suggested_next_actions"] = ["Repeat with a narrower query window or smaller selector scope."]
        return ToolResponse(
            ok=True,
            operation=operation,
            data=data,
            meta=meta,
            request_id=request_id,
            resource=resource,
            side_effects=side_effects or [],
            observed_at=observed_at(),
        )

    def _local_response(
        self,
        operation: str,
        data: Any,
        *,
        resource: dict[str, Any] | None = None,
        state: dict[str, Any] | None = None,
        warnings: list[str] | None = None,
        side_effects: list[dict[str, Any]] | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        bounded, truncated = bound_output(data, limit)
        return ToolResponse(
            ok=True,
            operation=operation,
            request_id=f"req_{uuid.uuid4().hex}",
            resource=resource,
            state=state or {},
            data=bounded,
            side_effects=side_effects or [],
            warnings=warnings or [],
            meta={"summary": summarize_data(bounded), "truncated": truncated},
            observed_at=observed_at(),
        ).as_dict()

    def _sensor_state_preview(
        self,
        *,
        operation: str,
        oid: str,
        sensor_id: str,
        method: str,
        path_suffix: str,
        resource_type: str,
        expected_effect: str,
        reversibility: str,
        side_effect_type: str,
        token_ttl_seconds: int,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation=operation,
            oid=scoped_oid,
            method=method,
            path=f"{safe_sensor_id}/{path_suffix}",
            resource={"type": resource_type, "id": safe_sensor_id, "parent": {"type": "organization", "id": scoped_oid}},
            data=None,
            json_body=None,
            expected_effect=f"{expected_effect} Target sensor: {safe_sensor_id}.",
            reversibility=reversibility,
            side_effects=[{"type": side_effect_type, "resource": {"type": "sensor", "id": safe_sensor_id}}],
            token_ttl_seconds=token_ttl,
        )

    def _preview_mutation(
        self,
        *,
        operation: str,
        oid: str,
        method: str,
        path: str,
        resource_type: str,
        resource_id: str,
        expected_effect: str,
        reversibility: str,
        side_effect_type: str,
        token_ttl_seconds: int,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_body: Any | None = None,
        parent_oid: str | None = None,
        base_url: str | None = None,
    ) -> dict[str, Any]:
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        resource: dict[str, Any] = {"type": resource_type, "id": resource_id}
        if parent_oid is not None:
            resource["parent"] = {"type": "organization", "id": parent_oid}
        return self._create_mutation_preview(
            operation=operation,
            oid=oid,
            method=method,
            path=path,
            resource=resource,
            base_url=base_url,
            params=params,
            data=data,
            json_body=json_body,
            expected_effect=expected_effect,
            reversibility=reversibility,
            side_effects=[{"type": side_effect_type, "resource": {"type": resource_type, "id": resource_id}}],
            token_ttl_seconds=token_ttl,
        )

    def _preview_group_email_mutation(
        self,
        operation: str,
        method: str,
        group_id: str,
        email: str,
        path_suffix: str,
        side_effect_type: str,
        token_ttl_seconds: int,
    ) -> dict[str, Any]:
        safe_group_id = require_path_segment(group_id, "group_id")
        safe_email = require_email(email)
        return self._preview_mutation(
            operation=operation,
            oid="-",
            method=method,
            path=f"groups/{quote(safe_group_id, safe='')}/{path_suffix}",
            resource_type=operation.rsplit(".", 1)[0].replace(".", "_"),
            resource_id=f"{safe_group_id}:{safe_email}",
            params={"member_email": safe_email},
            expected_effect=f"{operation} for {safe_email} on group {safe_group_id}.",
            reversibility="Apply the opposite group membership or ownership operation if this was unintended.",
            side_effect_type=side_effect_type,
            token_ttl_seconds=token_ttl_seconds,
        )

    def _preview_group_org_mutation(
        self,
        operation: str,
        method: str,
        group_id: str,
        member_oid: str,
        side_effect_type: str,
        token_ttl_seconds: int,
    ) -> dict[str, Any]:
        safe_group_id = require_path_segment(group_id, "group_id")
        safe_member_oid = require_oid(member_oid)
        return self._preview_mutation(
            operation=operation,
            oid="-",
            method=method,
            path=f"groups/{quote(safe_group_id, safe='')}/orgs",
            resource_type="group_org_membership",
            resource_id=f"{safe_group_id}:{safe_member_oid}",
            params={"oid": safe_member_oid},
            expected_effect=f"{operation} for org {safe_member_oid} on group {safe_group_id}.",
            reversibility="Apply the opposite group org membership operation if this was unintended.",
            side_effect_type=side_effect_type,
            token_ttl_seconds=token_ttl_seconds,
        )

    def _extension_definition_id(self, extension_definition: dict[str, Any], extension_name: str | None) -> str:
        if extension_name is not None:
            return require_extension_name(extension_name)
        raw_name = extension_definition.get("name") or extension_definition.get("extension_name") or extension_definition.get("id")
        if raw_name is None:
            return "extension_definition"
        return require_extension_name(str(raw_name))

    def _hive_set_params(
        self,
        data: dict[str, Any],
        *,
        enabled: bool | None = None,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        expiry: int | None = None,
        etag: str | None = None,
    ) -> dict[str, Any]:
        require_dict(data, "data")
        params: dict[str, Any] = {"data": json.dumps(data)}
        usr_mtd: dict[str, Any] = {}
        if enabled is not None:
            usr_mtd["enabled"] = require_bool_or_none(enabled, "enabled")
        checked_tags = require_string_list(tags, "tags")
        if checked_tags is not None:
            usr_mtd["tags"] = checked_tags
        if comment is not None:
            if not isinstance(comment, str) or len(comment) > 1000 or "\x00" in comment:
                raise ValidationError("comment must be a string under 1000 characters without NUL bytes")
            usr_mtd["comment"] = comment
        if expiry is not None:
            usr_mtd["expiry"] = require_unix_seconds(expiry, "expiry")
        if usr_mtd:
            params["usr_mtd"] = json.dumps(usr_mtd)
        if etag is not None:
            params["etag"] = require_token(etag, "etag")
        return params

    def _preview_hive_set(
        self,
        *,
        operation: str,
        oid: str,
        hive_name: str,
        name: str,
        data: dict[str, Any],
        resource_type: str,
        enabled: bool | None,
        tags: list[str] | str | None,
        comment: str | None,
        expiry: int | None,
        etag: str | None,
        token_ttl_seconds: int,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation=operation,
            oid=scoped_oid,
            method="POST",
            path=f"hive/{hive_name}/{scoped_oid}/{quote(safe_name, safe='')}/data",
            resource={"type": resource_type, "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
            params=self._hive_set_params(data, enabled=enabled, tags=tags, comment=comment, expiry=expiry, etag=etag),
            data=None,
            json_body=None,
            expected_effect=f"Create or update {resource_type} {safe_name!r} in hive {hive_name}.",
            reversibility="Restore the prior hive record value or delete this record if it was newly created.",
            side_effects=[{"type": f"{resource_type}_set", "resource": {"type": resource_type, "id": safe_name}}],
            token_ttl_seconds=token_ttl,
        )

    def _preview_hive_delete(
        self,
        *,
        operation: str,
        oid: str,
        hive_name: str,
        name: str,
        resource_type: str,
        token_ttl_seconds: int,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation=operation,
            oid=scoped_oid,
            method="DELETE",
            path=f"hive/{hive_name}/{scoped_oid}/{quote(safe_name, safe='')}",
            resource={"type": resource_type, "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
            data=None,
            json_body=None,
            expected_effect=f"Delete {resource_type} {safe_name!r} from hive {hive_name}.",
            reversibility="Recreate the hive record from a known-good backup if deletion was unintended.",
            side_effects=[{"type": f"{resource_type}_deleted", "resource": {"type": resource_type, "id": safe_name}}],
            token_ttl_seconds=token_ttl,
        )

    def _preview_service_request(
        self,
        *,
        operation: str,
        oid: str,
        service: str,
        request_data: dict[str, Any],
        resource_type: str,
        resource_id: str,
        expected_effect: str,
        reversibility: str,
        side_effect_type: str,
        token_ttl_seconds: int,
        is_async: bool = False,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation=operation,
            oid=scoped_oid,
            method="POST",
            path=f"service/{scoped_oid}/{service}",
            resource={"type": resource_type, "id": resource_id, "parent": {"type": "organization", "id": scoped_oid}},
            params=service_request_params(request_data, is_async=is_async),
            data=None,
            json_body=None,
            expected_effect=expected_effect,
            reversibility=reversibility,
            side_effects=[{"type": side_effect_type, "resource": {"type": resource_type, "id": resource_id}}],
            token_ttl_seconds=token_ttl,
        )

    def _create_mutation_preview(
        self,
        *,
        operation: str,
        oid: str,
        method: str,
        path: str,
        resource: dict[str, Any],
        data: dict[str, Any] | None,
        json_body: Any | None,
        expected_effect: str,
        reversibility: str,
        side_effects: list[dict[str, Any]],
        token_ttl_seconds: int,
        params: dict[str, Any] | None = None,
        base_url: str | None = None,
    ) -> dict[str, Any]:
        self._prune_expired_mutations()
        token = f"mut_{uuid.uuid4().hex}"
        mutation = PendingMutation(
            token=token,
            expires_at=time.time() + token_ttl_seconds,
            operation=operation,
            oid=oid,
            method=method,
            path=path,
            resource=resource,
            base_url=base_url,
            params=params,
            data=data,
            json_body=json_body,
            expected_effect=expected_effect,
            reversibility=reversibility,
            side_effects=side_effects,
        )
        self._pending_mutations[token] = mutation
        preview = self._preview_data(mutation, time.time())
        return ToolResponse(
            ok=True,
            operation=f"{operation}.preview",
            request_id=f"req_{uuid.uuid4().hex}",
            resource=resource,
            state={"current": "pending_confirmation"},
            data=preview,
            side_effects=[],
            warnings=["No LimaCharlie change has been made. Call lc_confirm_mutation with confirmation_token to execute."],
            meta={
                "summary": {
                    "preview_operation": operation,
                    "expires_in_seconds": preview["expires_in_seconds"],
                    "requires_confirmation": True,
                },
                "truncated": False,
            },
            observed_at=observed_at(),
        ).as_dict()

    def _preview_data(self, mutation: PendingMutation, now: float, *, include_token: bool = True) -> dict[str, Any]:
        root = (mutation.base_url or f"{self.api_root}/v1").rstrip("/")
        preview = {
            "operation": mutation.operation,
            "http_method": mutation.method,
            "endpoint": f"{root.rstrip('/')}/{mutation.path.lstrip('/')}",
            "oid": mutation.oid,
            "resource": mutation.resource,
            "params": mutation.params,
            "data": mutation.data,
            "json_body": mutation.json_body,
            "expected_effect": mutation.expected_effect,
            "reversibility": mutation.reversibility,
            "expected_side_effects": mutation.side_effects,
            "expires_in_seconds": max(0, int(mutation.expires_at - now)),
        }
        if include_token:
            preview["confirmation_token"] = mutation.token
        return preview

    def _prune_expired_mutations(self) -> None:
        now = time.time()
        expired = [token for token, mutation in self._pending_mutations.items() if mutation.expires_at <= now]
        for token in expired:
            self._pending_mutations.pop(token, None)

    def _mutation_token_error(self, operation: str, token: str, code: str, message: str) -> dict[str, Any]:
        return ToolResponse(
            ok=False,
            operation=operation,
            request_id=f"req_{uuid.uuid4().hex}",
            resource={"type": "mutation_preview", "id": token},
            state={"current": "not_found"},
            data=None,
            side_effects=[],
            warnings=[],
            meta={"summary": {"shape": "empty"}, "truncated": False},
            observed_at=observed_at(),
            error={
                "code": code,
                "class": "not_found",
                "message": message,
                "retryable": False,
                "same_input_retryable": False,
                "suggested_next_actions": [
                    "Create a new preview for the intended mutation.",
                    "Confirm the new token before it expires.",
                ],
            },
        ).as_dict()

    @staticmethod
    def _download_targets(targets: dict[tuple[str, str], str]) -> list[dict[str, str]]:
        return [
            {
                "platform": platform,
                "arch": arch,
                "url": f"https://downloads.limacharlie.io/{path}",
            }
            for (platform, arch), path in sorted(targets.items())
        ]

    def _search_body(
        self,
        oid: str,
        query: str,
        start: int,
        end: int,
        stream: str | None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "oid": oid,
            "query": query,
            "startTime": str(int(start)),
            "endTime": str(int(end)),
        }
        safe_stream = require_search_stream(stream)
        if safe_stream:
            body["stream"] = safe_stream
        return body

    def _search_root(self, oid: str) -> str:
        cached = self._search_roots.get(oid)
        if cached:
            return cached
        result = self.get_org_urls(oid)
        url = ""
        if result.get("ok") and isinstance(result.get("data"), dict):
            urls = result["data"]
            value = urls.get("search") or urls.get("search_api")
            if isinstance(value, str):
                url = value
        if not url:
            url = "https://search.limacharlie.io"
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        root = url.rstrip("/")
        if not root.endswith("/v1"):
            root = f"{root}/v1"
        self._search_roots[oid] = root
        return root

    def _replay_root(self, oid: str) -> str:
        result = self.get_org_urls(oid)
        url = ""
        if result.get("ok") and isinstance(result.get("data"), dict):
            value = result["data"].get("replay")
            if isinstance(value, str):
                url = value
        if not url:
            url = "replay.limacharlie.io"
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        return url.rstrip("/")

    def _finalize_search_poll(self, result: dict[str, Any], query_id: str, limit: int) -> None:
        data = result.get("data")
        if not isinstance(data, dict):
            result["state"] = {"current": "unknown", "terminal": False, "query_id": query_id}
            return
        results = data.get("results")
        next_token = None
        total_rows_seen = 0
        rows_returned = 0
        truncated = False
        if isinstance(results, list):
            for item in results:
                if not isinstance(item, dict):
                    continue
                token = item.get("nextToken") or item.get("next_token")
                if token:
                    next_token = str(token)
                rows = item.get("rows")
                if isinstance(rows, list):
                    total_rows_seen += len(rows)
                    remaining = max(limit - rows_returned, 0)
                    if len(rows) > remaining:
                        item["rows"] = rows[:remaining]
                        truncated = True
                    rows_returned += len(item["rows"])
                    if rows_returned >= limit:
                        truncated = truncated or total_rows_seen > rows_returned
        completed = bool(data.get("completed"))
        if completed and next_token:
            current = "ready_for_next_page"
            terminal = False
        elif completed:
            current = "succeeded"
            terminal = True
        else:
            current = "running"
            terminal = False
        result["state"] = {
            "current": current,
            "terminal": terminal,
            "query_id": query_id,
            "next_poll_in_ms": data.get("nextPollInMs"),
            "checkpoint": {
                "next_token": next_token,
                "rows_returned": rows_returned,
                "rows_seen_before_bounding": total_rows_seen,
                "resume_tool": "lc_poll_search_query" if next_token else None,
            },
        }
        result["meta"]["summary"] = summarize_data(data)
        result["meta"]["summary"]["search_state"] = current
        result["meta"]["summary"]["query_id"] = query_id
        result["meta"]["summary"]["rows_returned"] = rows_returned
        result["meta"]["truncated"] = bool(result["meta"].get("truncated") or truncated)
        if result["meta"]["truncated"]:
            result["meta"]["suggested_next_actions"] = [
                "Repeat with a lower limit, narrower query, or continue from checkpoint.next_token."
            ]
        elif next_token:
            result["meta"]["suggested_next_actions"] = [
                "Call lc_poll_search_query with checkpoint.next_token to retrieve the next page."
            ]
        elif not completed:
            result["meta"]["suggested_next_actions"] = [
                "Wait for next_poll_in_ms, then call lc_poll_search_query again with the same query_id."
            ]

    def _get_jwt(self, oid: str | None, *, force_refresh: bool = False) -> str:
        scoped_oid = "-" if oid == "-" else require_oid(oid or "")
        cached = self._tokens.get(scoped_oid)
        now = time.time()
        if cached and not force_refresh and cached.expires_at - 60 > now:
            return cached.value
        if not self.api_key:
            raise RuntimeError("LC_API_KEY is required for direct API authentication")

        data: dict[str, Any] = {"oid": scoped_oid, "secret": self.api_key}
        if self.uid:
            data["uid"] = self.uid
        response = self.http.request(
            "POST",
            self.jwt_root,
            data=data,
            timeout=self.timeout_seconds,
        )
        if response.status_code < 200 or response.status_code >= 300:
            raise RuntimeError(f"JWT exchange failed with status {response.status_code}: {response.text[:300]}")
        payload = self._parse_response(response)
        token = payload.get("jwt") or payload.get("token")
        if not token:
            raise RuntimeError("JWT exchange response did not include a jwt field")
        expires_in = int(payload.get("expires_in") or payload.get("ttl") or 3000)
        self._tokens[scoped_oid] = Token(value=token, expires_at=now + expires_in)
        return token

    @staticmethod
    def _parse_response(response: httpx.Response) -> Any:
        content_type = response.headers.get("content-type", "")
        if "json" in content_type:
            return response.json()
        text = response.text
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text

    def _audit(
        self,
        operation: str,
        oid: str | None,
        method: str,
        url: str,
        params: dict[str, Any] | None,
        status_code: int | None,
        duration_ms: int,
        response_bytes: int,
        response_excerpt: str,
    ) -> None:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "operation": operation,
            "oid": oid,
            "method": method,
            "url": url,
            "params": params or {},
            "status_code": status_code,
            "duration_ms": duration_ms,
            "response_bytes": response_bytes,
            "response_excerpt": response_excerpt,
        }
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")


def client_from_env() -> LimaCharlieAPI:
    return LimaCharlieAPI()
