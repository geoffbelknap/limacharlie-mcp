from __future__ import annotations

import base64
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
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 200},
        "side_effects": "none",
        "notes": "Cases is a beta LimaCharlie surface; auth or extension errors are possible.",
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
}


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
_SUMMARY_LIST_KEYS = (
    "data",
    "items",
    "sensors",
    "detects",
    "detections",
    "cases",
    "orgs",
    "events",
    "artifacts",
    "jobs",
    "users",
    "api_keys",
    "keys",
    "outputs",
    "resources",
    "extensions",
    "rules",
    "records",
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


def require_case_number(case_number: str) -> str:
    if not isinstance(case_number, str) or not _SAFE_CASE_NUMBER.match(case_number):
        raise ValidationError("case_number must be a numeric case number")
    return case_number


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


def require_ioc_type(obj_type: str) -> str:
    if obj_type not in _IOC_TYPES:
        raise ValidationError(f"obj_type must be one of: {', '.join(sorted(_IOC_TYPES))}")
    return obj_type


def require_info_type(info: str) -> str:
    if info not in _INFO_TYPES:
        raise ValidationError("info must be 'summary' or 'locations'")
    return info


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

    def list_cases(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit, maximum=200)
        return self._request(
            "GET",
            "api/v1/cases",
            operation="case.list",
            oid=scoped_oid,
            resource={"type": "case_collection", "id": scoped_oid},
            params={"oids": scoped_oid, "page_size": bounded_limit},
            limit=bounded_limit,
            base_url=self.cases_root,
        ).as_dict()

    def get_case(self, oid: str, case_number: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        return self._request(
            "GET",
            f"api/v1/cases/{safe_case_number}",
            operation="case.get",
            oid=scoped_oid,
            resource={"type": "case", "id": safe_case_number, "parent": {"type": "organization", "id": scoped_oid}},
            params={"oid": scoped_oid},
            base_url=self.cases_root,
        ).as_dict()

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

    def list_user_permissions(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/users/permissions",
            operation="user.permission.list",
            oid=scoped_oid,
            resource={"type": "user_permission_collection", "id": scoped_oid},
        ).as_dict()

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
    ) -> ToolResponse:
        started = time.time()
        request_id = f"req_{uuid.uuid4().hex}"
        root = (base_url or f"{self.api_root}/v1").rstrip("/")
        url = f"{root}/{path.lstrip('/')}"
        headers = {"User-Agent": "limacharlie-mcp/0.1.0"}
        try:
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
        self._audit(operation, oid, method, url, params, response.status_code, duration_ms, len(raw_text), raw_text[:500])
        meta = {
            "duration_ms": duration_ms,
            "status_code": response.status_code,
            "truncated": False,
        }
        data = normalize_api_data(self._parse_response(response))
        if response.status_code < 200 or response.status_code >= 300:
            meta["summary"] = summarize_data(data)
            return ToolResponse(
                ok=False,
                operation=operation,
                data=data,
                error=classify_error(response.status_code, data, raw_text),
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
            observed_at=observed_at(),
        )

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
