from __future__ import annotations

from collections.abc import Callable
from typing import Any

from mcp.server.fastmcp import FastMCP

from .api import ValidationError, client_from_env, input_error_response


mcp = FastMCP("limacharlie")
lc = client_from_env()


def _call(operation: str, fn: Callable[..., dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
    try:
        return fn(**kwargs)
    except ValidationError as exc:
        return input_error_response(operation, str(exc))


@mcp.tool()
def lc_tool_catalog() -> dict:
    """Describe LimaCharlie MCP tools, inputs, bounds, side effects, and use cases."""

    return lc.tool_catalog()


@mcp.tool()
def lc_auth_whoami(oid: str | None = None, check_perm: str | None = None) -> dict:
    """Return the authenticated LimaCharlie API identity.

    Pass both oid and check_perm to test a specific permission in an explicit
    organization context.
    """

    return _call("auth.whoami", lc.auth_whoami, oid=oid, check_perm=check_perm)


@mcp.tool()
def lc_auth_status(oid: str | None = None) -> dict:
    """Show LimaCharlie credential mode and cached JWT status without exposing secrets."""

    return _call("auth.status", lc.auth_status, oid=oid)


@mcp.tool()
def lc_auth_refresh(oid: str | None = None) -> dict:
    """Force a LimaCharlie JWT refresh using configured API-key credentials."""

    return _call("auth.refresh", lc.auth_refresh, oid=oid)


@mcp.tool()
def lc_list_orgs() -> dict:
    """List organizations available to the authenticated LimaCharlie API key."""

    return lc.list_orgs()


@mcp.tool()
def lc_list_sensors(oid: str, selector: str | None = None, limit: int = 100) -> dict:
    """List sensors for an explicit org, optionally filtered by selector."""

    return _call("sensor.list", lc.list_sensors, oid=oid, selector=selector, limit=limit)


@mcp.tool()
def lc_get_sensor(oid: str, sensor_id: str) -> dict:
    """Fetch one sensor by sensor ID for an explicit org."""

    return _call("sensor.get", lc.get_sensor, oid=oid, sensor_id=sensor_id)


@mcp.tool()
def lc_list_detections(
    oid: str,
    start: int,
    end: int,
    limit: int = 100,
    cursor: str = "-",
    category: str | None = None,
) -> dict:
    """List one bounded page of detections for an explicit org and unix-second time window."""

    return _call(
        "detection.list",
        lc.list_detections,
        oid=oid,
        start=start,
        end=end,
        limit=limit,
        cursor=cursor,
        category=category,
    )


@mcp.tool()
def lc_get_detection(oid: str, detect_id: str) -> dict:
    """Fetch a single detection by detection ID for an explicit org."""

    return _call("detection.get", lc.get_detection, oid=oid, detect_id=detect_id)


@mcp.tool()
def lc_list_cases(oid: str, limit: int = 100) -> dict:
    """List LimaCharlie cases for an explicit org."""

    return _call("case.list", lc.list_cases, oid=oid, limit=limit)


@mcp.tool()
def lc_get_case(oid: str, case_number: str) -> dict:
    """Fetch a LimaCharlie case by case number for an explicit org."""

    return _call("case.get", lc.get_case, oid=oid, case_number=case_number)


@mcp.tool()
def lc_list_sensor_events(
    oid: str,
    sensor_id: str,
    start: int,
    end: int,
    event_type: str | None = None,
    limit: int = 100,
    cursor: str = "-",
    is_forward: bool = True,
) -> dict:
    """List one bounded page of historical events for one sensor."""

    return _call(
        "event.list",
        lc.list_sensor_events,
        oid=oid,
        sensor_id=sensor_id,
        start=start,
        end=end,
        event_type=event_type,
        limit=limit,
        cursor=cursor,
        is_forward=is_forward,
    )


@mcp.tool()
def lc_get_sensor_event_overview(oid: str, sensor_id: str, start: int, end: int) -> dict:
    """Fetch event timeline overview for one sensor and time window."""

    return _call(
        "event.overview",
        lc.get_sensor_event_overview,
        oid=oid,
        sensor_id=sensor_id,
        start=start,
        end=end,
    )


@mcp.tool()
def lc_get_event(oid: str, sensor_id: str, atom: str) -> dict:
    """Fetch one sensor event by atom."""

    return _call("event.get", lc.get_event, oid=oid, sensor_id=sensor_id, atom=atom)


@mcp.tool()
def lc_list_child_events(oid: str, sensor_id: str, atom: str, limit: int = 100) -> dict:
    """Fetch child events for a parent event atom."""

    return _call("event.children", lc.list_child_events, oid=oid, sensor_id=sensor_id, atom=atom, limit=limit)


@mcp.tool()
def lc_get_event_retention(
    oid: str,
    sensor_id: str,
    start: int,
    end: int,
    is_detailed: bool = False,
) -> dict:
    """Fetch retained event count/statistics for one sensor and time window."""

    return _call(
        "event.retention",
        lc.get_event_retention,
        oid=oid,
        sensor_id=sensor_id,
        start=start,
        end=end,
        is_detailed=is_detailed,
    )


@mcp.tool()
def lc_search_ioc(
    oid: str,
    obj_type: str,
    obj_name: str,
    info: str = "summary",
    case_sensitive: bool = True,
    wildcards: bool = False,
    limit: int = 100,
    per_object: bool | None = None,
) -> dict:
    """Search Insight prevalence or locations for one IOC/object."""

    return _call(
        "ioc.search",
        lc.search_ioc,
        oid=oid,
        obj_type=obj_type,
        obj_name=obj_name,
        info=info,
        case_sensitive=case_sensitive,
        wildcards=wildcards,
        limit=limit,
        per_object=per_object,
    )


@mcp.tool()
def lc_list_artifacts(
    oid: str,
    sensor_id: str | None = None,
    start: int | None = None,
    end: int | None = None,
    cursor: str | None = None,
    limit: int = 100,
) -> dict:
    """List one bounded page of artifacts for an org, sensor, time window, or cursor."""

    return _call(
        "artifact.list",
        lc.list_artifacts,
        oid=oid,
        sensor_id=sensor_id,
        start=start,
        end=end,
        cursor=cursor,
        limit=limit,
    )


@mcp.tool()
def lc_get_artifact_url(oid: str, artifact_id: str) -> dict:
    """Request original artifact payload or signed export URL."""

    return _call("artifact.get_url", lc.get_artifact_url, oid=oid, artifact_id=artifact_id)


@mcp.tool()
def lc_list_jobs(oid: str, start: int, end: int, sensor_id: str | None = None, limit: int = 100) -> dict:
    """List service jobs for an explicit org and time window."""

    return _call("job.list", lc.list_jobs, oid=oid, start=start, end=end, sensor_id=sensor_id, limit=limit)


@mcp.tool()
def lc_get_job(oid: str, job_id: str) -> dict:
    """Fetch one service job."""

    return _call("job.get", lc.get_job, oid=oid, job_id=job_id)


@mcp.tool()
def lc_wait_job(
    oid: str,
    job_id: str,
    timeout_seconds: int = 60,
    poll_interval_seconds: int = 5,
) -> dict:
    """Poll one service job until terminal state or bounded timeout."""

    return _call(
        "job.wait",
        lc.wait_job,
        oid=oid,
        job_id=job_id,
        timeout_seconds=timeout_seconds,
        poll_interval_seconds=poll_interval_seconds,
    )


@mcp.tool()
def lc_list_audit_logs(
    oid: str,
    start: int,
    end: int,
    event_type: str | None = None,
    sensor_id: str | None = None,
    limit: int = 100,
    cursor: str = "-",
) -> dict:
    """List one bounded page of org audit logs for a time window."""

    return _call(
        "audit.list",
        lc.list_audit_logs,
        oid=oid,
        start=start,
        end=end,
        event_type=event_type,
        sensor_id=sensor_id,
        limit=limit,
        cursor=cursor,
    )


@mcp.tool()
def lc_list_tags(oid: str, limit: int = 100) -> dict:
    """List tags observed across sensors in an org."""

    return _call("tag.list", lc.list_tags, oid=oid, limit=limit)


@mcp.tool()
def lc_find_sensors_by_tag(oid: str, tag: str, limit: int = 100) -> dict:
    """Find sensors with a specific tag."""

    return _call("tag.sensor_search", lc.find_sensors_by_tag, oid=oid, tag=tag, limit=limit)


@mcp.tool()
def lc_find_sensors_by_hostname(oid: str, hostname: str, limit: int = 100) -> dict:
    """Find sensors by hostname prefix."""

    return _call("sensor.hostname_search", lc.find_sensors_by_hostname, oid=oid, hostname=hostname, limit=limit)


@mcp.tool()
def lc_list_schemas(oid: str, platform: str | None = None, limit: int = 100) -> dict:
    """List event schemas for an org, optionally filtered by platform."""

    return _call("schema.list", lc.list_schemas, oid=oid, platform=platform, limit=limit)


@mcp.tool()
def lc_get_schema(oid: str, name: str) -> dict:
    """Fetch one event schema definition."""

    return _call("schema.get", lc.get_schema, oid=oid, name=name)


@mcp.tool()
def lc_get_ontology(limit: int = 100) -> dict:
    """Fetch LimaCharlie ontology/event definitions."""

    return _call("ontology.get", lc.get_ontology, limit=limit)


@mcp.tool()
def lc_list_event_types(limit: int = 100) -> dict:
    """List available LimaCharlie event types."""

    return _call("event_type.list", lc.list_event_types, limit=limit)


@mcp.tool()
def lc_get_mitre_report(oid: str) -> dict:
    """Fetch MITRE ATT&CK coverage data for an org."""

    return _call("mitre.get", lc.get_mitre_report, oid=oid)


@mcp.tool()
def lc_get_org_info(oid: str) -> dict:
    """Fetch organization inventory and quota metadata."""

    return _call("org.get", lc.get_org_info, oid=oid)


@mcp.tool()
def lc_get_org_stats(oid: str) -> dict:
    """Fetch organization usage statistics."""

    return _call("org.stats", lc.get_org_stats, oid=oid)


@mcp.tool()
def lc_list_org_errors(oid: str) -> dict:
    """List current organization component errors."""

    return _call("org.errors", lc.list_org_errors, oid=oid)


@mcp.tool()
def lc_list_users(oid: str, limit: int = 100) -> dict:
    """List users with access to an org."""

    return _call("user.list", lc.list_users, oid=oid, limit=limit)


@mcp.tool()
def lc_list_user_permissions(oid: str) -> dict:
    """List user permission mappings for an org."""

    return _call("user.permission.list", lc.list_user_permissions, oid=oid)


@mcp.tool()
def lc_list_api_keys(oid: str, limit: int = 100) -> dict:
    """List API key metadata for an org."""

    return _call("api_key.list", lc.list_api_keys, oid=oid, limit=limit)


@mcp.tool()
def lc_list_installation_keys(oid: str, limit: int = 100) -> dict:
    """List installation key metadata for an org."""

    return _call("installation_key.list", lc.list_installation_keys, oid=oid, limit=limit)


@mcp.tool()
def lc_get_installation_key(oid: str, installation_key_id: str) -> dict:
    """Fetch one installation key."""

    return _call(
        "installation_key.get",
        lc.get_installation_key,
        oid=oid,
        installation_key_id=installation_key_id,
    )


@mcp.tool()
def lc_list_outputs(oid: str, limit: int = 100) -> dict:
    """List output integration configuration for an org."""

    return _call("output.list", lc.list_outputs, oid=oid, limit=limit)


@mcp.tool()
def lc_list_extension_subscriptions(oid: str, limit: int = 100) -> dict:
    """List extension subscriptions for an org."""

    return _call("extension.list_subscribed", lc.list_extension_subscriptions, oid=oid, limit=limit)


@mcp.tool()
def lc_list_available_extensions(limit: int = 100) -> dict:
    """List globally available extension definitions."""

    return _call("extension.list_available", lc.list_available_extensions, limit=limit)


@mcp.tool()
def lc_get_extension(extension_name: str) -> dict:
    """Fetch one globally available extension definition."""

    return _call("extension.get", lc.get_extension, extension_name=extension_name)


@mcp.tool()
def lc_get_extension_schema(oid: str, extension_name: str) -> dict:
    """Fetch one extension schema for an org context."""

    return _call("extension.schema.get", lc.get_extension_schema, oid=oid, extension_name=extension_name)


@mcp.tool()
def lc_list_artifact_rules(oid: str, limit: int = 100) -> dict:
    """List artifact collection rules for an org."""

    return _call("artifact_rule.list", lc.list_artifact_rules, oid=oid, limit=limit)


@mcp.tool()
def lc_list_ingestion_keys(oid: str, limit: int = 100) -> dict:
    """List ingestion key metadata for an org."""

    return _call("ingestion_key.list", lc.list_ingestion_keys, oid=oid, limit=limit)


@mcp.tool()
def lc_list_logging_rules(oid: str, limit: int = 100) -> dict:
    """List logging collection rules for an org."""

    return _call("logging_rule.list", lc.list_logging_rules, oid=oid, limit=limit)


@mcp.tool()
def lc_list_dr_rules(oid: str, namespace: str | None = None, limit: int = 100) -> dict:
    """List D&R rules from a hive namespace."""

    return _call("dr_rule.list", lc.list_dr_rules, oid=oid, namespace=namespace, limit=limit)


@mcp.tool()
def lc_get_dr_rule(oid: str, name: str, namespace: str | None = None) -> dict:
    """Fetch one D&R rule by name from a hive namespace."""

    return _call("dr_rule.get", lc.get_dr_rule, oid=oid, name=name, namespace=namespace)


@mcp.tool()
def lc_list_fp_rules(oid: str, limit: int = 100) -> dict:
    """List false-positive rules for an org."""

    return _call("fp_rule.list", lc.list_fp_rules, oid=oid, limit=limit)


@mcp.tool()
def lc_get_fp_rule(oid: str, name: str) -> dict:
    """Fetch one false-positive rule by name."""

    return _call("fp_rule.get", lc.get_fp_rule, oid=oid, name=name)


@mcp.tool()
def lc_list_yara_rules(oid: str, limit: int = 100) -> dict:
    """List YARA scanning rules for an org."""

    return _call("yara_rule.list", lc.list_yara_rules, oid=oid, limit=limit)


@mcp.tool()
def lc_list_yara_sources(oid: str, limit: int = 100) -> dict:
    """List YARA source names for an org."""

    return _call("yara_source.list", lc.list_yara_sources, oid=oid, limit=limit)


@mcp.tool()
def lc_get_yara_source(oid: str, name: str) -> dict:
    """Fetch one YARA source by name."""

    return _call("yara_source.get", lc.get_yara_source, oid=oid, name=name)


def main() -> None:
    mcp.run()
