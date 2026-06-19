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
def lc_list_sensor_download_targets() -> dict:
    """List supported sensor installer target URLs without downloading binaries."""

    return lc.list_sensor_download_targets()


@mcp.tool()
def lc_list_adapter_download_targets() -> dict:
    """List supported adapter binary target URLs without downloading binaries."""

    return lc.list_adapter_download_targets()


@mcp.tool()
def lc_list_sensors(oid: str, selector: str | None = None, limit: int = 100) -> dict:
    """List sensors for an explicit org, optionally filtered by selector."""

    return _call("sensor.list", lc.list_sensors, oid=oid, selector=selector, limit=limit)


@mcp.tool()
def lc_get_sensor(oid: str, sensor_id: str) -> dict:
    """Fetch one sensor by sensor ID for an explicit org."""

    return _call("sensor.get", lc.get_sensor, oid=oid, sensor_id=sensor_id)


@mcp.tool()
def lc_list_online_sensors(oid: str, limit: int = 100) -> dict:
    """List currently online sensors or online sensor counts for an explicit org."""

    return _call("sensor.online.list", lc.list_online_sensors, oid=oid, limit=limit)


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
def lc_batch_search_iocs(
    oid: str,
    objects: dict[str, list[str]],
    info: str = "summary",
    case_sensitive: bool = True,
    limit: int = 100,
) -> dict:
    """Batch Insight prevalence or location lookup for bounded IOC groups."""

    return _call(
        "ioc.batch_search",
        lc.batch_search_iocs,
        oid=oid,
        objects=objects,
        info=info,
        case_sensitive=case_sensitive,
        limit=limit,
    )


@mcp.tool()
def lc_get_object_information(
    oid: str,
    obj_type: str,
    obj_name: str,
    info: str = "summary",
    case_sensitive: bool = True,
    wildcards: bool = False,
    limit: int = 100,
) -> dict:
    """Lookup one object through Insight with enrichment-oriented naming."""

    return _call(
        "ioc.object_info",
        lc.get_object_information,
        oid=oid,
        obj_type=obj_type,
        obj_name=obj_name,
        info=info,
        case_sensitive=case_sensitive,
        wildcards=wildcards,
        limit=limit,
    )


@mcp.tool()
def lc_get_insight_status(oid: str) -> dict:
    """Check whether Insight retention appears enabled for an org."""

    return _call("insight.status", lc.get_insight_status, oid=oid)


@mcp.tool()
def lc_validate_search_query(
    oid: str,
    query: str,
    start: int | None = None,
    end: int | None = None,
    stream: str | None = None,
) -> dict:
    """Validate LCQL through the org search service before estimation or execution."""

    return _call("search.validate", lc.validate_search_query, oid=oid, query=query, start=start, end=end, stream=stream)


@mcp.tool()
def lc_estimate_search_query(oid: str, query: str, start: int, end: int, stream: str | None = None) -> dict:
    """Estimate an LCQL query against an explicit unix-second time window."""

    return _call("search.estimate", lc.estimate_search_query, oid=oid, query=query, start=start, end=end, stream=stream)


@mcp.tool()
def lc_execute_search_query(oid: str, query: str, start: int, end: int, stream: str | None = None) -> dict:
    """Start a paginated LCQL search and return a query_id for bounded polling."""

    return _call("search.execute", lc.execute_search_query, oid=oid, query=query, start=start, end=end, stream=stream)


@mcp.tool()
def lc_poll_search_query(oid: str, query_id: str, token: str | None = None, limit: int = 100) -> dict:
    """Poll one bounded LCQL search page, returning checkpoint state for resume."""

    return _call("search.poll", lc.poll_search_query, oid=oid, query_id=query_id, token=token, limit=limit)


@mcp.tool()
def lc_cancel_search_query(oid: str, query_id: str) -> dict:
    """Cancel a running LCQL search job."""

    return _call("search.cancel", lc.cancel_search_query, oid=oid, query_id=query_id)


@mcp.tool()
def lc_validate_replay_rule(
    oid: str,
    rule_content: dict[str, Any],
    trace: bool = False,
    limit_events: int = 1,
    limit_evals: int = 1000,
) -> dict:
    """Validate a D&R rule through Replay using a dry-run minimal event."""

    return _call(
        "replay.validate_rule",
        lc.validate_replay_rule,
        oid=oid,
        rule_content=rule_content,
        trace=trace,
        limit_events=limit_events,
        limit_evals=limit_evals,
    )


@mcp.tool()
def lc_replay_scan_events(
    oid: str,
    events: list[dict[str, Any]],
    rule_name: str | None = None,
    namespace: str | None = None,
    rule_content: dict[str, Any] | None = None,
    trace: bool = False,
    limit_events: int = 100,
    limit_evals: int = 1000,
    stream: str = "event",
) -> dict:
    """Dry-run a D&R rule against explicit events through Replay."""

    return _call(
        "replay.scan_events",
        lc.replay_scan_events,
        oid=oid,
        events=events,
        rule_name=rule_name,
        namespace=namespace,
        rule_content=rule_content,
        trace=trace,
        limit_events=limit_events,
        limit_evals=limit_evals,
        stream=stream,
    )


@mcp.tool()
def lc_replay_dry_run(
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
    limit_evals: int = 10000,
) -> dict:
    """Dry-run a D&R rule against historical data without creating detections."""

    return _call(
        "replay.run_dry",
        lc.replay_dry_run,
        oid=oid,
        start=start,
        end=end,
        rule_name=rule_name,
        detect=detect,
        respond=respond,
        sensor_id=sensor_id,
        selector=selector,
        stream=stream,
        trace=trace,
        limit_events=limit_events,
        limit_evals=limit_evals,
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
def lc_list_payloads(oid: str, limit: int = 100) -> dict:
    """List payload metadata for an org without downloading payload bytes."""

    return _call("payload.list", lc.list_payloads, oid=oid, limit=limit)


@mcp.tool()
def lc_get_payload_download_url(oid: str, name: str) -> dict:
    """Request payload API metadata, including a signed download URL when returned."""

    return _call("payload.get_url", lc.get_payload_download_url, oid=oid, name=name)


@mcp.tool()
def lc_get_arl(oid: str, arl_url: str, limit: int = 100) -> dict:
    """Resolve a LimaCharlie authenticated resource locator."""

    return _call("arl.get", lc.get_arl, oid=oid, arl_url=arl_url, limit=limit)


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
def lc_get_org_urls(oid: str) -> dict:
    """Fetch service URLs for an explicit org."""

    return _call("org.urls", lc.get_org_urls, oid=oid)


@mcp.tool()
def lc_get_runtime_metadata(
    oid: str,
    entity_type: str | None = None,
    entity_name: str | None = None,
    limit: int = 100,
) -> dict:
    """Fetch runtime metadata for an explicit org, optionally filtered by entity."""

    return _call(
        "org.runtime_metadata",
        lc.get_runtime_metadata,
        oid=oid,
        entity_type=entity_type,
        entity_name=entity_name,
        limit=limit,
    )


@mcp.tool()
def lc_get_quota_usage(oid: str) -> dict:
    """Fetch enforced quota usage for an explicit org."""

    return _call("org.quota_usage", lc.get_quota_usage, oid=oid)


@mcp.tool()
def lc_get_billing_status(oid: str) -> dict:
    """Fetch current billing status for an org."""

    return _call("billing.status", lc.get_billing_status, oid=oid)


@mcp.tool()
def lc_get_billing_details(oid: str) -> dict:
    """Fetch detailed billing information for an org."""

    return _call("billing.details", lc.get_billing_details, oid=oid)


@mcp.tool()
def lc_get_billing_invoice_url(oid: str, year: int, month: int, fmt: str | None = None) -> dict:
    """Fetch an invoice URL for a specific billing month."""

    return _call("billing.invoice_url", lc.get_billing_invoice_url, oid=oid, year=year, month=month, fmt=fmt)


@mcp.tool()
def lc_list_billing_plans(limit: int = 100) -> dict:
    """List available billing plans."""

    return _call("billing.plans", lc.list_billing_plans, limit=limit)


@mcp.tool()
def lc_list_groups(limit: int = 100) -> dict:
    """List organization groups accessible to the authenticated identity."""

    return _call("group.list", lc.list_groups, limit=limit)


@mcp.tool()
def lc_get_group(group_id: str) -> dict:
    """Fetch one organization group definition."""

    return _call("group.get", lc.get_group, group_id=group_id)


@mcp.tool()
def lc_list_group_logs(group_id: str, limit: int = 100) -> dict:
    """List audit logs for one organization group."""

    return _call("group.logs", lc.list_group_logs, group_id=group_id, limit=limit)


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
def lc_list_vulnerability_cves(
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
) -> dict:
    """List CVEs observed across the org's sensors through ext-vulnerability-reporting."""

    return _call(
        "vulnerability.cve.list",
        lc.list_vulnerability_cves,
        oid=oid,
        cursor=cursor,
        limit=limit,
        sort_by=sort_by,
        sort_asc=sort_asc,
        filters=filters,
        search=search,
        include_tags=include_tags,
        include_enrichment=include_enrichment,
        filter_via_state=filter_via_state,
    )


@mcp.tool()
def lc_get_vulnerability_cve(oid: str, cve: str, include_enrichment: bool | None = None) -> dict:
    """Fetch details for one CVE through ext-vulnerability-reporting."""

    return _call(
        "vulnerability.cve.get",
        lc.get_vulnerability_cve,
        oid=oid,
        cve=cve,
        include_enrichment=include_enrichment,
    )


@mcp.tool()
def lc_list_vulnerability_cve_hosts(
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
) -> dict:
    """List endpoints affected by one CVE."""

    return _call(
        "vulnerability.cve.hosts",
        lc.list_vulnerability_cve_hosts,
        oid=oid,
        cve=cve,
        cursor=cursor,
        limit=limit,
        sort_by=sort_by,
        sort_asc=sort_asc,
        filters=filters,
        search=search,
        include_tags=include_tags,
        filter_via_state=filter_via_state,
        normalized_package_name=normalized_package_name,
    )


@mcp.tool()
def lc_list_vulnerability_cve_packages(
    oid: str,
    cve: str,
    cursor: str | None = None,
    limit: int = 100,
    sort_by: str | None = None,
    sort_asc: bool | None = None,
    include_enrichment: bool | None = None,
) -> dict:
    """List package/version pairs affected by one CVE."""

    return _call(
        "vulnerability.cve.packages",
        lc.list_vulnerability_cve_packages,
        oid=oid,
        cve=cve,
        cursor=cursor,
        limit=limit,
        sort_by=sort_by,
        sort_asc=sort_asc,
        include_enrichment=include_enrichment,
    )


@mcp.tool()
def lc_list_vulnerability_endpoints(
    oid: str,
    cursor: str | None = None,
    limit: int = 100,
    sort_by: str | None = None,
    sort_asc: bool | None = None,
    filters: dict[str, list[str]] | None = None,
    search: dict[str, Any] | None = None,
    include_tags: bool | None = None,
    filter_via_state: bool | None = None,
) -> dict:
    """List endpoints with vulnerability counts."""

    return _call(
        "vulnerability.endpoint.list",
        lc.list_vulnerability_endpoints,
        oid=oid,
        cursor=cursor,
        limit=limit,
        sort_by=sort_by,
        sort_asc=sort_asc,
        filters=filters,
        search=search,
        include_tags=include_tags,
        filter_via_state=filter_via_state,
    )


@mcp.tool()
def lc_list_vulnerability_host_packages(
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
) -> dict:
    """List vulnerable packages and CVEs on one sensor."""

    return _call(
        "vulnerability.host.packages",
        lc.list_vulnerability_host_packages,
        oid=oid,
        sensor_id=sensor_id,
        cursor=cursor,
        limit=limit,
        sort_by=sort_by,
        sort_asc=sort_asc,
        filters=filters,
        search=search,
        include_tags=include_tags,
        include_enrichment=include_enrichment,
        filter_via_state=filter_via_state,
        rollup_subpackages=rollup_subpackages,
    )


@mcp.tool()
def lc_get_vulnerability_dashboard(oid: str, sort_asc: bool | None = None) -> dict:
    """Fetch vulnerability dashboard graph data."""

    return _call("vulnerability.dashboard", lc.get_vulnerability_dashboard, oid=oid, sort_asc=sort_asc)


@mcp.tool()
def lc_list_vulnerability_resolutions(
    oid: str,
    scope: str | None = None,
    resolutions: list[str] | None = None,
    cursor: str | None = None,
    limit: int = 100,
) -> dict:
    """List stored vulnerability finding resolution overlays."""

    return _call(
        "vulnerability.resolution.list",
        lc.list_vulnerability_resolutions,
        oid=oid,
        scope=scope,
        resolutions=resolutions,
        cursor=cursor,
        limit=limit,
    )


@mcp.tool()
def lc_list_vulnerability_snapshots(oid: str, days: int = 30, severities: list[str] | None = None) -> dict:
    """List daily open-finding counts for vulnerability burndown views."""

    return _call("vulnerability.snapshot.list", lc.list_vulnerability_snapshots, oid=oid, days=days, severities=severities)


@mcp.tool()
def lc_get_vulnerability_epss_history(oid: str, cve: str, days: int = 90) -> dict:
    """Fetch EPSS score and percentile history for one CVE."""

    return _call("vulnerability.epss_history", lc.get_vulnerability_epss_history, oid=oid, cve=cve, days=days)


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
def lc_list_integrity_rules(oid: str, limit: int = 100) -> dict:
    """List integrity monitoring rules for an org."""

    return _call("integrity_rule.list", lc.list_integrity_rules, oid=oid, limit=limit)


@mcp.tool()
def lc_get_integrity_rule(oid: str, name: str) -> dict:
    """Fetch one integrity monitoring rule by name."""

    return _call("integrity_rule.get", lc.get_integrity_rule, oid=oid, name=name)


@mcp.tool()
def lc_validate_usp_mapping(
    oid: str,
    platform: str,
    mapping: dict[str, Any] | None = None,
    mappings: list[dict[str, Any]] | None = None,
    text_input: str | None = None,
    json_input: dict[str, Any] | list[dict[str, Any]] | None = None,
    hostname: str | None = None,
    indexing: dict[str, Any] | None = None,
) -> dict:
    """Validate a Universal Sensor Protocol mapping/input configuration."""

    return _call(
        "usp.validate",
        lc.validate_usp_mapping,
        oid=oid,
        platform=platform,
        mapping=mapping,
        mappings=mappings,
        text_input=text_input,
        json_input=json_input,
        hostname=hostname,
        indexing=indexing,
    )


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


@mcp.tool()
def lc_list_pending_mutations() -> dict:
    """List local mutation previews that can still be confirmed."""

    return lc.list_pending_mutations()


@mcp.tool()
def lc_preview_add_sensor_tag(
    oid: str,
    sensor_id: str,
    tag: str,
    ttl_seconds: int = 0,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview adding a tag to one sensor. No LimaCharlie write occurs until confirmation."""

    return _call(
        "sensor.tag.add.preview",
        lc.preview_add_sensor_tag,
        oid=oid,
        sensor_id=sensor_id,
        tag=tag,
        ttl_seconds=ttl_seconds,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_remove_sensor_tag(
    oid: str,
    sensor_id: str,
    tag: str,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview removing a tag from one sensor. No LimaCharlie write occurs until confirmation."""

    return _call(
        "sensor.tag.remove.preview",
        lc.preview_remove_sensor_tag,
        oid=oid,
        sensor_id=sensor_id,
        tag=tag,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_confirm_mutation(confirmation_token: str) -> dict:
    """Execute the exact typed mutation bound to a short-lived preview token."""

    return _call("mutation.confirm", lc.confirm_mutation, confirmation_token=confirmation_token)


@mcp.tool()
def lc_cancel_mutation(confirmation_token: str) -> dict:
    """Cancel one pending local mutation preview without calling LimaCharlie."""

    return _call("mutation.cancel", lc.cancel_mutation, confirmation_token=confirmation_token)


def main() -> None:
    mcp.run()
