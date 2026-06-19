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
def lc_get_sensor_isolation_status(oid: str, sensor_id: str) -> dict:
    """Check whether one sensor is currently network-isolated."""

    return _call("sensor.isolation_status.get", lc.get_sensor_isolation_status, oid=oid, sensor_id=sensor_id)


@mcp.tool()
def lc_get_sensor_seal_status(oid: str, sensor_id: str) -> dict:
    """Check whether one sensor is currently sealed."""

    return _call("sensor.seal_status.get", lc.get_sensor_seal_status, oid=oid, sensor_id=sensor_id)


@mcp.tool()
def lc_wait_sensor_online(
    oid: str,
    sensor_id: str,
    timeout_seconds: int = 300,
    poll_interval_seconds: int = 5,
) -> dict:
    """Poll one sensor until it is online or a bounded timeout expires."""

    return _call(
        "sensor.wait_online",
        lc.wait_sensor_online,
        oid=oid,
        sensor_id=sensor_id,
        timeout_seconds=timeout_seconds,
        poll_interval_seconds=poll_interval_seconds,
    )


@mcp.tool()
def lc_preview_sensor_task(
    oid: str,
    sensor_id: str,
    tasks: str | list[str],
    investigation_id: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview tasking one sensor. No task is queued until confirmation."""

    return _call(
        "sensor.task.preview",
        lc.preview_sensor_task,
        oid=oid,
        sensor_id=sensor_id,
        tasks=tasks,
        investigation_id=investigation_id,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_isolate_sensor(oid: str, sensor_id: str, token_ttl_seconds: int = 300) -> dict:
    """Preview isolating one sensor from the network."""

    return _call("sensor.isolate.preview", lc.preview_isolate_sensor, oid=oid, sensor_id=sensor_id, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_rejoin_sensor(oid: str, sensor_id: str, token_ttl_seconds: int = 300) -> dict:
    """Preview removing network isolation from one sensor."""

    return _call("sensor.rejoin.preview", lc.preview_rejoin_sensor, oid=oid, sensor_id=sensor_id, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_seal_sensor(oid: str, sensor_id: str, token_ttl_seconds: int = 300) -> dict:
    """Preview sealing one sensor against uninstall."""

    return _call("sensor.seal.preview", lc.preview_seal_sensor, oid=oid, sensor_id=sensor_id, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_unseal_sensor(oid: str, sensor_id: str, token_ttl_seconds: int = 300) -> dict:
    """Preview unsealing one sensor."""

    return _call("sensor.unseal.preview", lc.preview_unseal_sensor, oid=oid, sensor_id=sensor_id, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_delete_sensor(oid: str, sensor_id: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting one sensor record."""

    return _call("sensor.delete.preview", lc.preview_delete_sensor, oid=oid, sensor_id=sensor_id, token_ttl_seconds=token_ttl_seconds)


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
def lc_list_cases(
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
) -> dict:
    """List LimaCharlie cases for an explicit org, with optional filters."""

    return _call(
        "case.list",
        lc.list_cases,
        oid=oid,
        status=status,
        severity=severity,
        classification=classification,
        assignee=assignee,
        search=search,
        sensor_id=sensor_id,
        tags=tags,
        sort=sort,
        order=order,
        limit=limit,
        page_token=page_token,
    )


@mcp.tool()
def lc_get_case(oid: str, case_number: str) -> dict:
    """Fetch a LimaCharlie case by case number for an explicit org."""

    return _call("case.get", lc.get_case, oid=oid, case_number=case_number)


@mcp.tool()
def lc_preview_create_case(
    oid: str,
    detection: dict[str, Any] | None = None,
    severity: str | None = None,
    summary: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating a LimaCharlie case through ext-cases."""

    return _call(
        "case.create.preview",
        lc.preview_create_case,
        oid=oid,
        detection=detection,
        severity=severity,
        summary=summary,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_update_case(
    oid: str,
    case_number: str,
    status: str | None = None,
    severity: str | None = None,
    assignees: list[str] | str | None = None,
    classification: str | None = None,
    summary: str | None = None,
    conclusion: str | None = None,
    tags: list[str] | str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview updating a case. No write is sent until confirmation."""

    return _call(
        "case.update.preview",
        lc.preview_update_case,
        oid=oid,
        case_number=case_number,
        status=status,
        severity=severity,
        assignees=assignees,
        classification=classification,
        summary=summary,
        conclusion=conclusion,
        tags=tags,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_add_case_note(
    oid: str,
    case_number: str,
    content: str,
    note_type: str | None = None,
    is_public: bool | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview adding a note to a case."""

    return _call(
        "case.note.add.preview",
        lc.preview_add_case_note,
        oid=oid,
        case_number=case_number,
        content=content,
        note_type=note_type,
        is_public=is_public,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_update_case_note_visibility(
    oid: str,
    case_number: str,
    event_id: str,
    is_public: bool,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview changing a case note's public visibility."""

    return _call(
        "case.note.visibility.preview",
        lc.preview_update_case_note_visibility,
        oid=oid,
        case_number=case_number,
        event_id=event_id,
        is_public=is_public,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_bulk_update_cases(
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
) -> dict:
    """Preview bulk-updating up to 200 cases."""

    return _call(
        "case.bulk_update.preview",
        lc.preview_bulk_update_cases,
        oid=oid,
        case_numbers=case_numbers,
        status=status,
        severity=severity,
        assignees=assignees,
        classification=classification,
        summary=summary,
        conclusion=conclusion,
        tags=tags,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_merge_cases(
    oid: str,
    target_case_number: str,
    source_case_numbers: list[str | int] | str,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview merging source cases into a target case."""

    return _call(
        "case.merge.preview",
        lc.preview_merge_cases,
        oid=oid,
        target_case_number=target_case_number,
        source_case_numbers=source_case_numbers,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_list_case_detections(oid: str, case_number: str) -> dict:
    """List detections linked to a case."""

    return _call("case.detection.list", lc.list_case_detections, oid=oid, case_number=case_number)


@mcp.tool()
def lc_preview_add_case_detection(oid: str, case_number: str, detection: dict[str, Any], token_ttl_seconds: int = 300) -> dict:
    """Preview linking a detection to a case."""

    return _call("case.detection.add.preview", lc.preview_add_case_detection, oid=oid, case_number=case_number, detection=detection, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_remove_case_detection(oid: str, case_number: str, detection_id: str, token_ttl_seconds: int = 300) -> dict:
    """Preview removing a detection link from a case."""

    return _call("case.detection.remove.preview", lc.preview_remove_case_detection, oid=oid, case_number=case_number, detection_id=detection_id, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_case_entities(oid: str, case_number: str) -> dict:
    """List entities attached to a case."""

    return _call("case.entity.list", lc.list_case_entities, oid=oid, case_number=case_number)


@mcp.tool()
def lc_search_case_entities(oid: str, entity_type: str, entity_value: str) -> dict:
    """Search case entities across an org."""

    return _call("case.entity.search", lc.search_case_entities, oid=oid, entity_type=entity_type, entity_value=entity_value)


@mcp.tool()
def lc_preview_add_case_entity(
    oid: str,
    case_number: str,
    entity_type: str,
    entity_value: str,
    note: str | None = None,
    verdict: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview adding an entity/IOC to a case."""

    return _call(
        "case.entity.add.preview",
        lc.preview_add_case_entity,
        oid=oid,
        case_number=case_number,
        entity_type=entity_type,
        entity_value=entity_value,
        note=note,
        verdict=verdict,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_update_case_entity(
    oid: str,
    case_number: str,
    entity_id: str,
    note: str | None = None,
    verdict: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview updating a case entity note or verdict."""

    return _call(
        "case.entity.update.preview",
        lc.preview_update_case_entity,
        oid=oid,
        case_number=case_number,
        entity_id=entity_id,
        note=note,
        verdict=verdict,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_remove_case_entity(oid: str, case_number: str, entity_id: str, token_ttl_seconds: int = 300) -> dict:
    """Preview removing an entity from a case."""

    return _call("case.entity.remove.preview", lc.preview_remove_case_entity, oid=oid, case_number=case_number, entity_id=entity_id, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_case_telemetry(oid: str, case_number: str) -> dict:
    """List telemetry references linked to a case."""

    return _call("case.telemetry.list", lc.list_case_telemetry, oid=oid, case_number=case_number)


@mcp.tool()
def lc_preview_add_case_telemetry(
    oid: str,
    case_number: str,
    event: dict[str, Any],
    note: str | None = None,
    verdict: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview linking telemetry to a case."""

    return _call(
        "case.telemetry.add.preview",
        lc.preview_add_case_telemetry,
        oid=oid,
        case_number=case_number,
        event=event,
        note=note,
        verdict=verdict,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_update_case_telemetry(
    oid: str,
    case_number: str,
    telemetry_id: str,
    note: str | None = None,
    verdict: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview updating case telemetry note or verdict."""

    return _call(
        "case.telemetry.update.preview",
        lc.preview_update_case_telemetry,
        oid=oid,
        case_number=case_number,
        telemetry_id=telemetry_id,
        note=note,
        verdict=verdict,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_remove_case_telemetry(oid: str, case_number: str, telemetry_id: str, token_ttl_seconds: int = 300) -> dict:
    """Preview removing telemetry from a case."""

    return _call("case.telemetry.remove.preview", lc.preview_remove_case_telemetry, oid=oid, case_number=case_number, telemetry_id=telemetry_id, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_case_artifacts(oid: str, case_number: str) -> dict:
    """List forensic artifacts linked to a case."""

    return _call("case.artifact.list", lc.list_case_artifacts, oid=oid, case_number=case_number)


@mcp.tool()
def lc_preview_add_case_artifact(
    oid: str,
    case_number: str,
    path: str,
    source: str,
    artifact_type: str | None = None,
    note: str | None = None,
    verdict: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview adding a forensic artifact reference to a case."""

    return _call(
        "case.artifact.add.preview",
        lc.preview_add_case_artifact,
        oid=oid,
        case_number=case_number,
        path=path,
        source=source,
        artifact_type=artifact_type,
        note=note,
        verdict=verdict,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_remove_case_artifact(oid: str, case_number: str, artifact_id: str, token_ttl_seconds: int = 300) -> dict:
    """Preview removing a forensic artifact reference from a case."""

    return _call("case.artifact.remove.preview", lc.preview_remove_case_artifact, oid=oid, case_number=case_number, artifact_id=artifact_id, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_export_case(oid: str, case_number: str) -> dict:
    """Export a case with detections, entities, telemetry, and artifacts."""

    return _call("case.export", lc.export_case, oid=oid, case_number=case_number)


@mcp.tool()
def lc_get_cases_report_summary(oid: str, time_from: str, time_to: str, group_by: str | None = None) -> dict:
    """Get Cases report summary metrics."""

    return _call("case.report", lc.get_cases_report_summary, oid=oid, time_from=time_from, time_to=time_to, group_by=group_by)


@mcp.tool()
def lc_get_cases_dashboard_counts(oid: str) -> dict:
    """Get Cases dashboard counts."""

    return _call("case.dashboard", lc.get_cases_dashboard_counts, oid=oid)


@mcp.tool()
def lc_get_cases_config(oid: str) -> dict:
    """Get Cases configuration for an org."""

    return _call("case.config.get", lc.get_cases_config, oid=oid)


@mcp.tool()
def lc_preview_set_cases_config(oid: str, config: dict[str, Any], token_ttl_seconds: int = 300) -> dict:
    """Preview replacing Cases configuration for an org."""

    return _call("case.config.set.preview", lc.preview_set_cases_config, oid=oid, config=config, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_case_assignees(oid: str) -> dict:
    """List unique case assignee emails for an org."""

    return _call("case.assignees.list", lc.list_case_assignees, oid=oid)


@mcp.tool()
def lc_list_case_orgs() -> dict:
    """List ext-cases organizations accessible to the caller."""

    return lc.list_case_orgs()


@mcp.tool()
def lc_preview_set_case_tags(oid: str, case_number: str, tags: list[str] | str, token_ttl_seconds: int = 300) -> dict:
    """Preview replacing all tags on a case."""

    return _call("case.tag.set.preview", lc.preview_set_case_tags, oid=oid, case_number=case_number, tags=tags, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_add_case_tags(oid: str, case_number: str, tags: list[str] | str, token_ttl_seconds: int = 300) -> dict:
    """Preview adding tags to a case by replacing the exact merged tag list."""

    return _call("case.tag.add.preview", lc.preview_add_case_tags, oid=oid, case_number=case_number, tags=tags, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_remove_case_tags(oid: str, case_number: str, tags: list[str] | str, token_ttl_seconds: int = 300) -> dict:
    """Preview removing tags from a case by replacing the exact remaining tag list."""

    return _call("case.tag.remove.preview", lc.preview_remove_case_tags, oid=oid, case_number=case_number, tags=tags, token_ttl_seconds=token_ttl_seconds)


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
def lc_list_saved_queries(oid: str, limit: int = 100) -> dict:
    """List saved LCQL queries stored in the query hive."""

    return _call("saved_query.list", lc.list_saved_queries, oid=oid, limit=limit)


@mcp.tool()
def lc_get_saved_query(oid: str, name: str) -> dict:
    """Fetch one saved LCQL query by name."""

    return _call("saved_query.get", lc.get_saved_query, oid=oid, name=name)


@mcp.tool()
def lc_preview_set_saved_query(
    oid: str,
    name: str,
    query: str,
    start: int | None = None,
    end: int | None = None,
    stream: str | None = None,
    tags: list[str] | str | None = None,
    comment: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating or updating one saved LCQL query."""

    return _call(
        "saved_query.set.preview",
        lc.preview_set_saved_query,
        oid=oid,
        name=name,
        query=query,
        start=start,
        end=end,
        stream=stream,
        tags=tags,
        comment=comment,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_delete_saved_query(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting one saved LCQL query."""

    return _call("saved_query.delete.preview", lc.preview_delete_saved_query, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_execute_saved_query(
    oid: str,
    name: str,
    start: int | None = None,
    end: int | None = None,
    stream: str | None = None,
) -> dict:
    """Load a saved query and start a paginated LCQL search job."""

    return _call("saved_query.execute", lc.execute_saved_query, oid=oid, name=name, start=start, end=end, stream=stream)


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
def lc_preview_payload_upload_url(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview requesting a signed payload upload URL without uploading bytes."""

    return _call("payload.upload_url.preview", lc.preview_payload_upload_url, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_delete_payload(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting a payload."""

    return _call("payload.delete.preview", lc.preview_delete_payload, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


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
def lc_preview_delete_job(oid: str, job_id: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting one service job record."""

    return _call("job.delete.preview", lc.preview_delete_job, oid=oid, job_id=job_id, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_reliable_tasks(oid: str, limit: int = 100) -> dict:
    """List pending reliable-tasking extension tasks for an org."""

    return _call("reliable_task.list", lc.list_reliable_tasks, oid=oid, limit=limit)


@mcp.tool()
def lc_preview_reliable_task(
    oid: str,
    task: str,
    sensor_id: str | None = None,
    selector: str | None = None,
    context: str | None = None,
    ttl_seconds: int | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview queueing one reliable task through ext-reliable-tasking."""

    return _call(
        "reliable_task.send.preview",
        lc.preview_reliable_task,
        oid=oid,
        task=task,
        sensor_id=sensor_id,
        selector=selector,
        context=context,
        ttl_seconds=ttl_seconds,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_delete_reliable_task(
    oid: str,
    task_id: str,
    sensor_id: str | None = None,
    selector: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview cancelling one pending reliable task through ext-reliable-tasking."""

    return _call(
        "reliable_task.delete.preview",
        lc.preview_delete_reliable_task,
        oid=oid,
        task_id=task_id,
        sensor_id=sensor_id,
        selector=selector,
        token_ttl_seconds=token_ttl_seconds,
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
def lc_export_sensors(oid: str) -> dict:
    """Export the full sensor manifest for an org."""

    return _call("sensor.export", lc.export_sensors, oid=oid)


@mcp.tool()
def lc_preview_set_sensor_version(
    oid: str,
    version: str | None = None,
    is_fallback: bool = False,
    is_sleep: bool = False,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview changing the org sensor version policy."""

    return _call(
        "sensor.version.set.preview",
        lc.preview_set_sensor_version,
        oid=oid,
        version=version,
        is_fallback=is_fallback,
        is_sleep=is_sleep,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_list_available_services(oid: str, limit: int = 100) -> dict:
    """List services/replicants available to an org."""

    return _call("service.list", lc.list_available_services, oid=oid, limit=limit)


@mcp.tool()
def lc_preview_service_request(
    oid: str,
    service_name: str,
    request_data: dict[str, Any],
    is_async: bool = False,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview a generic non-impersonated service request."""

    return _call(
        "service.request.preview",
        lc.preview_service_request,
        oid=oid,
        service_name=service_name,
        request_data=request_data,
        is_async=is_async,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_spotcheck_run(
    oid: str,
    task: str,
    tag: str | None = None,
    selector: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview running a fleet-wide spotcheck task through the spotcheck service."""

    return _call(
        "spotcheck.run.preview",
        lc.preview_spotcheck_run,
        oid=oid,
        task=task,
        tag=tag,
        selector=selector,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_fetch_config(
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
) -> dict:
    """Fetch org IaC configuration through ext-infrastructure."""

    return _call(
        "config.fetch",
        lc.fetch_config,
        oid=oid,
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


@mcp.tool()
def lc_preview_push_config(
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
) -> dict:
    """Preview pushing org IaC configuration through ext-infrastructure."""

    return _call(
        "config.push.preview",
        lc.preview_push_config,
        oid=oid,
        config=config,
        is_force=is_force,
        is_dry_run=is_dry_run,
        ignore_inaccessible=ignore_inaccessible,
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
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_list_exfil_rules(oid: str) -> dict:
    """List exfil prevention rules."""

    return _call("exfil_rule.list", lc.list_exfil_rules, oid=oid)


@mcp.tool()
def lc_preview_create_exfil_watch(
    oid: str,
    name: str,
    event: str,
    value: str,
    operator: str,
    path: str | list[str],
    tags: list[str] | str | None = None,
    platforms: list[str] | str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating an exfil watch rule."""

    return _call(
        "exfil_watch.create.preview",
        lc.preview_create_exfil_watch,
        oid=oid,
        name=name,
        event=event,
        value=value,
        operator=operator,
        path=path,
        tags=tags,
        platforms=platforms,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_create_exfil_event(
    oid: str,
    name: str,
    events: list[str] | str,
    tags: list[str] | str | None = None,
    platforms: list[str] | str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating an exfil event rule."""

    return _call(
        "exfil_event.create.preview",
        lc.preview_create_exfil_event,
        oid=oid,
        name=name,
        events=events,
        tags=tags,
        platforms=platforms,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_delete_exfil_event(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting an exfil event rule."""

    return _call("exfil_event.delete.preview", lc.preview_delete_exfil_event, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_delete_exfil_watch(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting an exfil watch rule."""

    return _call("exfil_watch.delete.preview", lc.preview_delete_exfil_watch, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_feedback_channels(oid: str) -> dict:
    """List ext-feedback channel configuration."""

    return _call("feedback.channel.list", lc.list_feedback_channels, oid=oid)


@mcp.tool()
def lc_preview_set_feedback_channels(
    oid: str,
    channels: list[dict[str, Any]],
    etag: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview replacing ext-feedback channel configuration."""

    return _call(
        "feedback.channel.set.preview",
        lc.preview_set_feedback_channels,
        oid=oid,
        channels=channels,
        etag=etag,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_feedback_simple_approval(
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
) -> dict:
    """Preview sending an external approval request through ext-feedback."""

    return _call(
        "feedback.approval.preview",
        lc.preview_feedback_simple_approval,
        oid=oid,
        channel=channel,
        question=question,
        feedback_destination=feedback_destination,
        case_id=case_id,
        playbook_name=playbook_name,
        approved_content=approved_content,
        denied_content=denied_content,
        timeout_seconds=timeout_seconds,
        timeout_choice=timeout_choice,
        timeout_content=timeout_content,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_feedback_acknowledgement(
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
) -> dict:
    """Preview sending an external acknowledgement request through ext-feedback."""

    return _call(
        "feedback.acknowledgement.preview",
        lc.preview_feedback_acknowledgement,
        oid=oid,
        channel=channel,
        question=question,
        feedback_destination=feedback_destination,
        case_id=case_id,
        playbook_name=playbook_name,
        acknowledged_content=acknowledged_content,
        timeout_seconds=timeout_seconds,
        timeout_content=timeout_content,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_feedback_question(
    oid: str,
    channel: str,
    question: str,
    feedback_destination: str,
    case_id: str | None = None,
    playbook_name: str | None = None,
    timeout_seconds: int | None = None,
    timeout_content: dict[str, Any] | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview sending an external free-form question through ext-feedback."""

    return _call(
        "feedback.question.preview",
        lc.preview_feedback_question,
        oid=oid,
        channel=channel,
        question=question,
        feedback_destination=feedback_destination,
        case_id=case_id,
        playbook_name=playbook_name,
        timeout_seconds=timeout_seconds,
        timeout_content=timeout_content,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_list_hive_types() -> dict:
    """List known LimaCharlie hive type names."""

    return lc.list_hive_types()


@mcp.tool()
def lc_list_hive_records(oid: str, hive_name: str, partition_key: str | None = None, limit: int = 100) -> dict:
    """List records from a Hive partition."""

    return _call("hive.record.list", lc.list_hive_records, oid=oid, hive_name=hive_name, partition_key=partition_key, limit=limit)


@mcp.tool()
def lc_get_hive_record(oid: str, hive_name: str, key: str, partition_key: str | None = None) -> dict:
    """Fetch one Hive record's data payload."""

    return _call("hive.record.get", lc.get_hive_record, oid=oid, hive_name=hive_name, key=key, partition_key=partition_key)


@mcp.tool()
def lc_get_hive_record_metadata(oid: str, hive_name: str, key: str, partition_key: str | None = None) -> dict:
    """Fetch one Hive record's metadata."""

    return _call("hive.record.metadata.get", lc.get_hive_record_metadata, oid=oid, hive_name=hive_name, key=key, partition_key=partition_key)


@mcp.tool()
def lc_get_hive_schema(hive_name: str) -> dict:
    """Fetch the JSON Schema for a typed Hive."""

    return _call("hive.schema.get", lc.get_hive_schema, hive_name=hive_name)


@mcp.tool()
def lc_validate_hive_record(
    oid: str,
    hive_name: str,
    key: str,
    data: Any,
    partition_key: str | None = None,
    arl_url: str | None = None,
    enabled: bool | None = None,
    tags: list[str] | str | None = None,
    comment: str | None = None,
    expiry: int | None = None,
    etag: str | None = None,
    ui_actions: list[dict[str, Any]] | None = None,
) -> dict:
    """Validate a Hive record without saving it."""

    return _call(
        "hive.record.validate",
        lc.validate_hive_record,
        oid=oid,
        hive_name=hive_name,
        key=key,
        data=data,
        partition_key=partition_key,
        arl_url=arl_url,
        enabled=enabled,
        tags=tags,
        comment=comment,
        expiry=expiry,
        etag=etag,
        ui_actions=ui_actions,
    )


@mcp.tool()
def lc_preview_set_hive_record(
    oid: str,
    hive_name: str,
    key: str,
    data: Any | None = None,
    partition_key: str | None = None,
    arl_url: str | None = None,
    enabled: bool | None = None,
    tags: list[str] | str | None = None,
    comment: str | None = None,
    expiry: int | None = None,
    etag: str | None = None,
    ui_actions: list[dict[str, Any]] | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating or updating a generic Hive record."""

    return _call(
        "hive.record.set.preview",
        lc.preview_set_hive_record,
        oid=oid,
        hive_name=hive_name,
        key=key,
        data=data,
        partition_key=partition_key,
        arl_url=arl_url,
        enabled=enabled,
        tags=tags,
        comment=comment,
        expiry=expiry,
        etag=etag,
        ui_actions=ui_actions,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_delete_hive_record(
    oid: str,
    hive_name: str,
    key: str,
    partition_key: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview deleting a generic Hive record."""

    return _call("hive.record.delete.preview", lc.preview_delete_hive_record, oid=oid, hive_name=hive_name, key=key, partition_key=partition_key, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_rename_hive_record(
    oid: str,
    hive_name: str,
    key: str,
    new_name: str,
    partition_key: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview renaming a generic Hive record."""

    return _call("hive.record.rename.preview", lc.preview_rename_hive_record, oid=oid, hive_name=hive_name, key=key, new_name=new_name, partition_key=partition_key, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_set_hive_record_enabled(
    oid: str,
    hive_name: str,
    key: str,
    enabled: bool,
    partition_key: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview setting a Hive record's enabled metadata while preserving existing metadata."""

    return _call("hive.record.enabled.set.preview", lc.preview_set_hive_record_enabled, oid=oid, hive_name=hive_name, key=key, enabled=enabled, partition_key=partition_key, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_secrets(oid: str, limit: int = 100) -> dict:
    """List secret Hive records without exposing secret values."""

    return _call("secret.list", lc.list_secrets, oid=oid, limit=limit)


@mcp.tool()
def lc_get_secret(oid: str, name: str) -> dict:
    """Fetch one secret Hive record with sensitive fields redacted."""

    return _call("secret.get", lc.get_secret, oid=oid, name=name)


@mcp.tool()
def lc_preview_set_secret(
    oid: str,
    name: str,
    secret_value: str,
    tags: list[str] | str | None = None,
    comment: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating or updating a secret Hive record."""

    return _call(
        "secret.set.preview",
        lc.preview_set_secret,
        oid=oid,
        name=name,
        secret_value=secret_value,
        tags=tags,
        comment=comment,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_delete_secret(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting a secret Hive record."""

    return _call("secret.delete.preview", lc.preview_delete_secret, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_set_secret_enabled(
    oid: str,
    name: str,
    enabled: bool,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview toggling a secret Hive record's enabled metadata."""

    return _call("secret.enabled.set.preview", lc.preview_set_secret_enabled, oid=oid, name=name, enabled=enabled, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_lookups(oid: str, limit: int = 100) -> dict:
    """List lookup Hive records."""

    return _call("lookup.list", lc.list_lookups, oid=oid, limit=limit)


@mcp.tool()
def lc_get_lookup(oid: str, name: str) -> dict:
    """Fetch one lookup Hive record."""

    return _call("lookup.get", lc.get_lookup, oid=oid, name=name)


@mcp.tool()
def lc_preview_set_lookup(
    oid: str,
    name: str,
    lookup_data: dict[str, Any] | None = None,
    newline_content: str | None = None,
    yaml_content: str | None = None,
    tags: list[str] | str | None = None,
    comment: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating or updating a lookup Hive record from one supported data format."""

    return _call(
        "lookup.set.preview",
        lc.preview_set_lookup,
        oid=oid,
        name=name,
        lookup_data=lookup_data,
        newline_content=newline_content,
        yaml_content=yaml_content,
        tags=tags,
        comment=comment,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_delete_lookup(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting a lookup Hive record."""

    return _call("lookup.delete.preview", lc.preview_delete_lookup, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_set_lookup_enabled(
    oid: str,
    name: str,
    enabled: bool,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview toggling a lookup Hive record's enabled metadata."""

    return _call("lookup.enabled.set.preview", lc.preview_set_lookup_enabled, oid=oid, name=name, enabled=enabled, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_cloud_adapters(oid: str, limit: int = 100) -> dict:
    """List cloud adapter Hive records."""

    return _call("cloud_adapter.list", lc.list_cloud_adapters, oid=oid, limit=limit)


@mcp.tool()
def lc_get_cloud_adapter(oid: str, name: str) -> dict:
    """Fetch one cloud adapter Hive record."""

    return _call("cloud_adapter.get", lc.get_cloud_adapter, oid=oid, name=name)


@mcp.tool()
def lc_preview_set_cloud_adapter(
    oid: str,
    name: str,
    data: dict[str, Any],
    enabled: bool | None = None,
    tags: list[str] | str | None = None,
    comment: str | None = None,
    expiry: int | None = None,
    etag: str | None = None,
    ui_actions: list[dict[str, Any]] | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating or updating a cloud adapter Hive record."""

    return _call("cloud_adapter.set.preview", lc.preview_set_cloud_adapter, oid=oid, name=name, data=data, enabled=enabled, tags=tags, comment=comment, expiry=expiry, etag=etag, ui_actions=ui_actions, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_delete_cloud_adapter(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting a cloud adapter Hive record."""

    return _call("cloud_adapter.delete.preview", lc.preview_delete_cloud_adapter, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_set_cloud_adapter_enabled(oid: str, name: str, enabled: bool, token_ttl_seconds: int = 300) -> dict:
    """Preview toggling a cloud adapter Hive record's enabled metadata."""

    return _call("cloud_adapter.enabled.set.preview", lc.preview_set_cloud_adapter_enabled, oid=oid, name=name, enabled=enabled, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_external_adapters(oid: str, limit: int = 100) -> dict:
    """List external adapter Hive records."""

    return _call("external_adapter.list", lc.list_external_adapters, oid=oid, limit=limit)


@mcp.tool()
def lc_get_external_adapter(oid: str, name: str) -> dict:
    """Fetch one external adapter Hive record."""

    return _call("external_adapter.get", lc.get_external_adapter, oid=oid, name=name)


@mcp.tool()
def lc_preview_set_external_adapter(
    oid: str,
    name: str,
    data: dict[str, Any],
    enabled: bool | None = None,
    tags: list[str] | str | None = None,
    comment: str | None = None,
    expiry: int | None = None,
    etag: str | None = None,
    ui_actions: list[dict[str, Any]] | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating or updating an external adapter Hive record."""

    return _call("external_adapter.set.preview", lc.preview_set_external_adapter, oid=oid, name=name, data=data, enabled=enabled, tags=tags, comment=comment, expiry=expiry, etag=etag, ui_actions=ui_actions, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_delete_external_adapter(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting an external adapter Hive record."""

    return _call("external_adapter.delete.preview", lc.preview_delete_external_adapter, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_set_external_adapter_enabled(oid: str, name: str, enabled: bool, token_ttl_seconds: int = 300) -> dict:
    """Preview toggling an external adapter Hive record's enabled metadata."""

    return _call("external_adapter.enabled.set.preview", lc.preview_set_external_adapter_enabled, oid=oid, name=name, enabled=enabled, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_playbooks(oid: str, limit: int = 100) -> dict:
    """List playbook Hive records."""

    return _call("playbook.list", lc.list_playbooks, oid=oid, limit=limit)


@mcp.tool()
def lc_get_playbook(oid: str, name: str) -> dict:
    """Fetch one playbook Hive record."""

    return _call("playbook.get", lc.get_playbook, oid=oid, name=name)


@mcp.tool()
def lc_preview_set_playbook(
    oid: str,
    name: str,
    data: dict[str, Any],
    enabled: bool | None = None,
    tags: list[str] | str | None = None,
    comment: str | None = None,
    expiry: int | None = None,
    etag: str | None = None,
    ui_actions: list[dict[str, Any]] | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating or updating a playbook Hive record."""

    return _call("playbook.set.preview", lc.preview_set_playbook, oid=oid, name=name, data=data, enabled=enabled, tags=tags, comment=comment, expiry=expiry, etag=etag, ui_actions=ui_actions, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_delete_playbook(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting a playbook Hive record."""

    return _call("playbook.delete.preview", lc.preview_delete_playbook, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_set_playbook_enabled(oid: str, name: str, enabled: bool, token_ttl_seconds: int = 300) -> dict:
    """Preview toggling a playbook Hive record's enabled metadata."""

    return _call("playbook.enabled.set.preview", lc.preview_set_playbook_enabled, oid=oid, name=name, enabled=enabled, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_sops(oid: str, limit: int = 100) -> dict:
    """List SOP Hive records."""

    return _call("sop.list", lc.list_sops, oid=oid, limit=limit)


@mcp.tool()
def lc_get_sop(oid: str, name: str) -> dict:
    """Fetch one SOP Hive record."""

    return _call("sop.get", lc.get_sop, oid=oid, name=name)


@mcp.tool()
def lc_preview_set_sop(
    oid: str,
    name: str,
    data: dict[str, Any],
    enabled: bool | None = None,
    tags: list[str] | str | None = None,
    comment: str | None = None,
    expiry: int | None = None,
    etag: str | None = None,
    ui_actions: list[dict[str, Any]] | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating or updating an SOP Hive record."""

    return _call("sop.set.preview", lc.preview_set_sop, oid=oid, name=name, data=data, enabled=enabled, tags=tags, comment=comment, expiry=expiry, etag=etag, ui_actions=ui_actions, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_delete_sop(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting an SOP Hive record."""

    return _call("sop.delete.preview", lc.preview_delete_sop, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_set_sop_enabled(oid: str, name: str, enabled: bool, token_ttl_seconds: int = 300) -> dict:
    """Preview toggling an SOP Hive record's enabled metadata."""

    return _call("sop.enabled.set.preview", lc.preview_set_sop_enabled, oid=oid, name=name, enabled=enabled, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_org_notes(oid: str, limit: int = 100) -> dict:
    """List organization-note Hive records."""

    return _call("org_note.list", lc.list_org_notes, oid=oid, limit=limit)


@mcp.tool()
def lc_get_org_note(oid: str, name: str) -> dict:
    """Fetch one organization-note Hive record."""

    return _call("org_note.get", lc.get_org_note, oid=oid, name=name)


@mcp.tool()
def lc_preview_set_org_note(
    oid: str,
    name: str,
    data: dict[str, Any],
    enabled: bool | None = None,
    tags: list[str] | str | None = None,
    comment: str | None = None,
    expiry: int | None = None,
    etag: str | None = None,
    ui_actions: list[dict[str, Any]] | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating or updating an organization-note Hive record."""

    return _call("org_note.set.preview", lc.preview_set_org_note, oid=oid, name=name, data=data, enabled=enabled, tags=tags, comment=comment, expiry=expiry, etag=etag, ui_actions=ui_actions, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_delete_org_note(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting an organization-note Hive record."""

    return _call("org_note.delete.preview", lc.preview_delete_org_note, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_set_org_note_enabled(oid: str, name: str, enabled: bool, token_ttl_seconds: int = 300) -> dict:
    """Preview toggling an organization-note Hive record's enabled metadata."""

    return _call("org_note.enabled.set.preview", lc.preview_set_org_note_enabled, oid=oid, name=name, enabled=enabled, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_ai_agents(oid: str, limit: int = 100) -> dict:
    """List AI agent Hive records."""

    return _call("ai_agent.list", lc.list_ai_agents, oid=oid, limit=limit)


@mcp.tool()
def lc_get_ai_agent(oid: str, name: str) -> dict:
    """Fetch one AI agent Hive record."""

    return _call("ai_agent.get", lc.get_ai_agent, oid=oid, name=name)


@mcp.tool()
def lc_preview_set_ai_agent(
    oid: str,
    name: str,
    data: dict[str, Any],
    enabled: bool | None = None,
    tags: list[str] | str | None = None,
    comment: str | None = None,
    expiry: int | None = None,
    etag: str | None = None,
    ui_actions: list[dict[str, Any]] | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating or updating an AI agent Hive record."""

    return _call("ai_agent.set.preview", lc.preview_set_ai_agent, oid=oid, name=name, data=data, enabled=enabled, tags=tags, comment=comment, expiry=expiry, etag=etag, ui_actions=ui_actions, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_delete_ai_agent(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting an AI agent Hive record."""

    return _call("ai_agent.delete.preview", lc.preview_delete_ai_agent, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_set_ai_agent_enabled(oid: str, name: str, enabled: bool, token_ttl_seconds: int = 300) -> dict:
    """Preview toggling an AI agent Hive record's enabled metadata."""

    return _call("ai_agent.enabled.set.preview", lc.preview_set_ai_agent_enabled, oid=oid, name=name, enabled=enabled, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_ai_skills(oid: str, limit: int = 100) -> dict:
    """List AI skill Hive records."""

    return _call("ai_skill.list", lc.list_ai_skills, oid=oid, limit=limit)


@mcp.tool()
def lc_get_ai_skill(oid: str, name: str) -> dict:
    """Fetch one AI skill Hive record."""

    return _call("ai_skill.get", lc.get_ai_skill, oid=oid, name=name)


@mcp.tool()
def lc_preview_set_ai_skill(
    oid: str,
    name: str,
    data: dict[str, Any],
    enabled: bool | None = None,
    tags: list[str] | str | None = None,
    comment: str | None = None,
    expiry: int | None = None,
    etag: str | None = None,
    ui_actions: list[dict[str, Any]] | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating or updating an AI skill Hive record."""

    return _call("ai_skill.set.preview", lc.preview_set_ai_skill, oid=oid, name=name, data=data, enabled=enabled, tags=tags, comment=comment, expiry=expiry, etag=etag, ui_actions=ui_actions, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_delete_ai_skill(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting an AI skill Hive record."""

    return _call("ai_skill.delete.preview", lc.preview_delete_ai_skill, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_set_ai_skill_enabled(oid: str, name: str, enabled: bool, token_ttl_seconds: int = 300) -> dict:
    """Preview toggling an AI skill Hive record's enabled metadata."""

    return _call("ai_skill.enabled.set.preview", lc.preview_set_ai_skill_enabled, oid=oid, name=name, enabled=enabled, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_ai_memory_records(oid: str, partition_key: str | None = None, limit: int = 100) -> dict:
    """List ai_memory Hive records."""

    return _call("ai_memory.record.list", lc.list_ai_memory_records, oid=oid, partition_key=partition_key, limit=limit)


@mcp.tool()
def lc_get_ai_memory_record(oid: str, agent: str, partition_key: str | None = None) -> dict:
    """Fetch the full ai_memory record for an agent."""

    return _call("ai_memory.record.get", lc.get_ai_memory_record, oid=oid, agent=agent, partition_key=partition_key)


@mcp.tool()
def lc_list_ai_memories(oid: str, agent: str, partition_key: str | None = None) -> dict:
    """List memory entries for an ai_memory agent record."""

    return _call("ai_memory.list", lc.list_ai_memories, oid=oid, agent=agent, partition_key=partition_key)


@mcp.tool()
def lc_get_ai_memory(oid: str, agent: str, memory_name: str, partition_key: str | None = None) -> dict:
    """Fetch one memory entry from an ai_memory agent record."""

    return _call("ai_memory.get", lc.get_ai_memory, oid=oid, agent=agent, memory_name=memory_name, partition_key=partition_key)


@mcp.tool()
def lc_preview_set_ai_memory(
    oid: str,
    agent: str,
    memory_name: str,
    content: str,
    partition_key: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview setting one ai_memory entry through the partial-merge hook."""

    return _call("ai_memory.set.preview", lc.preview_set_ai_memory, oid=oid, agent=agent, memory_name=memory_name, content=content, partition_key=partition_key, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_delete_ai_memory(
    oid: str,
    agent: str,
    memory_name: str,
    partition_key: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview deleting one ai_memory entry through the partial-merge hook."""

    return _call("ai_memory.delete.preview", lc.preview_delete_ai_memory, oid=oid, agent=agent, memory_name=memory_name, partition_key=partition_key, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_delete_ai_memory_record(
    oid: str,
    agent: str,
    partition_key: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview deleting an entire ai_memory agent record."""

    return _call("ai_memory.record.delete.preview", lc.preview_delete_ai_memory_record, oid=oid, agent=agent, partition_key=partition_key, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_ai_sessions(oid: str, status: str | None = None, cursor: str | None = None, limit: int = 100) -> dict:
    """List org-scoped AI sessions for governance and cost visibility."""

    return _call("ai.session.list", lc.list_ai_sessions, oid=oid, status=status, cursor=cursor, limit=limit)


@mcp.tool()
def lc_get_ai_session(oid: str, session_id: str) -> dict:
    """Fetch one org-scoped AI session."""

    return _call("ai.session.get", lc.get_ai_session, oid=oid, session_id=session_id)


@mcp.tool()
def lc_get_ai_session_history(oid: str, session_id: str, limit: int = 100) -> dict:
    """Fetch bounded conversation history for one org-scoped AI session."""

    return _call("ai.session.history", lc.get_ai_session_history, oid=oid, session_id=session_id, limit=limit)


@mcp.tool()
def lc_preview_terminate_ai_session(oid: str, session_id: str, token_ttl_seconds: int = 300) -> dict:
    """Preview terminating a running AI session."""

    return _call("ai.session.terminate.preview", lc.preview_terminate_ai_session, oid=oid, session_id=session_id, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_ai_usage_identities(oid: str, limit: int = 100) -> dict:
    """List API key identities with AI-session usage data."""

    return _call("ai.usage.identity.list", lc.list_ai_usage_identities, oid=oid, limit=limit)


@mcp.tool()
def lc_get_ai_usage(oid: str, identity: str, limit: int = 100) -> dict:
    """Fetch bounded token and cost usage for one AI usage identity."""

    return _call("ai.usage.get", lc.get_ai_usage, oid=oid, identity=identity, limit=limit)


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
def lc_check_org_name(name: str) -> dict:
    """Check whether an organization name is available."""

    return _call("org.name.check", lc.check_org_name, name=name)


@mcp.tool()
def lc_preview_create_org(
    name: str,
    location: str | None = None,
    template: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating a new organization."""

    return _call(
        "org.create.preview",
        lc.preview_create_org,
        name=name,
        location=location,
        template=template,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_get_org_config_value(oid: str, config_name: str) -> dict:
    """Get one organization config value."""

    return _call("org.config.get", lc.get_org_config_value, oid=oid, config_name=config_name)


@mcp.tool()
def lc_preview_set_org_config_value(oid: str, config_name: str, value: str, token_ttl_seconds: int = 300) -> dict:
    """Preview setting one organization config value."""

    return _call(
        "org.config.set.preview",
        lc.preview_set_org_config_value,
        oid=oid,
        config_name=config_name,
        value=value,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_dismiss_org_error(oid: str, component: str, token_ttl_seconds: int = 300) -> dict:
    """Preview dismissing one organization component error."""

    return _call("org.error.dismiss.preview", lc.preview_dismiss_org_error, oid=oid, component=component, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_get_org_delete_confirmation(oid: str) -> dict:
    """Request the LimaCharlie organization delete confirmation token."""

    return _call("org.delete.confirmation", lc.get_org_delete_confirmation, oid=oid)


@mcp.tool()
def lc_preview_delete_org(oid: str, confirmation: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting an organization using a LimaCharlie confirmation token."""

    return _call("org.delete.preview", lc.preview_delete_org, oid=oid, confirmation=confirmation, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_set_org_quota(oid: str, quota: int, token_ttl_seconds: int = 300) -> dict:
    """Preview setting the sensor quota for an org."""

    return _call("org.quota.set.preview", lc.preview_set_org_quota, oid=oid, quota=quota, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_rename_org(oid: str, new_name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview renaming an org."""

    return _call("org.rename.preview", lc.preview_rename_org, oid=oid, new_name=new_name, token_ttl_seconds=token_ttl_seconds)


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
def lc_preview_create_group(name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview creating an organization group."""

    return _call("group.create.preview", lc.preview_create_group, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_get_group(group_id: str) -> dict:
    """Fetch one organization group definition."""

    return _call("group.get", lc.get_group, group_id=group_id)


@mcp.tool()
def lc_preview_delete_group(group_id: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting an organization group."""

    return _call("group.delete.preview", lc.preview_delete_group, group_id=group_id, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_group_logs(group_id: str, limit: int = 100) -> dict:
    """List audit logs for one organization group."""

    return _call("group.logs", lc.list_group_logs, group_id=group_id, limit=limit)


@mcp.tool()
def lc_preview_add_group_member(group_id: str, email: str, token_ttl_seconds: int = 300) -> dict:
    """Preview adding a user as a group member."""

    return _call("group.member.add.preview", lc.preview_add_group_member, group_id=group_id, email=email, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_remove_group_member(group_id: str, email: str, token_ttl_seconds: int = 300) -> dict:
    """Preview removing a user from group members."""

    return _call("group.member.remove.preview", lc.preview_remove_group_member, group_id=group_id, email=email, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_add_group_owner(group_id: str, email: str, token_ttl_seconds: int = 300) -> dict:
    """Preview adding a user as a group owner."""

    return _call("group.owner.add.preview", lc.preview_add_group_owner, group_id=group_id, email=email, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_remove_group_owner(group_id: str, email: str, token_ttl_seconds: int = 300) -> dict:
    """Preview removing a user from group owners."""

    return _call("group.owner.remove.preview", lc.preview_remove_group_owner, group_id=group_id, email=email, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_set_group_permissions(group_id: str, permissions: list[str] | str, token_ttl_seconds: int = 300) -> dict:
    """Preview replacing a group's permission list."""

    return _call("group.permissions.set.preview", lc.preview_set_group_permissions, group_id=group_id, permissions=permissions, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_add_group_org(group_id: str, member_oid: str, token_ttl_seconds: int = 300) -> dict:
    """Preview adding an organization to a group."""

    return _call("group.org.add.preview", lc.preview_add_group_org, group_id=group_id, member_oid=member_oid, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_remove_group_org(group_id: str, member_oid: str, token_ttl_seconds: int = 300) -> dict:
    """Preview removing an organization from a group."""

    return _call("group.org.remove.preview", lc.preview_remove_group_org, group_id=group_id, member_oid=member_oid, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_users(oid: str, limit: int = 100) -> dict:
    """List users with access to an org."""

    return _call("user.list", lc.list_users, oid=oid, limit=limit)


@mcp.tool()
def lc_preview_invite_user(oid: str, email: str, token_ttl_seconds: int = 300) -> dict:
    """Preview inviting a user to an org."""

    return _call("user.invite.preview", lc.preview_invite_user, oid=oid, email=email, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_remove_user(oid: str, email: str, token_ttl_seconds: int = 300) -> dict:
    """Preview removing a user from an org."""

    return _call("user.remove.preview", lc.preview_remove_user, oid=oid, email=email, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_user_permissions(oid: str) -> dict:
    """List user permission mappings for an org."""

    return _call("user.permission.list", lc.list_user_permissions, oid=oid)


@mcp.tool()
def lc_preview_add_user_permission(oid: str, email: str, permission: str, token_ttl_seconds: int = 300) -> dict:
    """Preview granting one permission to a user."""

    return _call("user.permission.add.preview", lc.preview_add_user_permission, oid=oid, email=email, permission=permission, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_remove_user_permission(oid: str, email: str, permission: str, token_ttl_seconds: int = 300) -> dict:
    """Preview revoking one permission from a user."""

    return _call("user.permission.remove.preview", lc.preview_remove_user_permission, oid=oid, email=email, permission=permission, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_set_user_role(oid: str, email: str, role: str, token_ttl_seconds: int = 300) -> dict:
    """Preview replacing a user's permissions with a predefined role."""

    return _call("user.role.set.preview", lc.preview_set_user_role, oid=oid, email=email, role=role, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_api_keys(oid: str, limit: int = 100) -> dict:
    """List API key metadata for an org."""

    return _call("api_key.list", lc.list_api_keys, oid=oid, limit=limit)


@mcp.tool()
def lc_preview_create_api_key(
    oid: str,
    name: str,
    permissions: list[str] | str,
    ip_range: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating an API key."""

    return _call("api_key.create.preview", lc.preview_create_api_key, oid=oid, name=name, permissions=permissions, ip_range=ip_range, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_delete_api_key(oid: str, key_hash: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting an API key by key hash."""

    return _call("api_key.delete.preview", lc.preview_delete_api_key, oid=oid, key_hash=key_hash, token_ttl_seconds=token_ttl_seconds)


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
def lc_preview_create_installation_key(
    oid: str,
    description: str,
    tags: list[str] | str | None = None,
    use_public_ca: bool = False,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating an installation key."""

    return _call(
        "installation_key.create.preview",
        lc.preview_create_installation_key,
        oid=oid,
        description=description,
        tags=tags,
        use_public_ca=use_public_ca,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_delete_installation_key(oid: str, installation_key_id: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting an installation key."""

    return _call("installation_key.delete.preview", lc.preview_delete_installation_key, oid=oid, installation_key_id=installation_key_id, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_outputs(oid: str, limit: int = 100) -> dict:
    """List output integration configuration for an org."""

    return _call("output.list", lc.list_outputs, oid=oid, limit=limit)


@mcp.tool()
def lc_preview_create_ingestion_key(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview creating an ingestion key."""

    return _call("ingestion_key.create.preview", lc.preview_create_ingestion_key, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_delete_ingestion_key(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting an ingestion key."""

    return _call("ingestion_key.delete.preview", lc.preview_delete_ingestion_key, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_create_output(
    oid: str,
    name: str,
    module: str,
    data_type: str,
    config: dict[str, Any] | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating an output integration."""

    return _call("output.create.preview", lc.preview_create_output, oid=oid, name=name, module=module, data_type=data_type, config=config, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_delete_output(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting an output integration."""

    return _call("output.delete.preview", lc.preview_delete_output, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_extension_subscriptions(oid: str, limit: int = 100) -> dict:
    """List extension subscriptions for an org."""

    return _call("extension.list_subscribed", lc.list_extension_subscriptions, oid=oid, limit=limit)


@mcp.tool()
def lc_preview_subscribe_extension(oid: str, extension_name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview subscribing an org to an extension."""

    return _call("extension.subscribe.preview", lc.preview_subscribe_extension, oid=oid, extension_name=extension_name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_unsubscribe_extension(oid: str, extension_name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview unsubscribing an org from an extension."""

    return _call("extension.unsubscribe.preview", lc.preview_unsubscribe_extension, oid=oid, extension_name=extension_name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_rekey_extension(oid: str, extension_name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview rotating an extension subscription API key."""

    return _call("extension.rekey.preview", lc.preview_rekey_extension, oid=oid, extension_name=extension_name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_available_extensions(limit: int = 100) -> dict:
    """List globally available extension definitions."""

    return _call("extension.list_available", lc.list_available_extensions, limit=limit)


@mcp.tool()
def lc_get_extension(extension_name: str) -> dict:
    """Fetch one globally available extension definition."""

    return _call("extension.get", lc.get_extension, extension_name=extension_name)


@mcp.tool()
def lc_preview_create_extension(
    extension_definition: dict[str, Any],
    extension_name: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating an extension definition."""

    return _call("extension.create.preview", lc.preview_create_extension, extension_definition=extension_definition, extension_name=extension_name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_update_extension(
    extension_definition: dict[str, Any],
    extension_name: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview updating an extension definition."""

    return _call("extension.update.preview", lc.preview_update_extension, extension_definition=extension_definition, extension_name=extension_name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_delete_extension(extension_name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting an extension definition."""

    return _call("extension.delete.preview", lc.preview_delete_extension, extension_name=extension_name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_get_extension_schema(oid: str, extension_name: str) -> dict:
    """Fetch one extension schema for an org context."""

    return _call("extension.schema.get", lc.get_extension_schema, oid=oid, extension_name=extension_name)


@mcp.tool()
def lc_preview_extension_request(
    oid: str,
    extension_name: str,
    action: str,
    data: dict[str, Any] | None = None,
    impersonate: bool = False,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview a generic extension request."""

    return _call(
        "extension.request.preview",
        lc.preview_extension_request,
        oid=oid,
        extension_name=extension_name,
        action=action,
        data=data,
        impersonate=impersonate,
        token_ttl_seconds=token_ttl_seconds,
    )


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
def lc_preview_set_artifact_rule(
    oid: str,
    name: str,
    platforms: list[str] | str,
    patterns: list[str] | str,
    is_delete_after: bool = False,
    retention_days: int = 30,
    tags: list[str] | str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating or updating an artifact collection rule."""

    return _call(
        "artifact_rule.set.preview",
        lc.preview_set_artifact_rule,
        oid=oid,
        name=name,
        platforms=platforms,
        patterns=patterns,
        is_delete_after=is_delete_after,
        retention_days=retention_days,
        tags=tags,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_delete_artifact_rule(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting an artifact collection rule."""

    return _call("artifact_rule.delete.preview", lc.preview_delete_artifact_rule, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_ingestion_keys(oid: str, limit: int = 100) -> dict:
    """List ingestion key metadata for an org."""

    return _call("ingestion_key.list", lc.list_ingestion_keys, oid=oid, limit=limit)


@mcp.tool()
def lc_list_logging_rules(oid: str, limit: int = 100) -> dict:
    """List logging collection rules for an org."""

    return _call("logging_rule.list", lc.list_logging_rules, oid=oid, limit=limit)


@mcp.tool()
def lc_preview_set_logging_rule(
    oid: str,
    name: str,
    patterns: list[str] | str,
    tags: list[str] | str | None = None,
    platforms: list[str] | str | None = None,
    retention_days: int | None = None,
    delete_after: bool = False,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating or updating a logging collection rule."""

    return _call(
        "logging_rule.set.preview",
        lc.preview_set_logging_rule,
        oid=oid,
        name=name,
        patterns=patterns,
        tags=tags,
        platforms=platforms,
        retention_days=retention_days,
        delete_after=delete_after,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_delete_logging_rule(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting a logging collection rule."""

    return _call("logging_rule.delete.preview", lc.preview_delete_logging_rule, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_dr_rules(oid: str, namespace: str | None = None, limit: int = 100) -> dict:
    """List D&R rules from a hive namespace."""

    return _call("dr_rule.list", lc.list_dr_rules, oid=oid, namespace=namespace, limit=limit)


@mcp.tool()
def lc_get_dr_rule(oid: str, name: str, namespace: str | None = None) -> dict:
    """Fetch one D&R rule by name from a hive namespace."""

    return _call("dr_rule.get", lc.get_dr_rule, oid=oid, name=name, namespace=namespace)


@mcp.tool()
def lc_preview_set_dr_rule(
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
) -> dict:
    """Preview creating or updating a D&R rule."""

    return _call(
        "dr_rule.set.preview",
        lc.preview_set_dr_rule,
        oid=oid,
        name=name,
        data=data,
        namespace=namespace,
        enabled=enabled,
        tags=tags,
        comment=comment,
        expiry=expiry,
        etag=etag,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_delete_dr_rule(oid: str, name: str, namespace: str | None = None, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting a D&R rule."""

    return _call("dr_rule.delete.preview", lc.preview_delete_dr_rule, oid=oid, name=name, namespace=namespace, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_fp_rules(oid: str, limit: int = 100) -> dict:
    """List false-positive rules for an org."""

    return _call("fp_rule.list", lc.list_fp_rules, oid=oid, limit=limit)


@mcp.tool()
def lc_get_fp_rule(oid: str, name: str) -> dict:
    """Fetch one false-positive rule by name."""

    return _call("fp_rule.get", lc.get_fp_rule, oid=oid, name=name)


@mcp.tool()
def lc_preview_set_fp_rule(
    oid: str,
    name: str,
    data: dict[str, Any],
    enabled: bool | None = None,
    tags: list[str] | str | None = None,
    comment: str | None = None,
    expiry: int | None = None,
    etag: str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating or updating a false-positive rule."""

    return _call(
        "fp_rule.set.preview",
        lc.preview_set_fp_rule,
        oid=oid,
        name=name,
        data=data,
        enabled=enabled,
        tags=tags,
        comment=comment,
        expiry=expiry,
        etag=etag,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_delete_fp_rule(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting a false-positive rule."""

    return _call("fp_rule.delete.preview", lc.preview_delete_fp_rule, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_integrity_rules(oid: str, limit: int = 100) -> dict:
    """List integrity monitoring rules for an org."""

    return _call("integrity_rule.list", lc.list_integrity_rules, oid=oid, limit=limit)


@mcp.tool()
def lc_get_integrity_rule(oid: str, name: str) -> dict:
    """Fetch one integrity monitoring rule by name."""

    return _call("integrity_rule.get", lc.get_integrity_rule, oid=oid, name=name)


@mcp.tool()
def lc_preview_set_integrity_rule(
    oid: str,
    name: str,
    patterns: list[str] | str,
    tags: list[str] | str | None = None,
    platforms: list[str] | str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating or updating an integrity monitoring rule."""

    return _call(
        "integrity_rule.set.preview",
        lc.preview_set_integrity_rule,
        oid=oid,
        name=name,
        patterns=patterns,
        tags=tags,
        platforms=platforms,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_delete_integrity_rule(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting an integrity monitoring rule."""

    return _call("integrity_rule.delete.preview", lc.preview_delete_integrity_rule, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


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
def lc_preview_yara_scan(
    oid: str,
    sensor_id: str,
    rule: str,
    timeout_seconds: int | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview running an ad-hoc YARA scan on one sensor."""

    return _call(
        "yara.scan.preview",
        lc.preview_yara_scan,
        oid=oid,
        sensor_id=sensor_id,
        rule=rule,
        timeout_seconds=timeout_seconds,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_set_yara_rule(
    oid: str,
    name: str,
    sources: list[str] | str,
    tags: list[str] | str | None = None,
    platforms: list[str] | str | None = None,
    token_ttl_seconds: int = 300,
) -> dict:
    """Preview creating or updating a YARA scanning rule."""

    return _call(
        "yara_rule.set.preview",
        lc.preview_set_yara_rule,
        oid=oid,
        name=name,
        sources=sources,
        tags=tags,
        platforms=platforms,
        token_ttl_seconds=token_ttl_seconds,
    )


@mcp.tool()
def lc_preview_delete_yara_rule(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting a YARA scanning rule."""

    return _call("yara_rule.delete.preview", lc.preview_delete_yara_rule, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_list_yara_sources(oid: str, limit: int = 100) -> dict:
    """List YARA source names for an org."""

    return _call("yara_source.list", lc.list_yara_sources, oid=oid, limit=limit)


@mcp.tool()
def lc_get_yara_source(oid: str, name: str) -> dict:
    """Fetch one YARA source by name."""

    return _call("yara_source.get", lc.get_yara_source, oid=oid, name=name)


@mcp.tool()
def lc_preview_set_yara_source(oid: str, name: str, source: str, token_ttl_seconds: int = 300) -> dict:
    """Preview creating or updating a YARA source."""

    return _call("yara_source.set.preview", lc.preview_set_yara_source, oid=oid, name=name, source=source, token_ttl_seconds=token_ttl_seconds)


@mcp.tool()
def lc_preview_delete_yara_source(oid: str, name: str, token_ttl_seconds: int = 300) -> dict:
    """Preview deleting a YARA source."""

    return _call("yara_source.delete.preview", lc.preview_delete_yara_source, oid=oid, name=name, token_ttl_seconds=token_ttl_seconds)


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
