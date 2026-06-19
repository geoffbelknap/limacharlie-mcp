from __future__ import annotations

from dataclasses import dataclass
from typing import Any


DEFAULT_PROFILE = "full-dev"
MUTATION_OPERATION_PREFIXES = ("mutation.",)


@dataclass(frozen=True)
class ProfileDefinition:
    name: str
    title: str
    description: str
    include_suites: frozenset[str] = frozenset()
    include_actions: frozenset[str] | None = None
    include_operations: frozenset[str] = frozenset()
    include_operation_prefixes: tuple[str, ...] = ()
    include_tools: frozenset[str] = frozenset()
    read_only_all_suites: bool = False
    full_surface: bool = False


CORE_OPERATION_PREFIXES = (
    "auth.",
    "tool.",
    "download.",
    "schema.",
    "ontology.",
    "event_type.",
)
CORE_OPERATIONS = frozenset({"org.list"})

REVIEW_OPERATIONS = CORE_OPERATIONS | frozenset(
    {
        "api_key.list",
        "artifact_rule.list",
        "audit.list",
        "billing.details",
        "billing.plans",
        "billing.status",
        "case.assignees.list",
        "case.config.get",
        "case.dashboard",
        "case.get",
        "case.list",
        "case.org.list",
        "case.report",
        "cloud_adapter.get",
        "cloud_adapter.list",
        "config.fetch",
        "detection.get",
        "detection.list",
        "dr_rule.get",
        "dr_rule.list",
        "exfil_rule.list",
        "extension.get",
        "extension.list_available",
        "extension.list_subscribed",
        "extension.schema.get",
        "external_adapter.get",
        "external_adapter.list",
        "feedback.channel.list",
        "fp_rule.get",
        "fp_rule.list",
        "group.get",
        "group.list",
        "group.logs",
        "hive.record.get",
        "hive.record.list",
        "hive.record.metadata.get",
        "hive.record.validate",
        "hive.schema.get",
        "hive.type.list",
        "ingestion_key.list",
        "installation_key.get",
        "installation_key.list",
        "integrity_rule.get",
        "integrity_rule.list",
        "lookup.get",
        "lookup.list",
        "mitre.get",
        "org.errors",
        "org.get",
        "org.quota_usage",
        "org.runtime_metadata",
        "org.stats",
        "org.urls",
        "output.list",
        "playbook.get",
        "playbook.list",
        "saved_query.get",
        "saved_query.list",
        "schema.get",
        "schema.list",
        "secret.list",
        "sensor.get",
        "sensor.hostname_search",
        "sensor.list",
        "sensor.online.list",
        "sensor.tag.list",
        "service.list",
        "sop.get",
        "sop.list",
        "tag.list",
        "tag.sensor_search",
        "user.list",
        "user.permission.list",
        "vulnerability.cve.get",
        "vulnerability.cve.hosts",
        "vulnerability.cve.list",
        "vulnerability.cve.packages",
        "vulnerability.dashboard",
        "vulnerability.endpoint.list",
        "vulnerability.epss_history",
        "vulnerability.host.packages",
        "vulnerability.resolution.list",
        "vulnerability.snapshot.list",
        "yara_rule.list",
        "yara_source.get",
        "yara_source.list",
    }
)

RECOVER_OPERATIONS = CORE_OPERATIONS | frozenset(
    {
        "artifact.list",
        "case.artifact.list",
        "case.detection.list",
        "case.entity.list",
        "case.entity.search",
        "case.get",
        "case.list",
        "case.note.add.preview",
        "case.tag.add.preview",
        "case.tag.remove.preview",
        "case.tag.set.preview",
        "case.telemetry.list",
        "case.update.preview",
        "detection.get",
        "detection.list",
        "dr_rule.get",
        "dr_rule.list",
        "event.get",
        "event.list",
        "event.overview",
        "extension.list_subscribed",
        "fp_rule.get",
        "fp_rule.list",
        "integrity_rule.get",
        "integrity_rule.list",
        "job.get",
        "job.list",
        "job.wait",
        "logging_rule.list",
        "mutation.cancel",
        "mutation.confirm",
        "mutation.pending.list",
        "org.errors",
        "org.get",
        "org.stats",
        "org.urls",
        "output.list",
        "reliable_task.delete.preview",
        "reliable_task.list",
        "reliable_task.send.preview",
        "schema.get",
        "schema.list",
        "sensor.get",
        "sensor.hostname_search",
        "sensor.isolation_status.get",
        "sensor.list",
        "sensor.online.list",
        "sensor.rejoin.preview",
        "sensor.seal_status.get",
        "sensor.tag.add.preview",
        "sensor.tag.list",
        "sensor.tag.remove.preview",
        "sensor.task.preview",
        "sensor.unseal.preview",
        "sensor.wait_online",
        "service.list",
        "spotcheck.run.preview",
        "tag.list",
        "tag.sensor_search",
        "yara.scan.preview",
        "yara_rule.list",
        "yara_source.get",
        "yara_source.list",
    }
)


PROFILE_DEFINITIONS: dict[str, ProfileDefinition] = {
    "full-dev": ProfileDefinition(
        name="full-dev",
        title="Full developer surface",
        description="All registered LimaCharlie MCP tools. Use for parity development and audits, not normal agent sessions.",
        full_surface=True,
    ),
    "core": ProfileDefinition(
        name="core",
        title="Core auth and reference",
        description="Authentication, org discovery, runtime status, schemas, ontology, event types, and download target references.",
        include_suites=frozenset({"platform"}),
        include_operations=CORE_OPERATIONS,
        include_operation_prefixes=CORE_OPERATION_PREFIXES,
    ),
    "fleet": ProfileDefinition(
        name="fleet",
        title="Fleet onboarding and maintenance",
        description="Sensor discovery, onboarding keys, tags, download targets, version policy, and bounded fleet health reads.",
        include_suites=frozenset({"platform"}),
        include_operations=CORE_OPERATIONS
        | frozenset(
            {
                "sensor.list",
                "sensor.get",
                "sensor.wait_online",
                "sensor.online.list",
                "sensor.tag.list",
                "sensor.hostname_search",
                "sensor.export",
                "sensor.version.set.preview",
                "tag.list",
                "tag.sensor_search",
            }
        ),
        include_operation_prefixes=CORE_OPERATION_PREFIXES + ("installation_key.",) + MUTATION_OPERATION_PREFIXES,
    ),
    "admin": ProfileDefinition(
        name="admin",
        title="Organization administration",
        description="Organizations, users, groups, API keys, billing, outputs, extensions, and org-level configuration.",
        include_suites=frozenset({"platform", "administration"}),
        include_operation_prefixes=CORE_OPERATION_PREFIXES + MUTATION_OPERATION_PREFIXES,
    ),
    "content": ProfileDefinition(
        name="content",
        title="Detection and content maintenance",
        description="D&R, false positives, YARA, Hive content, lookups, secrets references, playbooks, SOPs, and content governance.",
        include_suites=frozenset({"platform", "content"}),
        include_operation_prefixes=CORE_OPERATION_PREFIXES + MUTATION_OPERATION_PREFIXES,
    ),
    "detect": ProfileDefinition(
        name="detect",
        title="Detect and investigate",
        description="Bounded detection, event, case, IOC, search, audit, artifact, payload, vulnerability, and job reads.",
        include_suites=frozenset({"platform", "investigation"}),
        include_actions=frozenset({"read", "execute"}),
        include_operations=CORE_OPERATIONS,
        include_operation_prefixes=CORE_OPERATION_PREFIXES,
    ),
    "contain": ProfileDefinition(
        name="contain",
        title="Contain affected systems",
        description="Endpoint containment previews, response tasking, reliable tasking, job cancellation, and supporting sensor/case evidence.",
        include_suites=frozenset({"platform", "response"}),
        include_operations=CORE_OPERATIONS
        | frozenset(
            {
                "sensor.list",
                "sensor.get",
                "sensor.isolation_status.get",
                "sensor.seal_status.get",
                "sensor.wait_online",
                "sensor.online.list",
                "detection.list",
                "detection.get",
                "case.list",
                "case.get",
            }
        ),
        include_operation_prefixes=CORE_OPERATION_PREFIXES + MUTATION_OPERATION_PREFIXES,
    ),
    "evict": ProfileDefinition(
        name="evict",
        title="Evict adversary footholds",
        description="Response tasking plus content and YARA surfaces used to remove persistence and unsafe artifacts through preview/confirm.",
        include_suites=frozenset({"platform", "response", "content"}),
        include_operations=CORE_OPERATIONS
        | frozenset(
            {
                "sensor.list",
                "sensor.get",
                "sensor.wait_online",
                "detection.list",
                "detection.get",
                "case.list",
                "case.get",
            }
        ),
        include_operation_prefixes=CORE_OPERATION_PREFIXES + MUTATION_OPERATION_PREFIXES,
    ),
    "recover": ProfileDefinition(
        name="recover",
        title="Recover and verify",
        description="Post-incident recovery verification plus guarded rejoin, unseal, tasking, spotcheck, tagging, and case-update previews.",
        include_suites=frozenset({"platform"}),
        include_operations=RECOVER_OPERATIONS,
        include_operation_prefixes=CORE_OPERATION_PREFIXES,
    ),
    "review": ProfileDefinition(
        name="review",
        title="Posture review and tuning",
        description="Read-only assessment for org posture, fleet health, detection quality, content coverage, case backlog, output health, and access hygiene.",
        include_suites=frozenset({"platform"}),
        include_actions=frozenset({"read", "validate"}),
        include_operations=REVIEW_OPERATIONS,
        include_operation_prefixes=CORE_OPERATION_PREFIXES,
    ),
}


def available_profiles() -> tuple[str, ...]:
    return tuple(PROFILE_DEFINITIONS)


def normalize_profile(profile: str | None) -> str:
    selected = (profile or DEFAULT_PROFILE).strip().lower()
    if selected in {"full", "all", "dev"}:
        selected = "full-dev"
    if selected not in PROFILE_DEFINITIONS:
        allowed = ", ".join(available_profiles())
        raise ValueError(f"Unknown LimaCharlie MCP profile {profile!r}. Expected one of: {allowed}.")
    return selected


def profile_catalog(catalog: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        name: {
            "title": definition.title,
            "description": definition.description,
            "operation_count": len(filter_operation_catalog(catalog, name)),
            "tool_count": len(tool_names_for_profile(catalog, name)),
        }
        for name, definition in PROFILE_DEFINITIONS.items()
    }


def filter_operation_catalog(catalog: dict[str, dict[str, Any]], profile: str | None) -> dict[str, dict[str, Any]]:
    selected = normalize_profile(profile)
    return {operation: spec for operation, spec in catalog.items() if operation_in_profile(operation, spec, selected)}


def tool_names_for_profile(catalog: dict[str, dict[str, Any]], profile: str | None) -> set[str]:
    operations = filter_operation_catalog(catalog, profile)
    return {str(spec["tool"]) for spec in operations.values()}


def operation_in_profile(operation: str, spec: dict[str, Any], profile: str | None) -> bool:
    selected = normalize_profile(profile)
    definition = PROFILE_DEFINITIONS[selected]
    if definition.full_surface:
        return True

    suite = str(spec.get("suite", ""))
    action = str(spec.get("action", ""))
    tool = str(spec.get("tool", ""))

    if operation in definition.include_operations or tool in definition.include_tools:
        return _action_allowed(action, definition)
    if operation.startswith(definition.include_operation_prefixes):
        return _action_allowed(action, definition)
    if definition.read_only_all_suites and action in {"read", "validate"}:
        return True
    if suite in definition.include_suites:
        return _action_allowed(action, definition)
    return False


def _action_allowed(action: str, definition: ProfileDefinition) -> bool:
    return definition.include_actions is None or action in definition.include_actions
