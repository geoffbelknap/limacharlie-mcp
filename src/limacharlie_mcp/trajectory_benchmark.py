from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from typing import Any

from .api import OPERATION_CATALOG, UNSUPPORTED_CAPABILITIES
from .profiles import available_profiles


@dataclass(frozen=True)
class Criterion:
    feature: str
    weight: int
    description: str


@dataclass(frozen=True)
class Trajectory:
    id: str
    title: str
    prompt: str
    category: str
    criteria: tuple[Criterion, ...]


@dataclass(frozen=True)
class Candidate:
    id: str
    title: str
    kind: str
    auth_model: str
    evidence: tuple[str, ...]
    features: frozenset[str]


TRAJECTORIES: tuple[Trajectory, ...] = (
    Trajectory(
        id="first_auth_setup",
        title="First auth/setup",
        prompt="Set up LimaCharlie auth for an agent session, verify access, and explain what is stored without exposing secrets.",
        category="auth",
        criteria=(
            Criterion("oauth_or_vault_auth", 2, "Avoids asking users to manage raw long-lived secrets in chat or env files."),
            Criterion("setup_verification", 2, "Verifies the credential against LimaCharlie before declaring setup complete."),
            Criterion("permission_guidance", 2, "Explains the smallest useful permissions for the chosen workflow."),
            Criterion("secret_redaction", 2, "Does not expose API keys, JWTs, Vault tokens, or generated runtime secrets."),
            Criterion("multi_org_discovery", 1, "Can help users discover or select orgs when the auth model permits it."),
        ),
    ),
    Trajectory(
        id="list_sensors",
        title="List sensors",
        prompt="List LimaCharlie sensors for an org, keep the result bounded, and tell me what permission is needed.",
        category="discovery",
        criteria=(
            Criterion("sensor_list", 2, "Has a direct way to list sensors."),
            Criterion("explicit_org_scope", 2, "Requires or preserves explicit org scope."),
            Criterion("bounded_results", 2, "Bounds output size with limits or pagination."),
            Criterion("structured_envelope", 2, "Returns operation, request id, resource, data, warnings, and summary metadata."),
            Criterion("permission_guidance", 1, "Advertises the required permission for sensor listing."),
        ),
    ),
    Trajectory(
        id="review_org_posture",
        title="Review org posture",
        prompt="Review my LimaCharlie org posture and produce evidence-backed findings and next actions.",
        category="review",
        criteria=(
            Criterion("posture_review", 3, "Has a first-class posture review workflow."),
            Criterion("evidence_summary", 2, "Includes source evidence and bounded counts behind findings."),
            Criterion("permission_aware_partial_results", 2, "Distinguishes missing permissions from real posture problems."),
            Criterion("profile_guidance", 1, "Guides agents to the right profile/tools for review."),
            Criterion("safe_remediation_handoff", 1, "Turns risky fixes into safe action suggestions instead of immediate writes."),
        ),
    ),
    Trajectory(
        id="tune_noisy_detection",
        title="Tune noisy detection",
        prompt="Find noisy detections, explain likely tuning options, and avoid weakening coverage without evidence.",
        category="tuning",
        criteria=(
            Criterion("detection_noise_review", 2, "Summarizes detection volume and concentration over a bounded time window."),
            Criterion("content_rule_review", 2, "Can inspect relevant D&R/FP/YARA/content context."),
            Criterion("replay_or_validation", 2, "Can validate or dry-run rule logic before proposing changes."),
            Criterion("safe_content_action", 2, "Requires safe action preview/confirm for content changes."),
            Criterion("before_after_measurement", 1, "Supports an explicit before/after measurement plan."),
        ),
    ),
    Trajectory(
        id="case_triage",
        title="Case or detection triage",
        prompt="Triage a case or detection, gather bounded evidence, and report what happened with request IDs.",
        category="investigation",
        criteria=(
            Criterion("case_triage", 2, "Can list/fetch cases or detections."),
            Criterion("sensor_event_context", 2, "Can gather bounded sensor event context."),
            Criterion("ioc_lookup", 1, "Can search indicators or object prevalence."),
            Criterion("structured_envelope", 2, "Returns evidence request IDs and resource identifiers."),
            Criterion("error_recovery", 2, "Gives retryable/not-found/policy next actions for common failures."),
        ),
    ),
    Trajectory(
        id="isolate_rejoin_safe_action",
        title="Isolate/rejoin safe action",
        prompt="Prepare isolation for a suspicious endpoint, show exactly what will happen, and require human confirmation.",
        category="contain",
        criteria=(
            Criterion("safe_endpoint_action", 3, "Supports endpoint isolation/rejoin through a safe action boundary."),
            Criterion("preview_confirm", 2, "Separates preview from confirmation with an expiring token."),
            Criterion("state_verification", 1, "Can read current isolation/seal state before and after."),
            Criterion("permission_guidance", 1, "Shows required permission for confirmation."),
            Criterion("reversibility_notes", 2, "Explains recovery or reversal steps."),
        ),
    ),
    Trajectory(
        id="dr_change_safe_action",
        title="D&R change safe action",
        prompt="Prepare a D&R change, validate it, show the diff/effect, and require confirmation before writing.",
        category="content",
        criteria=(
            Criterion("safe_dr_action", 3, "Supports D&R writes through a safe action boundary."),
            Criterion("replay_or_validation", 2, "Can validate or dry-run rule behavior."),
            Criterion("preview_confirm", 2, "Separates preview from confirmation with an expiring token."),
            Criterion("permission_guidance", 1, "Shows required permission for confirmation."),
            Criterion("reversibility_notes", 1, "Explains restore or rollback steps."),
        ),
    ),
    Trajectory(
        id="unsupported_firehose_request",
        title="Unsupported firehose request",
        prompt="Stream all LimaCharlie telemetry into the model so it can watch everything live.",
        category="unsupported",
        criteria=(
            Criterion("explicit_firehose_boundary", 3, "Refuses unbounded firehose or live telemetry streaming as an MCP workflow."),
            Criterion("bounded_alternatives", 2, "Suggests bounded historical reads or proper output/SIEM integrations."),
            Criterion("no_firehose_tools", 2, "Does not expose firehose/spout/live stream tools in normal catalog."),
            Criterion("unsupported_error_semantics", 2, "Represents unsupported capability clearly enough for agents to stop."),
        ),
    ),
)


NATIVE_PLUGIN = Candidate(
    id="native_claude_code_plugin",
    title="Native LimaCharlie Claude Code plugin",
    kind="native_plugin",
    auth_model="LimaCharlie CLI/OAuth path",
    evidence=(
        "Official plugin uses the LimaCharlie CLI through Bash for API access.",
        "Official plugin includes LimaCharlie skills for detection engineering, tuning, investigations, and sensor tasking.",
    ),
    features=frozenset(
        {
            "oauth_or_vault_auth",
            "setup_verification",
            "multi_org_discovery",
            "sensor_list",
            "case_triage",
            "sensor_event_context",
            "ioc_lookup",
            "detection_noise_review",
            "content_rule_review",
            "replay_or_validation",
        }
    ),
)

NATIVE_HOSTED_MCP = Candidate(
    id="native_hosted_mcp",
    title="Native LimaCharlie hosted MCP",
    kind="native_hosted_mcp",
    auth_model="Hosted HTTP MCP with OAuth-capable clients",
    evidence=(
        "Official docs list https://mcp.limacharlie.io/mcp as the hosted MCP endpoint.",
        "Official docs describe OAuth authentication for MCP clients that support it.",
    ),
    features=frozenset(
        {
            "oauth_or_vault_auth",
            "setup_verification",
            "multi_org_discovery",
            "sensor_list",
        }
    ),
)


def local_mcp_candidate() -> Candidate:
    operations = OPERATION_CATALOG
    features = {
        "oauth_or_vault_auth",
        "setup_verification",
        "permission_guidance",
        "secret_redaction",
        "sensor_list",
        "explicit_org_scope",
        "bounded_results",
        "structured_envelope",
        "posture_review",
        "evidence_summary",
        "permission_aware_partial_results",
        "profile_guidance",
        "safe_remediation_handoff",
        "detection_noise_review",
        "before_after_measurement",
        "case_triage",
        "sensor_event_context",
        "ioc_lookup",
        "error_recovery",
        "preview_confirm",
        "state_verification",
        "reversibility_notes",
        "explicit_firehose_boundary",
        "bounded_alternatives",
        "no_firehose_tools",
        "unsupported_error_semantics",
    }
    if "replay.validate_rule" in operations or "replay.run_dry" in operations:
        features.add("replay_or_validation")
    if {"dr_rule.list", "fp_rule.list", "yara_rule.list"} <= set(operations):
        features.add("content_rule_review")
    if "sensor.isolate.preview" in operations and "sensor.rejoin.preview" in operations and "action.confirm" in operations:
        features.add("safe_endpoint_action")
    if "dr_rule.set.preview" in operations and "action.confirm" in operations:
        features.add("safe_dr_action")
        features.add("safe_content_action")
    if "telemetry.firehose" not in UNSUPPORTED_CAPABILITIES:
        features.discard("explicit_firehose_boundary")
    return Candidate(
        id="local_direct_api_mcp",
        title="Local direct-API LimaCharlie MCP",
        kind="local_mcp",
        auth_model="Managed local Vault by default; direct LimaCharlie API JWT exchange",
        evidence=(
            "Uses direct LimaCharlie APIs rather than shelling out to the LimaCharlie CLI.",
            "Profiles, permission metadata, safe actions, redaction, and bounded responses are encoded in the operation catalog.",
            f"Profiles: {', '.join(available_profiles())}.",
        ),
        features=frozenset(features),
    )


def candidate_catalog() -> tuple[Candidate, ...]:
    return (local_mcp_candidate(), NATIVE_PLUGIN, NATIVE_HOSTED_MCP)


def score_candidate(candidate: Candidate, trajectory: Trajectory) -> dict[str, Any]:
    total = sum(criterion.weight for criterion in trajectory.criteria)
    earned = 0
    met: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    for criterion in trajectory.criteria:
        row = {
            "feature": criterion.feature,
            "weight": criterion.weight,
            "description": criterion.description,
        }
        if criterion.feature in candidate.features:
            earned += criterion.weight
            met.append(row)
        else:
            missing.append(row)
    ratio = earned / total if total else 0
    if ratio >= 0.85:
        rating = "strong"
    elif ratio >= 0.5:
        rating = "partial"
    else:
        rating = "weak"
    return {
        "candidate_id": candidate.id,
        "trajectory_id": trajectory.id,
        "score": earned,
        "max_score": total,
        "ratio": round(ratio, 3),
        "rating": rating,
        "met": met,
        "missing": missing,
    }


def build_report(candidates: tuple[Candidate, ...] | None = None, trajectories: tuple[Trajectory, ...] = TRAJECTORIES) -> dict[str, Any]:
    selected_candidates = candidates or candidate_catalog()
    scores = {
        candidate.id: {trajectory.id: score_candidate(candidate, trajectory) for trajectory in trajectories}
        for candidate in selected_candidates
    }
    totals = {}
    for candidate in selected_candidates:
        candidate_scores = scores[candidate.id].values()
        earned = sum(score["score"] for score in candidate_scores)
        maximum = sum(score["max_score"] for score in candidate_scores)
        totals[candidate.id] = {
            "score": earned,
            "max_score": maximum,
            "ratio": round(earned / maximum, 3) if maximum else 0,
            "strong_trajectory_count": sum(1 for score in candidate_scores if score["rating"] == "strong"),
            "partial_trajectory_count": sum(1 for score in candidate_scores if score["rating"] == "partial"),
            "weak_trajectory_count": sum(1 for score in candidate_scores if score["rating"] == "weak"),
        }
    return {
        "ok": True,
        "benchmark": "limacharlie_native_vs_local_mcp",
        "version": 1,
        "candidates": [_candidate_dict(candidate) for candidate in selected_candidates],
        "trajectories": [_trajectory_dict(trajectory) for trajectory in trajectories],
        "scores": scores,
        "totals": totals,
        "summary": _summary(totals),
    }


def _candidate_dict(candidate: Candidate) -> dict[str, Any]:
    return {
        "id": candidate.id,
        "title": candidate.title,
        "kind": candidate.kind,
        "auth_model": candidate.auth_model,
        "evidence": list(candidate.evidence),
        "features": sorted(candidate.features),
    }


def _trajectory_dict(trajectory: Trajectory) -> dict[str, Any]:
    return {
        "id": trajectory.id,
        "title": trajectory.title,
        "prompt": trajectory.prompt,
        "category": trajectory.category,
        "criteria": [
            {"feature": criterion.feature, "weight": criterion.weight, "description": criterion.description}
            for criterion in trajectory.criteria
        ],
    }


def _summary(totals: dict[str, dict[str, Any]]) -> dict[str, Any]:
    ranked = sorted(totals.items(), key=lambda item: (-item[1]["ratio"], item[0]))
    return {
        "leader": ranked[0][0] if ranked else None,
        "ranking": [{"candidate_id": candidate_id, **score} for candidate_id, score in ranked],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# LimaCharlie MCP trajectory benchmark",
        "",
        "## Summary",
    ]
    for row in report["summary"]["ranking"]:
        lines.append(f"- {row['candidate_id']}: {row['score']}/{row['max_score']} ({row['ratio']})")
    lines.append("")
    lines.append("## Trajectories")
    for trajectory in report["trajectories"]:
        lines.append(f"### {trajectory['title']}")
        for candidate_id, scores in report["scores"].items():
            score = scores[trajectory["id"]]
            lines.append(f"- {candidate_id}: {score['rating']} ({score['score']}/{score['max_score']})")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the deterministic LimaCharlie native-vs-local MCP trajectory benchmark.")
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    args = parser.parse_args(argv)
    report = build_report()
    if args.format == "markdown":
        print(render_markdown(report), end="")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
