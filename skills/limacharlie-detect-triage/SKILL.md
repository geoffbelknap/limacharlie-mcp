---
name: limacharlie-detect-triage
description: Triage LimaCharlie detections, events, cases, IOCs, searches, artifacts, jobs, and vulnerability evidence. Use when users ask what happened, whether an alert matters, how to investigate a detection or case, or how to collect bounded evidence before containment.
---

# LimaCharlie Detect Triage

## Workflow

Use the `detect` profile. Keep evidence bounded and preserve the incident arc:
detect before contain, evict, or recover.

1. Anchor the object:
   - Detection: `lc_get_detection`, then `lc_list_detections` for bounded context.
   - Case: `lc_get_case`, then linked detections, entities, telemetry, and artifacts.
   - Sensor: `lc_get_sensor`, `lc_list_sensor_events`, and event overview.
2. Build timeline:
   - Use explicit `start` and `end`.
   - Fetch child events only when a parent atom suggests a process tree or causal chain.
   - Use search estimation before executing LCQL.
3. Check prevalence:
   - Use IOC/object search tools for hashes, domains, IPs, paths, or command lines.
   - Prefer batch IOC lookup for small bounded sets.
4. Decide next phase:
   - If active risk remains, recommend containment actions but do not execute them.
   - If persistence or malicious artifacts are likely, hand off to evict workflow.
   - If the incident appears resolved, hand off to recover verification.

## Reporting

Return a concise timeline, affected assets, confidence, unknowns, and next
recommended workflow. Separate observed facts from inference.
