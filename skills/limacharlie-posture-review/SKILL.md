---
name: limacharlie-posture-review
description: Review a LimaCharlie organization for operational posture, fleet health, content coverage, output health, access hygiene, case backlog, and noisy detection signals. Use when users ask for expert review, recurring assessment, tuning opportunities, or whether their LimaCharlie instance is well configured.
---

# LimaCharlie Posture Review

## Workflow

Use the `review` profile when possible. Prefer aggregate tools first, then drill
into concrete records only where findings justify the context cost.

1. Establish scope:
   - Confirm `oid`.
   - Ask for a detection window only if detection noise is part of the review.
2. Run aggregate review:
   - Call `lc_review_org_posture`.
   - If a time window is available, include `start` and `end`.
3. Drill into high-signal areas:
   - Fleet: `lc_review_fleet_health`, then `lc_list_sensors`.
   - Content: `lc_review_content_coverage`, then D&R/FP/YARA/list tools.
   - Access: `lc_review_access_hygiene`, then `lc_list_api_keys` and `lc_list_user_permissions`.
   - Outputs: `lc_review_output_health`, then `lc_list_outputs`.
   - Cases: `lc_review_case_backlog`, then filtered `lc_list_cases`.
4. Report:
   - Lead with high and medium findings.
   - Separate evidence, risk, and recommendation.
   - Include source reads that failed due to missing permissions.

## Guardrails

Do not pull a firehose, spout, or unbounded telemetry stream. Do not imply that
streaming raw telemetry into an LLM is a security program. Use bounded reads,
time windows, cursors, and focused follow-up tools.

Do not mutate LimaCharlie state during review. If remediation is appropriate,
propose the relevant preview tool and wait for explicit user approval.
