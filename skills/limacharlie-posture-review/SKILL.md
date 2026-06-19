---
name: limacharlie-posture-review
description: Review LimaCharlie org posture across fleet, content, outputs, access, cases, and detection noise.
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

## Interpretation Notes

Treat service-managed LimaCharlie objects as explanatory context unless there is
independent evidence they are causing risk or noise:

- API keys whose names begin with `_ext-` or `_soteria-` are normally managed by
  extension subscriptions. Do not recommend deleting them directly; inspect
  extension subscriptions instead.
- If `lc_review_access_hygiene` reports many total API keys, distinguish
  user-generated keys from service-managed keys before calling it an access
  hygiene issue.
- Org errors for components shaped like
  `c2/analytics/rules/service.*` with `rule produced too many states` are
  service-managed rule-state pressure. Normal org API keys may not expose those
  hidden rule bodies for tuning. Report them as LimaCharlie-managed content
  signals, not as missing user permissions.
- Dismiss org errors only after deciding the underlying signal has been
  investigated or accepted; dismissal clears the symptom, not necessarily the
  cause.

## Guardrails

Do not pull a firehose, spout, or unbounded telemetry stream. Do not imply that
streaming raw telemetry into an LLM is a security program. Use bounded reads,
time windows, cursors, and focused follow-up tools.

Do not mutate LimaCharlie state during review. If remediation is appropriate,
propose the relevant preview tool and wait for explicit user approval.
