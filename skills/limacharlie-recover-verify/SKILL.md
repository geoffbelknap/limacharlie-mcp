---
name: limacharlie-recover-verify
description: Verify LimaCharlie post-incident recovery after containment and eviction. Use when users need to rejoin isolated sensors, unseal hosts, verify telemetry and outputs, close or update cases, confirm no recurrence, or assess readiness to return systems to normal operation.
---

# LimaCharlie Recover Verify

## Workflow

Use the `recover` profile. Recovery should restore normal operations only after
active risk has been contained and footholds have been evicted.

1. Verify readiness:
   - Confirm no active high-confidence detections in the recovery window.
   - Check sensor online state, isolation status, seal status, outputs, and cases.
   - Use `lc_review_fleet_health`, `lc_review_output_health`, and focused reads.
2. Preview restoration:
   - Rejoin sensors with `lc_preview_rejoin_sensor`.
   - Unseal sensors with `lc_preview_unseal_sensor`.
   - Add or remove recovery tags with sensor tag preview tools.
   - Update cases through case preview tools.
3. Confirm only explicit previews:
   - Explain why restoration is justified.
   - Confirm one preview token at a time.
4. Validate after restoration:
   - Re-read sensor status and case state.
   - Run bounded detection/event checks for recurrence.
   - Capture remaining risks and follow-up tuning or review work.

## Guardrails

Do not recover first because isolation is inconvenient. Do not treat a quiet
alert window as proof of recovery without checking telemetry health and output
delivery. If sources fail due to missing permissions, report the gap instead of
declaring recovery complete.
