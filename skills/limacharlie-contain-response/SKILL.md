---
name: limacharlie-contain-response
description: Contain affected systems in LimaCharlie with guarded preview/confirm actions. Use when users need endpoint isolation, response tasking, reliable tasking, sensor tags, job cancellation, or immediate risk reduction after detection triage.
---

# LimaCharlie Contain Response

## Workflow

Use the `contain` profile. Containment reduces blast radius; it is not the same
as eviction or recovery.

1. Verify target:
   - Confirm `oid`, `sensor_id`, hostname, platform, and recent online state.
   - Check existing isolation and seal status before proposing changes.
2. Choose the least disruptive action:
   - Isolation: `lc_preview_isolate_sensor`.
   - Tagging: `lc_preview_add_sensor_tag`.
   - Tasking: `lc_preview_sensor_task` or `lc_preview_reliable_task`.
   - Job cancellation: `lc_preview_delete_job` when a running job is harmful or stale.
3. Preview first:
   - Explain expected effect, reversibility, and target resource.
   - Ask for explicit confirmation before `lc_confirm_mutation`.
4. Verify:
   - Re-read isolation/seal status or job state.
   - Update a case only through preview tools if documentation is needed.

## Guardrails

Do not delete sensors as a containment shortcut unless the user explicitly asks
and understands the recovery impact. Do not execute multiple host actions from a
single vague instruction; preview exact targets and commands.
