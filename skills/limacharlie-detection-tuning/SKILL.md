---
name: limacharlie-detection-tuning
description: Tune LimaCharlie detections, false positives, noisy alerts, missing alerts, and content coverage.
---

# LimaCharlie Detection Tuning

## Workflow

Treat tuning as evidence work, not content churn.

1. Bound the sample:
   - Require `oid`, `start`, and `end`.
   - Call `lc_review_detection_noise` before listing many detections.
   - Use `lc_list_detections` only with explicit limits and windows.
2. Identify patterns:
   - Look for one rule/category dominating the sample.
   - Compare detections with cases and analyst outcomes when available.
   - Use `lc_review_content_coverage` and `lc_get_mitre_report` for coverage context.
3. Inspect concrete content:
   - Read the D&R rule with `lc_get_dr_rule`.
   - Read existing false-positive rules with `lc_list_fp_rules` and `lc_get_fp_rule`.
   - Check related YARA, integrity, and logging rules when the signal depends on collection.
4. Recommend changes:
   - Prefer narrower conditions, context checks, tags, or suppression boundaries.
   - Explain what evidence would validate the change.
   - Use preview tools for any proposed action.

## Output Shape

Return:

- the noisy or missing signal being evaluated,
- the bounded evidence window,
- likely root cause,
- proposed tuning approach,
- validation query or follow-up read,
- exact preview tool to use if the user approves.

Never claim a rule is safe to disable solely because it is noisy. Noisy may still
mean high-value. Tie each recommendation to evidence and expected risk.
