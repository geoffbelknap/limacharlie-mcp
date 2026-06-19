from __future__ import annotations

from typing import Any

from limacharlie_mcp.api import LimaCharlieAPI


OID = "263c19e9-bd4a-475a-8cd3-5403af446cb9"


class ReviewClient(LimaCharlieAPI):
    def __init__(self, tmp_path, *, fail_permissions: bool = False, detection_truncated: bool = False) -> None:
        super().__init__(api_key="secret", audit_path=tmp_path / "audit.jsonl")
        self.fail_permissions = fail_permissions
        self.detection_truncated = detection_truncated

    def response(self, operation: str, data: Any, *, ok: bool = True, truncated: bool = False) -> dict[str, Any]:
        response = self._local_response(operation, data, limit=100)
        response["ok"] = ok
        response["meta"]["truncated"] = truncated
        if not ok:
            response["error"] = {
                "code": "permission_denied",
                "class": "authorization",
                "message": "missing permission for test",
                "retryable": False,
                "same_input_retryable": False,
            }
        return response

    def list_sensors(self, oid: str, selector: str | None = None, limit: int = 100) -> dict[str, Any]:
        return self.response("sensor.list", {"sensors": [{"sid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}]})

    def list_online_sensors(self, oid: str, limit: int = 100) -> dict[str, Any]:
        return self.response("sensor.online.list", {"sensors": []})

    def list_tags(self, oid: str, limit: int = 100) -> dict[str, Any]:
        return self.response("tag.list", {"tags": ["prod"]})

    def list_detections(
        self,
        oid: str,
        start: int,
        end: int,
        limit: int = 100,
        cursor: str = "-",
        category: str | None = None,
    ) -> dict[str, Any]:
        return self.response(
            "detection.list",
            {"detects": [{"rule_name": "noisy_rule", "cat": "edr"} for _ in range(12)]},
            truncated=self.detection_truncated,
        )

    def list_cases(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self.response("case.list", {"cases": [{"status": "open", "severity": "high"}]})

    def get_cases_dashboard_counts(self, oid: str) -> dict[str, Any]:
        return self.response("case.dashboard", {"open": 1})

    def list_dr_rules(self, oid: str, namespace: str | None = None, limit: int = 100) -> dict[str, Any]:
        return self.response("dr_rule.list", {"rules": [{"name": "rule"}]})

    def list_fp_rules(self, oid: str, limit: int = 100) -> dict[str, Any]:
        return self.response("fp_rule.list", {"rules": []})

    def list_logging_rules(self, oid: str, limit: int = 100) -> dict[str, Any]:
        return self.response("logging_rule.list", {"rules": []})

    def list_integrity_rules(self, oid: str, limit: int = 100) -> dict[str, Any]:
        return self.response("integrity_rule.list", {"rules": []})

    def list_yara_rules(self, oid: str, limit: int = 100) -> dict[str, Any]:
        return self.response("yara_rule.list", {"rules": []})

    def get_mitre_report(self, oid: str) -> dict[str, Any]:
        return self.response("mitre.get", {"coverage": {}})

    def list_outputs(self, oid: str, limit: int = 100) -> dict[str, Any]:
        return self.response("output.list", {"outputs": []})

    def list_extension_subscriptions(self, oid: str, limit: int = 100) -> dict[str, Any]:
        return self.response("extension.list_subscribed", {"extensions": []})

    def list_feedback_channels(self, oid: str) -> dict[str, Any]:
        return self.response("feedback.channel.list", {"channels": []})

    def list_users(self, oid: str, limit: int = 100) -> dict[str, Any]:
        return self.response("user.list", {"users": [{"email": "analyst@example.com"}]})

    def list_user_permissions(self, oid: str) -> dict[str, Any]:
        return self.response("user.permission.list", {"users": []}, ok=not self.fail_permissions)

    def list_api_keys(self, oid: str, limit: int = 100) -> dict[str, Any]:
        return self.response("api_key.list", {"api_keys": []})

    def list_groups(self, limit: int = 100) -> dict[str, Any]:
        return self.response("group.list", {"groups": []})

    def list_org_errors(self, oid: str) -> dict[str, Any]:
        return self.response("org.errors", {"errors": [{"component": "output"}]})


def test_review_detection_noise_flags_truncated_and_concentrated_sample(tmp_path) -> None:
    client = ReviewClient(tmp_path, detection_truncated=True)

    result = client.review_detection_noise(OID, 1_750_000_000, 1_750_003_600, limit=10)

    assert result["ok"] is True
    finding_ids = {finding["id"] for finding in result["data"]["findings"]}
    assert "detection.sample_truncated" in finding_ids
    assert "detection.concentrated_rule_volume" in finding_ids
    assert result["data"]["metrics"]["top_rules"][0] == {"value": "noisy_rule", "count": 12}


def test_review_access_hygiene_keeps_partial_permission_failure(tmp_path) -> None:
    client = ReviewClient(tmp_path, fail_permissions=True)

    result = client.review_access_hygiene(OID)

    assert result["ok"] is True
    assert result["warnings"]
    failed_sources = [source for source in result["data"]["sources"] if not source["ok"]]
    assert failed_sources[0]["operation"] == "user.permission.list"
    assert any(finding["id"] == "access.no_org_api_keys" for finding in result["data"]["findings"])


def test_review_fleet_health_prefers_sensor_list_online_flags(tmp_path) -> None:
    class OnlineFlagClient(ReviewClient):
        def list_sensors(self, oid: str, selector: str | None = None, limit: int = 100) -> dict[str, Any]:
            return self.response(
                "sensor.list",
                {
                    "sensors": [
                        {"sid": "sensor-1", "is_online": True},
                        {"sid": "sensor-2", "is_online": True},
                        {"sid": "sensor-3", "is_online": True},
                        {"sid": "sensor-4", "is_online": False},
                    ]
                },
            )

        def list_online_sensors(self, oid: str, limit: int = 100) -> dict[str, Any]:
            return self.response("sensor.online.list", {"count": 1})

    client = OnlineFlagClient(tmp_path)

    result = client.review_fleet_health(OID)

    assert result["data"]["metrics"]["online_sensor_endpoint_count"] == 1
    assert result["data"]["metrics"]["sensor_list_online_count"] == 3
    assert result["data"]["metrics"]["online_sensor_sample_count"] == 3
    assert all(finding["id"] != "fleet.low_online_ratio" for finding in result["data"]["findings"])


def test_review_org_posture_aggregates_component_findings(tmp_path) -> None:
    client = ReviewClient(tmp_path)

    result = client.review_org_posture(OID, start=1_750_000_000, end=1_750_003_600, limit=20)

    assert result["ok"] is True
    assert result["operation"] == "review.org_posture"
    assert result["state"]["current"] == "needs_attention"
    assert result["data"]["metrics"]["component_count"] == 6
    assert any(finding["id"] == "org.component_errors" for finding in result["data"]["findings"])


def test_review_org_posture_exposes_failed_component_sources(tmp_path) -> None:
    client = ReviewClient(tmp_path, fail_permissions=True)

    result = client.review_org_posture(OID, limit=20)

    assert result["data"]["metrics"]["failed_source_count"] >= 1
    failed_sources = result["data"]["metrics"]["failed_sources"]
    assert any(source["operation"] == "user.permission.list" for source in failed_sources)
    assert any(source["operation"] == "user.permission.list" for source in result["data"]["sources"] if not source["ok"])
    access_component = next(
        component for component in result["data"]["metrics"]["components"] if component["operation"] == "review.access_hygiene"
    )
    assert access_component["failed_source_count"] == 1
