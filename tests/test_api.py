from __future__ import annotations

import json
import base64
import gzip
from pathlib import Path
from typing import Any

import httpx
import pytest

from limacharlie_mcp.api import LimaCharlieAPI, ValidationError


OID = "263c19e9-bd4a-475a-8cd3-5403af446cb9"
SID = "eb531a76-bd44-48e1-9fb6-5e24ae9560e4"


def compressed_json(payload: Any) -> str:
    return base64.b64encode(gzip.compress(json.dumps(payload).encode())).decode()


class FakeHTTP:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.routes: list[tuple[str, str, httpx.Response]] = []

    def add(self, method: str, url: str, payload: Any, status_code: int = 200) -> None:
        self.routes.append(
            (
                method,
                url,
                httpx.Response(
                    status_code,
                    json=payload,
                    headers={"content-type": "application/json"},
                ),
            )
        )

    def request(self, method, url, *, headers=None, params=None, data=None, json=None, timeout=None):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers or {},
                "params": params or {},
                "data": data,
                "json": json,
                "timeout": timeout,
            }
        )
        for route_method, route_url, response in self.routes:
            if route_method == method and route_url == url:
                return response
        raise AssertionError(f"unexpected request: {method} {url}")


def make_client(tmp_path: Path, fake: FakeHTTP) -> LimaCharlieAPI:
    fake.add("POST", "https://jwt.limacharlie.io", {"jwt": "test-token", "expires_in": 3000})
    return LimaCharlieAPI(api_key="secret", audit_path=tmp_path / "audit.jsonl", http_client=fake)


def assert_ax_envelope(result: dict[str, Any], operation: str) -> None:
    assert result["operation"] == operation
    assert result["request_id"].startswith("req_")
    assert "resource" in result
    assert "side_effects" in result
    assert "warnings" in result
    assert "observed_at" in result
    assert "summary" in result["meta"]


def test_tool_catalog_exposes_operation_contracts(tmp_path: Path) -> None:
    client = make_client(tmp_path, FakeHTTP())

    result = client.tool_catalog()

    assert result["ok"] is True
    assert_ax_envelope(result, "tool.catalog")
    assert result["data"]["default_mode"] == "read_only"
    assert result["data"]["operations"]["sensor.list"]["required_inputs"] == ["oid"]
    assert result["data"]["operations"]["event.list"]["suite"] == "investigation"
    assert result["data"]["operations"]["api_key.list"]["suite"] == "administration"
    assert result["data"]["operations"]["detection.list"]["bounds"]["time_format"] == "unix_seconds"


def test_list_orgs_uses_direct_api_and_jwt(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", "https://api.limacharlie.io/v1/user/orgs", {"orgs": [{"oid": OID, "name": "Test"}]})
    client = make_client(tmp_path, fake)

    result = client.list_orgs()

    assert result["ok"] is True
    assert_ax_envelope(result, "org.list")
    assert result["data"]["orgs"][0]["name"] == "Test"
    assert fake.calls[0]["url"] == "https://jwt.limacharlie.io"
    assert fake.calls[0]["data"]["oid"] == "-"
    assert fake.calls[1]["headers"]["Authorization"] == "Bearer test-token"


def test_auth_whoami_uses_minimal_oid_for_unscoped_identity(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", "https://api.limacharlie.io/v1/who", {"uid": "user-1"})
    client = make_client(tmp_path, fake)

    result = client.auth_whoami()

    assert result["ok"] is True
    assert_ax_envelope(result, "auth.whoami")
    assert fake.calls[0]["data"]["oid"] == "-"
    assert fake.calls[1]["url"] == "https://api.limacharlie.io/v1/who"


def test_auth_whoami_permission_check_is_local_and_requires_oid(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", "https://api.limacharlie.io/v1/who", {"perms": ["sensor.get"]})
    client = make_client(tmp_path, fake)

    result = client.auth_whoami(oid=OID, check_perm="sensor.get")

    assert result["ok"] is True
    assert_ax_envelope(result, "auth.whoami")
    assert result["data"] == {"perm": "sensor.get", "has_perm": True}
    assert fake.calls[0]["data"]["oid"] == OID


def test_auth_whoami_permission_check_requires_explicit_oid(tmp_path: Path) -> None:
    client = make_client(tmp_path, FakeHTTP())

    with pytest.raises(ValidationError, match="explicit oid"):
        client.auth_whoami(check_perm="sensor.get")


def test_auth_status_does_not_expose_secrets(tmp_path: Path) -> None:
    client = make_client(tmp_path, FakeHTTP())

    result = client.auth_status(OID)

    assert result["ok"] is True
    assert_ax_envelope(result, "auth.status")
    assert result["data"]["jwt_managed_by_server"] is True
    assert result["data"]["configured"]["api_key"] is True
    assert "secret" not in json.dumps(result)
    assert "test-token" not in json.dumps(result)


def test_auth_status_reports_missing_credentials(tmp_path: Path) -> None:
    client = LimaCharlieAPI(api_key="", audit_path=tmp_path / "audit.jsonl", http_client=FakeHTTP())

    result = client.auth_status()

    assert result["ok"] is False
    assert_ax_envelope(result, "auth.status")
    assert result["error"]["class"] == "auth"
    assert result["error"]["code"] == "missing_credentials"


def test_auth_refresh_forces_new_jwt_without_returning_token(tmp_path: Path) -> None:
    fake = FakeHTTP()
    client = make_client(tmp_path, fake)

    first = client.auth_refresh(OID)
    second = client.auth_refresh(OID)

    assert first["ok"] is True
    assert second["ok"] is True
    assert first["operation"] == "auth.refresh"
    assert first["side_effects"][0]["type"] == "local_jwt_cache_refresh"
    assert "test-token" not in json.dumps(first)
    assert [call["url"] for call in fake.calls] == ["https://jwt.limacharlie.io", "https://jwt.limacharlie.io"]


def test_org_scoped_tools_require_uuid_oid(tmp_path: Path) -> None:
    client = make_client(tmp_path, FakeHTTP())

    with pytest.raises(ValidationError, match="oid"):
        client.list_sensors("not-an-oid")


def test_list_sensors_uses_api_params_and_bounds_output(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add(
        "GET",
        f"https://api.limacharlie.io/v1/sensors/{OID}",
        {"sensors": [{"sid": "one"}, {"sid": "two"}, {"sid": "three"}]},
    )
    client = make_client(tmp_path, fake)

    result = client.list_sensors(OID, selector="plat == windows", limit=2)

    assert result["ok"] is True
    assert_ax_envelope(result, "sensor.list")
    assert result["meta"]["truncated"] is True
    assert result["meta"]["summary"]["sensors_count"] == 2
    assert result["resource"] == {"type": "sensor_collection", "id": OID}
    assert [row["sid"] for row in result["data"]["sensors"]] == ["one", "two"]
    assert fake.calls[1]["params"] == {"limit": 2, "selector": "plat == windows"}


def test_get_sensor_uses_sensor_endpoint(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/{SID}", {"info": {"sid": SID}})
    client = make_client(tmp_path, fake)

    result = client.get_sensor(OID, SID)

    assert result["ok"] is True
    assert_ax_envelope(result, "sensor.get")
    assert result["resource"]["id"] == SID
    assert fake.calls[1]["url"] == f"https://api.limacharlie.io/v1/{SID}"


def test_detection_list_requires_explicit_time_window(tmp_path: Path) -> None:
    client = make_client(tmp_path, FakeHTTP())

    with pytest.raises(ValidationError, match="end"):
        client.list_detections(OID, start=200, end=100)


def test_detection_list_uses_insight_api(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add(
        "GET",
        f"https://api.limacharlie.io/v1/insight/{OID}/detections",
        {"detects": [{"detect_id": "det-1"}]},
    )
    client = make_client(tmp_path, fake)

    result = client.list_detections(OID, start=1_771_000_000, end=1_771_003_600)

    assert result["ok"] is True
    assert_ax_envelope(result, "detection.list")
    assert fake.calls[1]["params"] == {
        "start": 1_771_000_000,
        "end": 1_771_003_600,
        "cursor": "-",
        "is_compressed": "true",
        "limit": 100,
    }


def test_get_detection_uses_direct_detection_endpoint(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add(
        "GET",
        f"https://api.limacharlie.io/v1/insight/{OID}/detections/det-1",
        {"detect_id": "det-1"},
    )
    client = make_client(tmp_path, fake)

    result = client.get_detection(OID, "det-1")

    assert result["ok"] is True
    assert_ax_envelope(result, "detection.get")
    assert fake.calls[1]["url"].endswith("/detections/det-1")


def test_cases_use_cases_api_root(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", "https://cases.limacharlie.io/api/v1/cases", {"cases": [{"case_number": 42}]})
    client = make_client(tmp_path, fake)

    result = client.list_cases(OID, limit=25)

    assert result["ok"] is True
    assert_ax_envelope(result, "case.list")
    assert fake.calls[1]["url"] == "https://cases.limacharlie.io/api/v1/cases"
    assert fake.calls[1]["params"] == {"oids": OID, "page_size": 25}


def test_sensor_events_are_decoded_and_bounded(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add(
        "GET",
        f"https://api.limacharlie.io/v1/insight/{OID}/{SID}",
        {
            "events": compressed_json([{"event_type": "NEW_PROCESS"}, {"event_type": "NETWORK_CONNECTION"}]),
            "next_cursor": "cursor-2",
        },
    )
    client = make_client(tmp_path, fake)

    result = client.list_sensor_events(OID, SID, start=1_771_000_000, end=1_771_003_600, limit=1)

    assert result["ok"] is True
    assert_ax_envelope(result, "event.list")
    assert result["data"]["events"] == [{"event_type": "NEW_PROCESS"}]
    assert result["meta"]["truncated"] is True
    assert result["meta"]["summary"]["events_count"] == 1
    assert result["meta"]["summary"]["next_cursor"] == "cursor-2"
    assert fake.calls[1]["params"] == {
        "start": 1_771_000_000,
        "end": 1_771_003_600,
        "is_compressed": "true",
        "is_forward": "true",
        "cursor": "-",
        "limit": 1,
    }


def test_event_lookup_tools_use_insight_paths(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/insight/{OID}/{SID}/overview", {"overview": [1, 2]})
    fake.add("GET", f"https://api.limacharlie.io/v1/insight/{OID}/{SID}/atom-1", {"event": {"atom": "atom-1"}})
    fake.add(
        "GET",
        f"https://api.limacharlie.io/v1/insight/{OID}/{SID}/atom-1/children",
        {"events": compressed_json([{"atom": "child-1"}])},
    )
    fake.add("GET", f"https://api.limacharlie.io/v1/insight/event_count/{OID}/{SID}", {"total": 12})
    client = make_client(tmp_path, fake)

    assert client.get_sensor_event_overview(OID, SID, 1_771_000_000, 1_771_003_600)["operation"] == "event.overview"
    assert client.get_event(OID, SID, "atom-1")["data"]["event"]["atom"] == "atom-1"
    assert client.list_child_events(OID, SID, "atom-1")["data"]["events"][0]["atom"] == "child-1"
    assert client.get_event_retention(OID, SID, 1_771_000_000, 1_771_003_600)["data"]["total"] == 12


def test_ioc_search_uses_insight_objects_path(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/insight/{OID}/objects/domain", {"summary": {"example.com": 2}})
    client = make_client(tmp_path, fake)

    result = client.search_ioc(OID, "domain", "example.com", info="summary", wildcards=True, limit=50)

    assert result["ok"] is True
    assert_ax_envelope(result, "ioc.search")
    assert fake.calls[1]["params"] == {
        "name": "example.com",
        "info": "summary",
        "case_sensitive": "true",
        "with_wildcards": "true",
        "per_object": "true",
        "limit": 50,
    }


def test_artifact_and_job_tools_use_bounded_paths(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/insight/{OID}/artifacts", {"artifacts": [{"id": "a1"}]})
    fake.add("POST", f"https://api.limacharlie.io/v1/insight/{OID}/artifacts/originals/a1", {"export": "https://signed"})
    fake.add("GET", f"https://api.limacharlie.io/v1/job/{OID}", {"jobs": compressed_json({"job-1": {"id": "job-1"}})})
    fake.add("GET", f"https://api.limacharlie.io/v1/job/{OID}/job-1", {"id": "job-1"})
    client = make_client(tmp_path, fake)

    assert client.list_artifacts(OID, start=1_771_000_000, end=1_771_003_600)["operation"] == "artifact.list"
    assert client.get_artifact_url(OID, "a1")["data"]["export"] == "https://signed"
    assert client.list_jobs(OID, start=1_771_000_000, end=1_771_003_600)["data"]["jobs"]["job-1"]["id"] == "job-1"
    assert client.get_job(OID, "job-1")["resource"]["id"] == "job-1"


def test_wait_job_returns_terminal_state(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/job/{OID}/job-1", {"id": "job-1", "completed": True})
    client = make_client(tmp_path, fake)

    result = client.wait_job(OID, "job-1")

    assert result["ok"] is True
    assert_ax_envelope(result, "job.wait")
    assert result["state"] == {"current": "succeeded", "terminal": True}
    assert result["meta"]["attempts"] == 1
    assert result["meta"]["summary"]["job_state"] == "succeeded"


def test_artifact_list_requires_time_window_without_cursor(tmp_path: Path) -> None:
    client = make_client(tmp_path, FakeHTTP())

    with pytest.raises(ValidationError, match="start and end"):
        client.list_artifacts(OID)


def test_admin_inventory_tools_use_org_endpoints(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/orgs/{OID}", {"oid": OID, "name": "Test"})
    fake.add("GET", f"https://api.limacharlie.io/v1/usage/{OID}", {"sensors": 10})
    fake.add("GET", f"https://api.limacharlie.io/v1/errors/{OID}", {"errors": {}})
    fake.add("GET", f"https://api.limacharlie.io/v1/orgs/{OID}/users", {"users": ["a@example.com"]})
    fake.add("GET", f"https://api.limacharlie.io/v1/orgs/{OID}/users/permissions", {"user_permissions": {}})
    fake.add("GET", f"https://api.limacharlie.io/v1/orgs/{OID}/keys", {"api_keys": [{"name": "reader"}]})
    fake.add("GET", f"https://api.limacharlie.io/v1/installationkeys/{OID}", {"keys": [{"iid": "iid-1"}]})
    fake.add("GET", f"https://api.limacharlie.io/v1/installationkeys/{OID}/iid-1", {"iid": "iid-1"})
    fake.add("GET", f"https://api.limacharlie.io/v1/outputs/{OID}", {"outputs": [{"name": "out"}]})
    fake.add("GET", f"https://api.limacharlie.io/v1/orgs/{OID}/subscriptions", {"resources": [{"name": "ext"}]})
    client = make_client(tmp_path, fake)

    assert client.get_org_info(OID)["data"]["name"] == "Test"
    assert client.get_org_stats(OID)["operation"] == "org.stats"
    assert client.list_org_errors(OID)["operation"] == "org.errors"
    assert client.list_users(OID)["data"]["users"] == ["a@example.com"]
    assert client.list_user_permissions(OID)["operation"] == "user.permission.list"
    assert client.list_api_keys(OID)["data"]["api_keys"][0]["name"] == "reader"
    assert client.list_installation_keys(OID)["data"]["keys"][0]["iid"] == "iid-1"
    assert client.get_installation_key(OID, "iid-1")["data"]["iid"] == "iid-1"
    assert client.list_outputs(OID)["data"]["outputs"][0]["name"] == "out"
    assert client.list_extension_subscriptions(OID)["data"]["resources"][0]["name"] == "ext"


def test_available_extensions_use_minimal_oid(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", "https://api.limacharlie.io/v1/extension/definition", {"extensions": [{"name": "one"}]})
    client = make_client(tmp_path, fake)

    result = client.list_available_extensions(limit=10)

    assert result["ok"] is True
    assert_ax_envelope(result, "extension.list_available")
    assert fake.calls[0]["data"]["oid"] == "-"


def test_dr_rule_tools_use_hive_namespaces(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/hive/dr-general/{OID}", {"rule-1": {"data": "{}"}})
    fake.add("GET", f"https://api.limacharlie.io/v1/hive/dr-managed/{OID}/rule-1/data", {"data": {"detect": {}}})
    client = make_client(tmp_path, fake)

    listed = client.list_dr_rules(OID)
    fetched = client.get_dr_rule(OID, "rule-1", namespace="managed")

    assert listed["operation"] == "dr_rule.list"
    assert fetched["operation"] == "dr_rule.get"
    assert fake.calls[2]["url"].endswith("/hive/dr-managed/" + OID + "/rule-1/data")


def test_audit_log_is_written_without_credentials(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/sensors/{OID}", {"sensors": []})
    client = make_client(tmp_path, fake)

    client.list_sensors(OID)

    entry = json.loads((tmp_path / "audit.jsonl").read_text().splitlines()[0])
    assert entry["operation"] == "sensor.list"
    assert entry["oid"] == OID
    assert entry["method"] == "GET"
    assert "Authorization" not in json.dumps(entry)


def test_non_2xx_result_returns_error(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/sensors/{OID}", {"error": "missing permission"}, 403)
    client = make_client(tmp_path, fake)

    result = client.list_sensors(OID)

    assert result["ok"] is False
    assert_ax_envelope(result, "sensor.list")
    assert result["error"]["class"] == "policy"
    assert result["error"]["code"] == "forbidden"
    assert result["error"]["message"] == "missing permission"
    assert result["error"]["retryable"] is False
    assert result["side_effects"] == []
