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


def decode_gzdata(value: str) -> Any:
    return json.loads(gzip.decompress(base64.b64decode(value)).decode())


def decode_request_data(value: str) -> Any:
    return json.loads(base64.b64decode(value).decode())


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
    assert result["data"]["operations"]["audit.list"]["suite"] == "investigation"
    assert result["data"]["operations"]["yara_rule.list"]["suite"] == "content"
    assert result["data"]["operations"]["billing.status"]["suite"] == "administration"
    assert result["data"]["operations"]["replay.validate_rule"]["suite"] == "content"
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


def test_download_target_tools_are_local_metadata(tmp_path: Path) -> None:
    fake = FakeHTTP()
    client = make_client(tmp_path, fake)

    sensors = client.list_sensor_download_targets()
    adapters = client.list_adapter_download_targets()

    assert sensors["ok"] is True
    assert_ax_envelope(sensors, "download.sensor_targets.list")
    assert any(target["platform"] == "windows" and target["arch"] == "64" for target in sensors["data"]["targets"])
    assert adapters["ok"] is True
    assert_ax_envelope(adapters, "download.adapter_targets.list")
    assert any(target["platform"] == "linux" and target["arch"] == "arm64" for target in adapters["data"]["targets"])
    assert "downloads.limacharlie.io" in sensors["data"]["targets"][0]["url"]
    assert fake.calls == []


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


def test_list_online_sensors_uses_online_endpoint(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/online/{OID}", {"sensors": [{"sid": SID}], "online": 1})
    client = make_client(tmp_path, fake)

    result = client.list_online_sensors(OID, limit=1)

    assert result["ok"] is True
    assert_ax_envelope(result, "sensor.online.list")
    assert result["data"]["sensors"] == [{"sid": SID}]
    assert result["resource"] == {"type": "online_sensor_collection", "id": OID}
    assert fake.calls[1]["url"] == f"https://api.limacharlie.io/v1/online/{OID}"


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


def test_insight_batch_status_and_object_info_use_expected_paths(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("POST", f"https://api.limacharlie.io/v1/insight/{OID}/objects", {"summary": {"example.com": 2}})
    fake.add("GET", f"https://api.limacharlie.io/v1/insight/{OID}", {"insight_bucket": "bucket-1"})
    fake.add("GET", f"https://api.limacharlie.io/v1/insight/{OID}/objects/ip", {"locations": [{"sid": SID}]})
    client = make_client(tmp_path, fake)

    batch = client.batch_search_iocs(OID, {"domain": ["example.com"]}, info="locations", limit=25)
    status = client.get_insight_status(OID)
    obj = client.get_object_information(OID, "ip", "192.0.2.10", info="locations", limit=10)

    assert batch["ok"] is True
    assert_ax_envelope(batch, "ioc.batch_search")
    assert json.loads(fake.calls[1]["params"]["objects"]) == {"domain": ["example.com"]}
    assert fake.calls[1]["params"]["limit"] == 25
    assert status["state"]["enabled"] is True
    assert status["operation"] == "insight.status"
    assert obj["operation"] == "ioc.object_info"
    assert fake.calls[3]["params"]["name"] == "192.0.2.10"


def test_validate_search_query_discovers_search_url_and_posts_json(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/orgs/{OID}/url", {"search": "region.replay-search.limacharlie.io"})
    fake.add("POST", "https://region.replay-search.limacharlie.io/v1/search/validate", {"valid": True, "cost": 7})
    client = make_client(tmp_path, fake)

    result = client.validate_search_query(
        OID,
        "event.FILE_PATH ends with .exe",
        start=1_771_000_000,
        end=1_771_003_600,
        stream="event",
    )

    assert result["ok"] is True
    assert_ax_envelope(result, "search.validate")
    assert fake.calls[0]["url"] == f"https://api.limacharlie.io/v1/orgs/{OID}/url"
    assert "Authorization" not in fake.calls[0]["headers"]
    assert fake.calls[1]["url"] == "https://jwt.limacharlie.io"
    assert fake.calls[2]["url"] == "https://region.replay-search.limacharlie.io/v1/search/validate"
    assert fake.calls[2]["json"] == {
        "oid": OID,
        "query": "event.FILE_PATH ends with .exe",
        "startTime": "1771000000",
        "endTime": "1771003600",
        "stream": "event",
    }


def test_estimate_search_query_uses_explicit_window(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/orgs/{OID}/url", {"search_api": "https://search.limacharlie.io"})
    fake.add("POST", "https://search.limacharlie.io/v1/search/validate", {"valid": True, "estimate": {"cost": 3}})
    client = make_client(tmp_path, fake)

    result = client.estimate_search_query(OID, "event/COMMAND_LINE contains powershell", 1_771_000_000, 1_771_003_600)

    assert result["ok"] is True
    assert_ax_envelope(result, "search.estimate")
    assert result["warnings"]
    assert fake.calls[2]["url"] == "https://search.limacharlie.io/v1/search/validate"
    assert fake.calls[2]["json"]["startTime"] == "1771000000"


def test_execute_search_query_starts_paginated_job_with_state(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/orgs/{OID}/url", {"search": "https://search.limacharlie.io/v1"})
    fake.add("POST", "https://search.limacharlie.io/v1/search", {"queryId": "query-1"})
    client = make_client(tmp_path, fake)

    result = client.execute_search_query(OID, "event.FILE_PATH ends with .exe", 1_771_000_000, 1_771_003_600)

    assert result["ok"] is True
    assert_ax_envelope(result, "search.execute")
    assert result["state"]["current"] == "running"
    assert result["state"]["query_id"] == "query-1"
    assert result["side_effects"][0]["type"] == "search_query_started"
    assert fake.calls[2]["json"]["paginated"] is True


def test_poll_search_query_returns_checkpoint_state_and_bounds_rows(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/orgs/{OID}/url", {"search": "https://search.limacharlie.io"})
    fake.add(
        "GET",
        "https://search.limacharlie.io/v1/search/query-1",
        {
            "completed": True,
            "results": [
                {
                    "type": "events",
                    "rows": [{"event": "one"}, {"event": "two"}, {"event": "three"}],
                    "nextToken": "token-2",
                }
            ],
        },
    )
    client = make_client(tmp_path, fake)

    result = client.poll_search_query(OID, "query-1", limit=2)

    assert result["ok"] is True
    assert_ax_envelope(result, "search.poll")
    assert result["state"]["current"] == "ready_for_next_page"
    assert result["state"]["checkpoint"]["next_token"] == "token-2"
    assert result["state"]["checkpoint"]["rows_returned"] == 2
    assert result["meta"]["truncated"] is True
    assert [row["event"] for row in result["data"]["results"][0]["rows"]] == ["one", "two"]


def test_cancel_search_query_calls_delete_and_reports_terminal_state(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/orgs/{OID}/url", {"search": "https://search.limacharlie.io"})
    fake.add("DELETE", "https://search.limacharlie.io/v1/search/query-1", {"ok": True})
    client = make_client(tmp_path, fake)

    result = client.cancel_search_query(OID, "query-1")

    assert result["ok"] is True
    assert_ax_envelope(result, "search.cancel")
    assert result["state"] == {"current": "cancelled", "terminal": True, "query_id": "query-1"}
    assert result["side_effects"][0]["type"] == "search_query_cancelled"


def test_replay_tools_use_replay_url_and_force_dry_run(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/orgs/{OID}/url", {"replay": "replay-region.limacharlie.io"})
    fake.add("POST", "https://replay-region.limacharlie.io/", {"results": []})
    client = make_client(tmp_path, fake)

    rule = {"detect": {"event": "NEW_PROCESS"}, "respond": []}
    validated = client.validate_replay_rule(OID, rule)
    scanned = client.replay_scan_events(OID, [{"event": {"FILE_PATH": "cmd.exe"}, "routing": {}}], rule_content=rule)
    dry = client.replay_dry_run(OID, 1_771_000_000, 1_771_003_600, rule_name="rule-1", limit_events=50)

    assert validated["operation"] == "replay.validate_rule"
    assert scanned["operation"] == "replay.scan_events"
    assert dry["operation"] == "replay.run_dry"
    assert fake.calls[2]["json"]["is_dry_run"] is True
    assert fake.calls[4]["json"]["event_source"]["events"][0]["event"]["FILE_PATH"] == "cmd.exe"
    assert fake.calls[6]["json"]["rule_source"]["rule_name"] == "rule-1"
    assert fake.calls[6]["json"]["limit_event"] == 50
    assert all(call["url"] != "https://jwt.limacharlie.io" for call in (fake.calls[3], fake.calls[5]))


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


def test_payload_and_arl_read_tools_use_expected_paths(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/payload/{OID}", {"payloads": [{"name": "p1"}]})
    fake.add("GET", f"https://api.limacharlie.io/v1/payload/{OID}/p1", {"get_url": "https://signed"})
    fake.add("GET", f"https://api.limacharlie.io/v1/arl/{OID}", {"data": [{"id": "resolved"}]})
    client = make_client(tmp_path, fake)

    payloads = client.list_payloads(OID)
    payload = client.get_payload_download_url(OID, "p1")
    arl = client.get_arl(OID, "lc://example/resource", limit=1)

    assert payloads["operation"] == "payload.list"
    assert payloads["data"]["payloads"][0]["name"] == "p1"
    assert payload["operation"] == "payload.get_url"
    assert payload["data"]["get_url"] == "https://signed"
    assert arl["operation"] == "arl.get"
    assert fake.calls[3]["params"] == {"arl": "lc://example/resource"}


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


def test_audit_logs_are_decoded_and_bounded(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add(
        "GET",
        f"https://api.limacharlie.io/v1/insight/{OID}/audit",
        {"events": compressed_json([{"event_type": "audit"}, {"event_type": "audit2"}]), "next_cursor": "c2"},
    )
    client = make_client(tmp_path, fake)

    result = client.list_audit_logs(OID, start=1_771_000_000, end=1_771_003_600, limit=1)

    assert result["ok"] is True
    assert_ax_envelope(result, "audit.list")
    assert result["data"]["events"] == [{"event_type": "audit"}]
    assert result["meta"]["truncated"] is True
    assert fake.calls[1]["params"] == {
        "start": 1_771_000_000,
        "end": 1_771_003_600,
        "cursor": "-",
        "is_compressed": "true",
        "limit": 1,
    }


def test_tag_and_hostname_read_tools_use_expected_paths(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/tags/{OID}", {"tags": ["prod", "windows"]})
    fake.add("GET", f"https://api.limacharlie.io/v1/tags/{OID}/prod", {"sensors": [{"sid": SID}]})
    fake.add("GET", f"https://api.limacharlie.io/v1/hostnames/{OID}", {"sensors": [{"sid": SID}]})
    client = make_client(tmp_path, fake)

    assert client.list_tags(OID)["data"]["tags"] == ["prod", "windows"]
    assert client.find_sensors_by_tag(OID, "prod")["operation"] == "tag.sensor_search"
    assert client.find_sensors_by_hostname(OID, "host")["operation"] == "sensor.hostname_search"
    assert fake.calls[3]["params"] == {"hostname": "host"}


def test_preview_add_sensor_tag_does_not_call_limacharlie(tmp_path: Path) -> None:
    fake = FakeHTTP()
    client = make_client(tmp_path, fake)

    result = client.preview_add_sensor_tag(OID, SID, "incident-response", ttl_seconds=3600)

    assert result["ok"] is True
    assert_ax_envelope(result, "sensor.tag.add.preview")
    assert result["state"]["current"] == "pending_confirmation"
    assert result["side_effects"] == []
    assert result["data"]["http_method"] == "POST"
    assert result["data"]["endpoint"] == f"https://api.limacharlie.io/v1/{SID}/tags"
    assert result["data"]["expected_side_effects"][0]["type"] == "sensor_tag_added"
    assert result["data"]["confirmation_token"].startswith("mut_")
    assert fake.calls == []


def test_confirm_add_sensor_tag_executes_exact_preview_once(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("POST", f"https://api.limacharlie.io/v1/{SID}/tags", {"ok": True})
    client = make_client(tmp_path, fake)
    preview = client.preview_add_sensor_tag(OID, SID, "incident-response", ttl_seconds=3600)
    token = preview["data"]["confirmation_token"]

    result = client.confirm_mutation(token)

    assert result["ok"] is True
    assert_ax_envelope(result, "mutation.confirm")
    assert result["data"]["confirmed_operation"] == "sensor.tag.add"
    assert result["side_effects"] == [
        {
            "type": "sensor_tag_added",
            "resource": {"type": "sensor", "id": SID},
            "tag": "incident-response",
            "ttl_seconds": 3600,
        }
    ]
    assert fake.calls[0]["url"] == "https://jwt.limacharlie.io"
    assert fake.calls[0]["data"]["oid"] == OID
    assert fake.calls[1]["method"] == "POST"
    assert fake.calls[1]["url"] == f"https://api.limacharlie.io/v1/{SID}/tags"
    assert fake.calls[1]["params"] == {"tags": "incident-response", "ttl": 3600}

    second = client.confirm_mutation(token)
    assert second["ok"] is False
    assert second["error"]["code"] == "mutation_preview_not_found"
    assert len(fake.calls) == 2


def test_preview_remove_sensor_tag_can_be_cancelled_without_http(tmp_path: Path) -> None:
    fake = FakeHTTP()
    client = make_client(tmp_path, fake)
    preview = client.preview_remove_sensor_tag(OID, SID, "old-tag")
    token = preview["data"]["confirmation_token"]

    pending = client.list_pending_mutations()
    cancelled = client.cancel_mutation(token)
    confirmed = client.confirm_mutation(token)

    assert pending["data"]["previews"][0]["operation"] == "sensor.tag.remove"
    assert cancelled["ok"] is True
    assert cancelled["side_effects"][0]["type"] == "local_preview_deleted"
    assert confirmed["ok"] is False
    assert fake.calls == []


def test_confirm_remove_sensor_tag_uses_delete_endpoint(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("DELETE", f"https://api.limacharlie.io/v1/{SID}/tags", {"ok": True})
    client = make_client(tmp_path, fake)
    preview = client.preview_remove_sensor_tag(OID, SID, "old-tag")

    result = client.confirm_mutation(preview["data"]["confirmation_token"])

    assert result["ok"] is True
    assert result["data"]["confirmed_operation"] == "sensor.tag.remove"
    assert result["side_effects"][0]["type"] == "sensor_tag_removed"
    assert fake.calls[1]["method"] == "DELETE"
    assert fake.calls[1]["params"] == {"tag": "old-tag"}


def test_preview_sensor_task_confirms_exact_task_params(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("POST", f"https://api.limacharlie.io/v1/{SID}", {"queued": True})
    client = make_client(tmp_path, fake)

    preview = client.preview_sensor_task(OID, SID, ["dir C:\\"], investigation_id="inv-1")
    assert preview["ok"] is True
    assert preview["operation"] == "sensor.task.preview"
    assert preview["side_effects"] == []
    assert fake.calls == []

    confirmed = client.confirm_mutation(preview["data"]["confirmation_token"])

    assert confirmed["ok"] is True
    assert confirmed["data"]["confirmed_operation"] == "sensor.task"
    assert confirmed["side_effects"][0]["type"] == "sensor_task_queued"
    assert fake.calls[1]["method"] == "POST"
    assert fake.calls[1]["url"] == f"https://api.limacharlie.io/v1/{SID}"
    assert fake.calls[1]["params"] == {"tasks": ["dir C:\\"], "investigation_id": "inv-1"}


def test_preview_sensor_state_and_job_delete_endpoints(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("POST", f"https://api.limacharlie.io/v1/{SID}/isolation", {"ok": True})
    fake.add("DELETE", f"https://api.limacharlie.io/v1/{SID}/seal", {"ok": True})
    fake.add("DELETE", f"https://api.limacharlie.io/v1/{SID}", {"ok": True})
    fake.add("DELETE", f"https://api.limacharlie.io/v1/job/{OID}/job-1", {"ok": True})
    client = make_client(tmp_path, fake)

    isolate = client.preview_isolate_sensor(OID, SID)
    unseal = client.preview_unseal_sensor(OID, SID)
    delete_sensor = client.preview_delete_sensor(OID, SID)
    delete_job = client.preview_delete_job(OID, "job-1")

    confirmed_isolate = client.confirm_mutation(isolate["data"]["confirmation_token"])
    confirmed_unseal = client.confirm_mutation(unseal["data"]["confirmation_token"])
    confirmed_delete_sensor = client.confirm_mutation(delete_sensor["data"]["confirmation_token"])
    confirmed_delete_job = client.confirm_mutation(delete_job["data"]["confirmation_token"])

    assert confirmed_isolate["side_effects"][0]["type"] == "sensor_isolated"
    assert confirmed_unseal["side_effects"][0]["type"] == "sensor_unsealed"
    assert confirmed_delete_sensor["side_effects"][0]["type"] == "sensor_deleted"
    assert confirmed_delete_job["side_effects"][0]["type"] == "job_deleted"
    assert [call["url"] for call in fake.calls[1:]] == [
        f"https://api.limacharlie.io/v1/{SID}/isolation",
        f"https://api.limacharlie.io/v1/{SID}/seal",
        f"https://api.limacharlie.io/v1/{SID}",
        f"https://api.limacharlie.io/v1/job/{OID}/job-1",
    ]


def test_schema_ontology_and_mitre_tools_use_expected_paths(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/orgs/{OID}/schema", {"schemas": [{"name": "NEW_PROCESS"}]})
    fake.add("GET", f"https://api.limacharlie.io/v1/orgs/{OID}/schema/NEW_PROCESS", {"name": "NEW_PROCESS"})
    fake.add("GET", "https://api.limacharlie.io/v1/ontology", {"events": [{"name": "NEW_PROCESS"}]})
    fake.add("GET", "https://api.limacharlie.io/v1/events", {"events": ["NEW_PROCESS"]})
    fake.add("GET", f"https://api.limacharlie.io/v1/mitre/{OID}", {"coverage": []})
    client = make_client(tmp_path, fake)

    assert client.list_schemas(OID)["operation"] == "schema.list"
    assert client.get_schema(OID, "NEW_PROCESS")["data"]["name"] == "NEW_PROCESS"
    assert client.get_ontology()["operation"] == "ontology.get"
    assert client.list_event_types()["data"]["events"] == ["NEW_PROCESS"]
    assert client.get_mitre_report(OID)["operation"] == "mitre.get"


def test_extension_artifact_and_ingestion_read_tools_use_expected_paths(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", "https://api.limacharlie.io/v1/extension/definition/ext-vuln", {"name": "ext-vuln"})
    fake.add("GET", "https://api.limacharlie.io/v1/extension/schema/ext-vuln", {"schema": {}})
    fake.add("GET", f"https://api.limacharlie.io/v1/insight/{OID}/artifacts/rules", {"rules": [{"name": "collect"}]})
    fake.add("GET", f"https://api.limacharlie.io/v1/insight/{OID}/ingestion_keys", {"keys": [{"name": "log"}]})
    client = make_client(tmp_path, fake)

    assert client.get_extension("ext-vuln")["data"]["name"] == "ext-vuln"
    assert client.get_extension_schema(OID, "ext-vuln")["operation"] == "extension.schema.get"
    assert fake.calls[3]["params"] == {"oid": OID}
    assert client.list_artifact_rules(OID)["data"]["rules"][0]["name"] == "collect"
    assert client.list_ingestion_keys(OID)["data"]["keys"][0]["name"] == "log"


def test_vulnerability_cve_list_uses_extension_request_and_unwraps_data(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add(
        "POST",
        "https://api.limacharlie.io/v1/extension/request/ext-vulnerability-reporting",
        {"data": {"results": [{"cve": "CVE-2024-12345"}], "next_cursor": "c2"}},
    )
    client = make_client(tmp_path, fake)

    result = client.list_vulnerability_cves(
        OID,
        limit=1,
        sort_by="lc_risk",
        sort_asc=False,
        filters={"severity": ["critical"]},
        search={"field": "cve", "op": "contains", "value": "2024"},
        include_enrichment=True,
    )

    assert result["ok"] is True
    assert_ax_envelope(result, "vulnerability.cve.list")
    assert result["data"]["results"] == [{"cve": "CVE-2024-12345"}]
    assert result["meta"]["summary"]["results_count"] == 1
    params = fake.calls[1]["params"]
    assert params["oid"] == OID
    assert params["action"] == "query_cves"
    assert decode_gzdata(params["gzdata"]) == {
        "limit": 1,
        "sort_by": "lc_risk",
        "sort_asc": False,
        "filters": {"severity": ["critical"]},
        "search": {"field": "cve", "op": "contains", "value": "2024"},
        "include_enrichment": True,
    }


def test_vulnerability_drilldown_tools_use_expected_actions(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("POST", "https://api.limacharlie.io/v1/extension/request/ext-vulnerability-reporting", {"data": {"ok": True}})
    client = make_client(tmp_path, fake)

    assert client.get_vulnerability_cve(OID, "cve-2024-12345")["operation"] == "vulnerability.cve.get"
    assert client.list_vulnerability_cve_hosts(OID, "CVE-2024-12345", normalized_package_name="openssl")["operation"] == "vulnerability.cve.hosts"
    assert client.list_vulnerability_cve_packages(OID, "CVE-2024-12345")["operation"] == "vulnerability.cve.packages"
    assert client.list_vulnerability_endpoints(OID, include_tags=True)["operation"] == "vulnerability.endpoint.list"
    assert client.list_vulnerability_host_packages(OID, SID, rollup_subpackages=True)["operation"] == "vulnerability.host.packages"
    assert client.get_vulnerability_dashboard(OID)["operation"] == "vulnerability.dashboard"

    actions = [call["params"].get("action") for call in fake.calls if call["url"].endswith("/extension/request/ext-vulnerability-reporting")]
    assert actions == [
        "query_cve",
        "query_cve_vuln_hosts",
        "query_cve_vuln_packages",
        "query_endpoints",
        "query_host_vuln_packages",
        "query_dashboard",
    ]
    cve_detail = decode_gzdata(fake.calls[1]["params"]["gzdata"])
    assert cve_detail == {"cve_id": "CVE-2024-12345"}
    cve_hosts = decode_gzdata(fake.calls[2]["params"]["gzdata"])
    assert cve_hosts["normalized_package_name"] == "openssl"
    host_packages = decode_gzdata(fake.calls[5]["params"]["gzdata"])
    assert host_packages["sid"] == SID
    assert host_packages["rollup_subpackages"] is True


def test_vulnerability_history_and_resolution_read_tools_use_expected_actions(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("POST", "https://api.limacharlie.io/v1/extension/request/ext-vulnerability-reporting", {"data": {"snapshots": []}})
    client = make_client(tmp_path, fake)

    resolutions = client.list_vulnerability_resolutions(OID, scope="host", resolutions=["mitigated"], limit=25)
    snapshots = client.list_vulnerability_snapshots(OID, days=30, severities=["critical", "high"])
    epss = client.get_vulnerability_epss_history(OID, "CVE-2024-12345", days=90)

    assert resolutions["operation"] == "vulnerability.resolution.list"
    assert snapshots["operation"] == "vulnerability.snapshot.list"
    assert epss["operation"] == "vulnerability.epss_history"
    actions = [call["params"].get("action") for call in fake.calls if call["url"].endswith("/extension/request/ext-vulnerability-reporting")]
    assert actions == ["list_finding_resolutions", "query_daily_snapshots", "query_epss_history"]
    assert decode_gzdata(fake.calls[1]["params"]["gzdata"]) == {
        "limit": 25,
        "scope": "host",
        "resolutions": ["mitigated"],
    }
    assert decode_gzdata(fake.calls[2]["params"]["gzdata"]) == {"days": 30, "severities": ["critical", "high"]}
    assert decode_gzdata(fake.calls[3]["params"]["gzdata"]) == {"cve": "CVE-2024-12345", "days": 90}


def test_vulnerability_tools_validate_cve_ids(tmp_path: Path) -> None:
    client = make_client(tmp_path, FakeHTTP())

    with pytest.raises(ValidationError, match="CVE"):
        client.get_vulnerability_cve(OID, "not-a-cve")


def test_fp_yara_and_logging_read_tools_use_expected_paths(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/hive/fp/{OID}", {"fp-1": {"data": "{}"}})
    fake.add("GET", f"https://api.limacharlie.io/v1/hive/fp/{OID}/fp-1/data", {"data": {"detect": {}}})
    fake.add("POST", f"https://api.limacharlie.io/v1/service/{OID}/yara", {"rules": {"r1": {}}})
    fake.add("POST", f"https://api.limacharlie.io/v1/service/{OID}/yara", {"sources": ["s1"]})
    fake.add("POST", f"https://api.limacharlie.io/v1/service/{OID}/yara", {"source": "rule x { condition: true }"})
    fake.add("POST", f"https://api.limacharlie.io/v1/service/{OID}/logging", {"rules": {"log1": {}}})
    client = make_client(tmp_path, fake)

    assert client.list_fp_rules(OID)["operation"] == "fp_rule.list"
    assert client.get_fp_rule(OID, "fp-1")["operation"] == "fp_rule.get"
    assert client.list_yara_rules(OID)["operation"] == "yara_rule.list"
    assert client.list_yara_sources(OID)["operation"] == "yara_source.list"
    assert client.get_yara_source(OID, "s1")["operation"] == "yara_source.get"
    assert client.list_logging_rules(OID)["operation"] == "logging_rule.list"
    encoded = fake.calls[3]["params"]["request_data"]
    decoded = json.loads(base64.b64decode(encoded).decode())
    assert decoded == {"action": "list_rules"}


def test_integrity_and_usp_tools_use_expected_paths(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("POST", f"https://api.limacharlie.io/v1/service/{OID}/integrity", {"rule-1": {"patterns": ["/bin/*"]}})
    fake.add("POST", f"https://api.limacharlie.io/v1/usp/validate/{OID}", {"valid": True})
    client = make_client(tmp_path, fake)

    listed = client.list_integrity_rules(OID)
    fetched = client.get_integrity_rule(OID, "rule-1")
    validation = client.validate_usp_mapping(OID, "json", mapping={"event": "NEW_PROCESS"}, json_input={"x": 1})

    assert listed["operation"] == "integrity_rule.list"
    assert fetched["operation"] == "integrity_rule.get"
    assert fetched["data"]["patterns"] == ["/bin/*"]
    assert decode_request_data(fake.calls[1]["params"]["request_data"]) == {"action": "list_rules"}
    assert validation["ok"] is True
    assert validation["operation"] == "usp.validate"
    assert fake.calls[3]["json"]["json_input"] == [{"x": 1}]


def test_artifact_rule_previews_confirm_exact_requests(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("POST", f"https://api.limacharlie.io/v1/insight/{OID}/artifacts/rules", {"ok": True})
    fake.add("DELETE", f"https://api.limacharlie.io/v1/insight/{OID}/artifacts/rules", {"ok": True})
    client = make_client(tmp_path, fake)

    set_preview = client.preview_set_artifact_rule(
        OID,
        "collect-logs",
        platforms=["windows"],
        patterns=["C:\\Windows\\Temp\\*.log"],
        is_delete_after=True,
        retention_days=14,
        tags=["incident"],
    )
    delete_preview = client.preview_delete_artifact_rule(OID, "collect-logs")

    assert set_preview["ok"] is True
    assert_ax_envelope(set_preview, "artifact_rule.set.preview")
    assert delete_preview["ok"] is True
    assert fake.calls == []

    set_confirmed = client.confirm_mutation(set_preview["data"]["confirmation_token"])
    delete_confirmed = client.confirm_mutation(delete_preview["data"]["confirmation_token"])

    assert set_confirmed["ok"] is True
    assert set_confirmed["data"]["confirmed_operation"] == "artifact_rule.set"
    assert set_confirmed["side_effects"][0]["type"] == "artifact_rule_set"
    assert fake.calls[1]["method"] == "POST"
    assert fake.calls[1]["json"] == {
        "name": "collect-logs",
        "platforms": ["windows"],
        "patterns": ["C:\\Windows\\Temp\\*.log"],
        "is_delete_after": True,
        "days_retention": 14,
        "tags": ["incident"],
    }
    assert delete_confirmed["ok"] is True
    assert delete_confirmed["data"]["confirmed_operation"] == "artifact_rule.delete"
    assert fake.calls[2]["method"] == "DELETE"
    assert fake.calls[2]["params"] == {"name": "collect-logs"}


def test_service_rule_previews_confirm_encoded_request_data(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("POST", f"https://api.limacharlie.io/v1/service/{OID}/logging", {"ok": True})
    fake.add("POST", f"https://api.limacharlie.io/v1/service/{OID}/integrity", {"ok": True})
    client = make_client(tmp_path, fake)

    logging_preview = client.preview_set_logging_rule(
        OID,
        "retain-processes",
        patterns=["event/NEW_PROCESS"],
        tags=["windows"],
        platforms=["windows"],
        retention_days=30,
        delete_after=True,
    )
    integrity_preview = client.preview_delete_integrity_rule(OID, "watch-bin")

    assert logging_preview["ok"] is True
    assert_ax_envelope(logging_preview, "logging_rule.set.preview")
    assert integrity_preview["ok"] is True
    assert fake.calls == []

    logging_confirmed = client.confirm_mutation(logging_preview["data"]["confirmation_token"])
    integrity_confirmed = client.confirm_mutation(integrity_preview["data"]["confirmation_token"])

    assert logging_confirmed["ok"] is True
    assert logging_confirmed["data"]["confirmed_operation"] == "logging_rule.set"
    assert fake.calls[1]["url"] == f"https://api.limacharlie.io/v1/service/{OID}/logging"
    assert fake.calls[1]["params"]["is_async"] is False
    assert decode_request_data(fake.calls[1]["params"]["request_data"]) == {
        "action": "add_rule",
        "name": "retain-processes",
        "patterns": ["event/NEW_PROCESS"],
        "tags": ["windows"],
        "platforms": ["windows"],
        "days_retention": "30",
        "is_delete_after": "true",
    }
    assert integrity_confirmed["ok"] is True
    assert integrity_confirmed["data"]["confirmed_operation"] == "integrity_rule.delete"
    assert fake.calls[2]["url"] == f"https://api.limacharlie.io/v1/service/{OID}/integrity"
    assert decode_request_data(fake.calls[2]["params"]["request_data"]) == {
        "action": "remove_rule",
        "name": "watch-bin",
    }


def test_hive_rule_previews_confirm_encoded_params(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("POST", f"https://api.limacharlie.io/v1/hive/dr-managed/{OID}/rule-1/data", {"ok": True})
    fake.add("DELETE", f"https://api.limacharlie.io/v1/hive/fp/{OID}/fp-1", {"ok": True})
    client = make_client(tmp_path, fake)

    dr_preview = client.preview_set_dr_rule(
        OID,
        "rule-1",
        data={"detect": {"event": "NEW_PROCESS"}, "respond": []},
        namespace="managed",
        enabled=True,
        tags=["prod"],
        comment="created by test",
        expiry=1_771_003_600,
        etag="etag-1",
    )
    fp_preview = client.preview_delete_fp_rule(OID, "fp-1")

    assert dr_preview["ok"] is True
    assert_ax_envelope(dr_preview, "dr_rule.set.preview")
    assert fp_preview["ok"] is True
    assert fake.calls == []

    dr_confirmed = client.confirm_mutation(dr_preview["data"]["confirmation_token"])
    fp_confirmed = client.confirm_mutation(fp_preview["data"]["confirmation_token"])

    assert dr_confirmed["ok"] is True
    assert dr_confirmed["data"]["confirmed_operation"] == "dr_rule.set"
    assert fake.calls[1]["method"] == "POST"
    assert json.loads(fake.calls[1]["params"]["data"]) == {"detect": {"event": "NEW_PROCESS"}, "respond": []}
    assert json.loads(fake.calls[1]["params"]["usr_mtd"]) == {
        "enabled": True,
        "tags": ["prod"],
        "comment": "created by test",
        "expiry": 1_771_003_600,
    }
    assert fake.calls[1]["params"]["etag"] == "etag-1"
    assert fp_confirmed["ok"] is True
    assert fp_confirmed["data"]["confirmed_operation"] == "fp_rule.delete"
    assert fake.calls[2]["method"] == "DELETE"
    assert fake.calls[2]["url"] == f"https://api.limacharlie.io/v1/hive/fp/{OID}/fp-1"


def test_yara_previews_confirm_service_requests(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("POST", f"https://api.limacharlie.io/v1/service/{OID}/yara", {"ok": True})
    client = make_client(tmp_path, fake)

    scan_preview = client.preview_yara_scan(OID, SID, "rule test { condition: true }", timeout_seconds=120)
    rule_preview = client.preview_set_yara_rule(OID, "rule-pack", sources=["source-1"], tags=["prod"], platforms=["linux"])
    source_preview = client.preview_set_yara_source(OID, "source-1", "rule x { condition: true }")
    delete_source_preview = client.preview_delete_yara_source(OID, "source-1")

    assert scan_preview["ok"] is True
    assert_ax_envelope(scan_preview, "yara.scan.preview")
    assert fake.calls == []

    scan_confirmed = client.confirm_mutation(scan_preview["data"]["confirmation_token"])
    rule_confirmed = client.confirm_mutation(rule_preview["data"]["confirmation_token"])
    source_confirmed = client.confirm_mutation(source_preview["data"]["confirmation_token"])
    delete_source_confirmed = client.confirm_mutation(delete_source_preview["data"]["confirmation_token"])

    assert scan_confirmed["data"]["confirmed_operation"] == "yara.scan"
    assert decode_request_data(fake.calls[1]["params"]["request_data"]) == {
        "action": "scan",
        "sid": SID,
        "rule": "rule test { condition: true }",
        "timeout": "120",
    }
    assert rule_confirmed["data"]["confirmed_operation"] == "yara_rule.set"
    rule_request = decode_request_data(fake.calls[2]["params"]["request_data"])
    assert rule_request["action"] == "add_rule"
    assert rule_request["name"] == "rule-pack"
    assert json.loads(rule_request["sources"]) == ["source-1"]
    assert json.loads(rule_request["tags"]) == ["prod"]
    assert json.loads(rule_request["platforms"]) == ["linux"]
    assert source_confirmed["data"]["confirmed_operation"] == "yara_source.set"
    assert decode_request_data(fake.calls[3]["params"]["request_data"]) == {
        "action": "add_source",
        "name": "source-1",
        "source": "rule x { condition: true }",
    }
    assert delete_source_confirmed["data"]["confirmed_operation"] == "yara_source.delete"
    assert decode_request_data(fake.calls[4]["params"]["request_data"]) == {
        "action": "remove_source",
        "name": "source-1",
    }


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


def test_org_user_and_api_key_previews_confirm_exact_requests(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("POST", f"https://api.limacharlie.io/v1/orgs/{OID}/quota", {"ok": True})
    fake.add("POST", f"https://api.limacharlie.io/v1/orgs/{OID}/name", {"ok": True})
    fake.add("POST", f"https://api.limacharlie.io/v1/orgs/{OID}/users", {"ok": True})
    fake.add("PUT", f"https://api.limacharlie.io/v1/orgs/{OID}/users/role", {"ok": True})
    fake.add("POST", f"https://api.limacharlie.io/v1/orgs/{OID}/keys", {"key": "one-time"})
    fake.add("DELETE", f"https://api.limacharlie.io/v1/orgs/{OID}/keys", {"ok": True})
    client = make_client(tmp_path, fake)

    quota = client.preview_set_org_quota(OID, 250)
    rename = client.preview_rename_org(OID, "Prod Org")
    invite = client.preview_invite_user(OID, "analyst@example.com")
    role = client.preview_set_user_role(OID, "analyst@example.com", "Viewer")
    create_key = client.preview_create_api_key(OID, "reader", ["sensor.get", "dr.get"], ip_range="10.0.0.0/8")
    delete_key = client.preview_delete_api_key(OID, "hash-1")

    assert quota["ok"] is True
    assert_ax_envelope(quota, "org.quota.set.preview")
    assert fake.calls == []

    confirmed = [
        client.confirm_mutation(quota["data"]["confirmation_token"]),
        client.confirm_mutation(rename["data"]["confirmation_token"]),
        client.confirm_mutation(invite["data"]["confirmation_token"]),
        client.confirm_mutation(role["data"]["confirmation_token"]),
        client.confirm_mutation(create_key["data"]["confirmation_token"]),
        client.confirm_mutation(delete_key["data"]["confirmation_token"]),
    ]

    assert [item["data"]["confirmed_operation"] for item in confirmed] == [
        "org.quota.set",
        "org.rename",
        "user.invite",
        "user.role.set",
        "api_key.create",
        "api_key.delete",
    ]
    assert fake.calls[1]["params"] == {"quota": 250}
    assert fake.calls[2]["params"] == {"name": "Prod Org"}
    assert fake.calls[3]["params"] == {"email": "analyst@example.com"}
    assert fake.calls[4]["json"] == {"email": "analyst@example.com", "role": "Viewer"}
    assert fake.calls[5]["params"] == {
        "key_name": "reader",
        "perms": "sensor.get,dr.get",
        "allowed_ip_range": "10.0.0.0/8",
    }
    assert fake.calls[6]["params"] == {"key_hash": "hash-1"}


def test_group_previews_confirm_exact_requests(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("POST", "https://api.limacharlie.io/v1/groups", {"id": "gid-1"})
    fake.add("DELETE", "https://api.limacharlie.io/v1/groups/gid-1", {"ok": True})
    fake.add("POST", "https://api.limacharlie.io/v1/groups/gid-1/users", {"ok": True})
    fake.add("DELETE", "https://api.limacharlie.io/v1/groups/gid-1/owners", {"ok": True})
    fake.add("POST", "https://api.limacharlie.io/v1/groups/gid-1/permissions", {"ok": True})
    fake.add("POST", "https://api.limacharlie.io/v1/groups/gid-1/orgs", {"ok": True})
    client = make_client(tmp_path, fake)

    create = client.preview_create_group("soc-team")
    delete = client.preview_delete_group("gid-1")
    member = client.preview_add_group_member("gid-1", "analyst@example.com")
    owner = client.preview_remove_group_owner("gid-1", "owner@example.com")
    perms = client.preview_set_group_permissions("gid-1", ["sensor.get", "dr.get"])
    org = client.preview_add_group_org("gid-1", OID)

    assert create["ok"] is True
    assert_ax_envelope(create, "group.create.preview")
    assert fake.calls == []

    client.confirm_mutation(create["data"]["confirmation_token"])
    client.confirm_mutation(delete["data"]["confirmation_token"])
    client.confirm_mutation(member["data"]["confirmation_token"])
    client.confirm_mutation(owner["data"]["confirmation_token"])
    client.confirm_mutation(perms["data"]["confirmation_token"])
    client.confirm_mutation(org["data"]["confirmation_token"])

    assert fake.calls[0]["data"]["oid"] == "-"
    assert fake.calls[1]["params"] == {"name": "soc-team"}
    assert fake.calls[2]["method"] == "DELETE"
    assert fake.calls[3]["params"] == {"member_email": "analyst@example.com"}
    assert fake.calls[4]["params"] == {"member_email": "owner@example.com"}
    assert fake.calls[5]["params"] == {"perm": ["sensor.get", "dr.get"]}
    assert fake.calls[6]["params"] == {"oid": OID}


def test_installation_ingestion_and_output_previews_confirm_exact_requests(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("POST", f"https://api.limacharlie.io/v1/installationkeys/{OID}", {"iid": "iid-1"})
    fake.add("DELETE", f"https://api.limacharlie.io/v1/installationkeys/{OID}", {"ok": True})
    fake.add("POST", f"https://api.limacharlie.io/v1/insight/{OID}/ingestion_keys", {"name": "ingest-1"})
    fake.add("DELETE", f"https://api.limacharlie.io/v1/insight/{OID}/ingestion_keys", {"ok": True})
    fake.add("POST", f"https://api.limacharlie.io/v1/outputs/{OID}", {"name": "out-1"})
    fake.add("DELETE", f"https://api.limacharlie.io/v1/outputs/{OID}", {"ok": True})
    client = make_client(tmp_path, fake)

    install = client.preview_create_installation_key(OID, "installer", tags=["prod", "edr"], use_public_ca=True)
    delete_install = client.preview_delete_installation_key(OID, "iid-1")
    ingest = client.preview_create_ingestion_key(OID, "ingest-1")
    delete_ingest = client.preview_delete_ingestion_key(OID, "ingest-1")
    output = client.preview_create_output(OID, "out-1", "webhook", "event", config={"url": "https://example.test/hook"})
    delete_output = client.preview_delete_output(OID, "out-1")

    assert install["ok"] is True
    assert_ax_envelope(install, "installation_key.create.preview")
    assert fake.calls == []

    client.confirm_mutation(install["data"]["confirmation_token"])
    client.confirm_mutation(delete_install["data"]["confirmation_token"])
    client.confirm_mutation(ingest["data"]["confirmation_token"])
    client.confirm_mutation(delete_ingest["data"]["confirmation_token"])
    client.confirm_mutation(output["data"]["confirmation_token"])
    client.confirm_mutation(delete_output["data"]["confirmation_token"])

    assert fake.calls[1]["params"] == {"desc": "installer", "use_public_root_ca": "true", "tags": "prod,edr"}
    assert fake.calls[2]["params"] == {"iid": "iid-1"}
    assert fake.calls[3]["params"] == {"name": "ingest-1"}
    assert fake.calls[4]["params"] == {"name": "ingest-1"}
    assert fake.calls[5]["params"] == {
        "name": "out-1",
        "module": "webhook",
        "type": "event",
        "url": "https://example.test/hook",
    }
    assert fake.calls[6]["params"] == {"name": "out-1"}


def test_extension_previews_confirm_exact_requests(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("POST", f"https://api.limacharlie.io/v1/orgs/{OID}/subscription/extension/ext-yara", {"ok": True})
    fake.add("DELETE", f"https://api.limacharlie.io/v1/orgs/{OID}/subscription/extension/ext-yara", {"ok": True})
    fake.add("PATCH", f"https://api.limacharlie.io/v1/orgs/{OID}/subscription/extension/ext-yara", {"key": "new"})
    fake.add("POST", "https://api.limacharlie.io/v1/extension/request/ext-vulnerability-reporting", {"data": {"ok": True}})
    client = make_client(tmp_path, fake)

    subscribe = client.preview_subscribe_extension(OID, "ext-yara")
    unsubscribe = client.preview_unsubscribe_extension(OID, "ext-yara")
    rekey = client.preview_rekey_extension(OID, "ext-yara")
    request = client.preview_extension_request(OID, "ext-vulnerability-reporting", "query_dashboard", data={"sort_asc": True})

    assert subscribe["ok"] is True
    assert_ax_envelope(subscribe, "extension.subscribe.preview")
    assert fake.calls == []

    client.confirm_mutation(subscribe["data"]["confirmation_token"])
    client.confirm_mutation(unsubscribe["data"]["confirmation_token"])
    client.confirm_mutation(rekey["data"]["confirmation_token"])
    client.confirm_mutation(request["data"]["confirmation_token"])

    assert fake.calls[1]["method"] == "POST"
    assert fake.calls[2]["method"] == "DELETE"
    assert fake.calls[3]["method"] == "PATCH"
    assert fake.calls[4]["params"]["oid"] == OID
    assert fake.calls[4]["params"]["action"] == "query_dashboard"
    assert decode_gzdata(fake.calls[4]["params"]["gzdata"]) == {"sort_asc": True}


def test_extension_definition_previews_and_impersonation_guard(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("POST", "https://api.limacharlie.io/v1/extension/definition", {"ok": True})
    fake.add("PUT", "https://api.limacharlie.io/v1/extension/definition", {"ok": True})
    fake.add("DELETE", "https://api.limacharlie.io/v1/extension/definition/ext-custom", {"ok": True})
    client = make_client(tmp_path, fake)

    create = client.preview_create_extension({"name": "ext-custom", "version": "1.0"})
    update = client.preview_update_extension({"name": "ext-custom", "version": "1.1"})
    delete = client.preview_delete_extension("ext-custom")

    with pytest.raises(ValidationError, match="impersonate"):
        client.preview_extension_request(OID, "ext-custom", "do_thing", impersonate=True)

    client.confirm_mutation(create["data"]["confirmation_token"])
    client.confirm_mutation(update["data"]["confirmation_token"])
    client.confirm_mutation(delete["data"]["confirmation_token"])

    assert fake.calls[0]["data"]["oid"] == "-"
    assert fake.calls[1]["json"] == {"name": "ext-custom", "version": "1.0"}
    assert fake.calls[2]["json"] == {"name": "ext-custom", "version": "1.1"}
    assert fake.calls[3]["method"] == "DELETE"


def test_org_platform_read_tools_use_expected_paths(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/orgs/{OID}/url", {"url": {"hooks": "https://hooks"}})
    fake.add("GET", f"https://api.limacharlie.io/v1/runtime_mtd/{OID}", {"records": [{"entity": "sensor"}]})
    fake.add("GET", f"https://api.limacharlie.io/v1/quota_usage/{OID}", {"usage": 3})
    client = make_client(tmp_path, fake)

    urls = client.get_org_urls(OID)
    runtime = client.get_runtime_metadata(OID, entity_type="sensor", entity_name="sensor-1", limit=1)
    quota = client.get_quota_usage(OID)

    assert urls["ok"] is True
    assert_ax_envelope(urls, "org.urls")
    assert urls["data"]["url"]["hooks"] == "https://hooks"
    assert fake.calls[0]["url"] == f"https://api.limacharlie.io/v1/orgs/{OID}/url"
    assert "Authorization" not in fake.calls[0]["headers"]
    assert runtime["data"]["records"] == [{"entity": "sensor"}]
    assert fake.calls[2]["params"] == {"entity_type": "sensor", "entity_name": "sensor-1"}
    assert quota["data"]["usage"] == 3


def test_billing_read_tools_use_expected_paths(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/orgs/{OID}/billing/status", {"status": "active"})
    fake.add("GET", f"https://api.limacharlie.io/v1/orgs/{OID}/billing/details", {"plan": "pro"})
    fake.add("GET", f"https://api.limacharlie.io/v1/orgs/{OID}/billing/invoice/2026/06", {"url": "https://invoice"})
    fake.add("GET", "https://api.limacharlie.io/v1/plans", {"plans": [{"name": "pro"}]})
    client = make_client(tmp_path, fake)

    status = client.get_billing_status(OID)
    details = client.get_billing_details(OID)
    invoice = client.get_billing_invoice_url(OID, 2026, 6, fmt="pdf")
    plans = client.list_billing_plans()

    assert status["operation"] == "billing.status"
    assert details["data"]["plan"] == "pro"
    assert invoice["resource"]["id"] == "2026-06"
    assert fake.calls[3]["params"] == {"format": "pdf"}
    assert plans["data"]["plans"][0]["name"] == "pro"


def test_group_read_tools_use_expected_paths(tmp_path: Path) -> None:
    fake = FakeHTTP()
    fake.add("GET", "https://api.limacharlie.io/v1/groups", {"groups": [{"id": "gid-1"}]})
    fake.add("GET", "https://api.limacharlie.io/v1/groups/gid-1", {"id": "gid-1", "members": []})
    fake.add("GET", "https://api.limacharlie.io/v1/groups/gid-1/logs", {"logs": [{"action": "created"}]})
    client = make_client(tmp_path, fake)

    groups = client.list_groups(limit=10)
    group = client.get_group("gid-1")
    logs = client.list_group_logs("gid-1", limit=5)

    assert groups["ok"] is True
    assert_ax_envelope(groups, "group.list")
    assert groups["data"]["groups"][0]["id"] == "gid-1"
    assert group["resource"] == {"type": "group", "id": "gid-1"}
    assert logs["data"]["logs"][0]["action"] == "created"
    assert fake.calls[0]["data"]["oid"] == "-"
    assert fake.calls[1]["url"] == "https://api.limacharlie.io/v1/groups"
    assert fake.calls[2]["url"] == "https://api.limacharlie.io/v1/groups/gid-1"
    assert fake.calls[3]["url"] == "https://api.limacharlie.io/v1/groups/gid-1/logs"


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
