# Unit tests: HenngeClient service (HENNGE One Admin REST API shape).
# Pure service layer (stdlib-only, no framework imports) - plain function tests.
#
# The transport contract is (url, headers, json_body, timeout_s): the budget is
# handed to the transport so a live implementation can bound its own wait, and
# re-checked by the client on elapsed time.

import pytest

from src.services.hennge_client import HenngeApiError, HenngeClient


def test_get_user_access_success_with_injected_get():
    captured = {}

    def get(url, headers, body, timeout_s):
        captured["url"] = url
        captured["headers"] = headers
        captured["body"] = body
        return 200, {"user_id": "u-1001", "access_data": [{"app_id": "app-1", "app_name": "app-1", "status": "active"}]}

    client = HenngeClient("https://hennge.example.test/v1/", get=get)
    resp = client.get_user_access("u-1001", "tok123")
    assert resp["access_data"][0]["app_id"] == "app-1"
    assert captured["url"] == "https://hennge.example.test/v1/users/u-1001/applications"
    # HENNGE One Admin REST API auth: per-call token travels as a Bearer header.
    assert captured["headers"]["Authorization"] == "Bearer tok123"
    assert captured["headers"]["Content-Type"] == "application/json"
    assert captured["body"]["user_id"] == "u-1001"


def test_get_user_policies_success_with_injected_get():
    captured = {}

    def get(url, headers, body, timeout_s):
        captured["url"] = url
        captured["body"] = body
        return 200, {
            "user_id": "u-1001",
            "policy_data": [{"policy_id": "pol-1", "policy_name": "mfa", "status": "assigned"}],
        }

    client = HenngeClient("https://hennge.example.test/v1", get=get)
    resp = client.get_user_policies("u-1001", "tok")
    assert resp["policy_data"][0]["policy_id"] == "pol-1"
    assert captured["url"] == "https://hennge.example.test/v1/users/u-1001/policies"
    assert captured["body"]["user_id"] == "u-1001"


def test_grant_access_success_with_injected_post():
    captured = {}

    def post(url, headers, body, timeout_s):
        captured["url"] = url
        captured["body"] = body
        return 200, {"task_id": 42, "grant_id": "g-42", "user_id": "u-1001"}

    client = HenngeClient("https://hennge.example.test/v1", post=post)
    payload = {"access_request": [{"user_id": "u-1001", "app_name": "Salesforce"}]}
    resp = client.grant_access(payload, "tok")
    assert resp["grant_id"] == "g-42"
    assert captured["url"] == "https://hennge.example.test/v1/access-grants"
    assert captured["body"] == payload


def test_revoke_access_success_with_injected_post():
    captured = {}

    def post(url, headers, body, timeout_s):
        captured["url"] = url
        captured["body"] = body
        return 200, {"task_id": 7, "revocation_id": "r-7", "user_id": "u-1001"}

    client = HenngeClient("https://hennge.example.test/v1", post=post)
    payload = {"access_request": [{"user_id": "u-1001", "app_name": "Salesforce"}]}
    resp = client.revoke_access(payload, "tok")
    assert resp["revocation_id"] == "r-7"
    assert captured["url"] == "https://hennge.example.test/v1/access-revocations"
    assert captured["body"] == payload


def test_non_2xx_raises_hennge_api_error():
    def post(url, headers, body, timeout_s):
        return 400, {"errors": ["access_request is malformed"]}

    client = HenngeClient("https://hennge.example.test/v1", post=post)
    with pytest.raises(HenngeApiError) as exc:
        client.grant_access({"access_request": [{}]}, "tok")
    assert exc.value.status_code == 400
    assert "access_request is malformed" in str(exc.value)


def test_default_stub_transport_lookup_shape():
    # No transport injected -> deterministic, network-free stub.
    client = HenngeClient()
    assert client.uses_stub_transport is True
    resp = client.get_user_access("u-1001", "tok")
    assert resp.get("_stub") is True
    assert resp["user_id"] == "u-1001"
    record = resp["access_data"][0]
    assert record["status"] == "active"
    assert record["app_name"]


def test_default_stub_transport_policies_shape():
    client = HenngeClient()
    resp = client.get_user_policies("u-1001", "tok")
    assert resp.get("_stub") is True
    record = resp["policy_data"][0]
    assert record["status"] == "assigned"
    assert record["policy_id"]


def test_default_stub_transport_grant_echoes_target_user():
    client = HenngeClient()
    resp = client.grant_access({"access_request": [{"user_id": "u-1001", "app_name": "Salesforce"}]}, "tok")
    assert resp.get("_stub") is True
    assert resp["user_id"] == "u-1001"
    assert resp["grant_id"].startswith("g-")
    assert isinstance(resp["task_id"], int)


def test_default_stub_transport_revoke_returns_revocation_id():
    client = HenngeClient()
    resp = client.revoke_access({"access_request": [{"user_id": "u-1001", "app_name": "Salesforce"}]}, "tok")
    assert resp.get("_stub") is True
    assert resp["revocation_id"].startswith("r-")


def test_injected_transport_disables_stub_flag():
    client = HenngeClient(get=lambda url, headers, body, timeout_s: (200, {"access_data": []}))
    assert client.uses_stub_transport is False


def test_transport_receives_the_configured_budget():
    """The declared budget reaches the transport, which is how a live client bounds its wait."""
    seen = {}

    def get(url, headers, body, timeout_s):
        seen["timeout_s"] = timeout_s
        return 200, {"access_data": [{"app_id": "a", "app_name": "a", "status": "active"}]}

    client = HenngeClient("https://hennge.example.test/v1", timeout_s=12.5, get=get)
    client.get_user_access("u-1001", "tok")
    assert seen["timeout_s"] == 12.5
    assert client.timeout_s == 12.5


def test_overrunning_the_budget_is_an_error_not_a_late_answer():
    """A response that arrives after the budget is discarded rather than acted on."""
    import time

    def get(url, headers, body, timeout_s):
        time.sleep(0.02)
        return 200, {"access_data": [{"app_id": "a", "app_name": "a", "status": "active"}]}

    client = HenngeClient("https://hennge.example.test/v1", timeout_s=0.001, get=get)
    with pytest.raises(HenngeApiError) as exc:
        client.get_user_access("u-1001", "tok")
    assert exc.value.status_code == 504
    assert "budget" in str(exc.value)
