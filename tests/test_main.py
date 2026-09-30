import json

import pytest
from fastapi.testclient import TestClient

import main

SECRET = "test-secret"
API_KEY = "admin-key"


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(main.settings, "webhook_secret", SECRET)
    monkeypatch.setattr(main.settings, "allow_unsigned", False)
    monkeypatch.setattr(main.settings, "logs_api_key", API_KEY)
    monkeypatch.setattr(main.settings, "supabase_url", "")
    monkeypatch.setattr(main.settings, "max_body_bytes", 1000)
    monkeypatch.setattr(main, "store", main.EventStore(main.settings))
    with TestClient(main.app) as c:
        yield c


def _post(client, body, **headers):
    raw = json.dumps(body).encode()
    sig = main.compute_signature(SECRET, raw)
    return client.post("/webhook", content=raw, headers={"X-Hub-Signature-256": sig, "Content-Type": "application/json", **headers})


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_valid_signature_accepted_and_listed(client):
    r = _post(client, {"order": 1}, **{"X-Event-Source": "shop", "X-Event-Type": "order.created"})
    assert r.status_code == 202 and r.json()["accepted"]
    logs = client.get("/logs", headers={"X-API-Key": API_KEY}).json()
    assert logs["count"] == 1 and logs["logs"][0]["payload"] == {"order": 1}


def test_invalid_signature_rejected(client):
    r = client.post("/webhook", content=b"{}", headers={"X-Hub-Signature-256": "sha256=deadbeef"})
    assert r.status_code == 401


def test_missing_secret_rejects_unless_allowed(client, monkeypatch):
    monkeypatch.setattr(main.settings, "webhook_secret", "")
    assert client.post("/webhook", json={"a": 1}).status_code == 503
    monkeypatch.setattr(main.settings, "allow_unsigned", True)
    assert client.post("/webhook", json={"a": 1}).status_code == 202


def test_duplicate_delivery_stored_once(client):
    assert _post(client, {"x": 1}, **{"X-GitHub-Delivery": "abc", "X-GitHub-Event": "push"}).status_code == 202
    r = _post(client, {"x": 1}, **{"X-GitHub-Delivery": "abc", "X-GitHub-Event": "push"})
    assert r.status_code == 200 and r.json()["duplicate"]
    logs = client.get("/logs", headers={"X-API-Key": API_KEY}).json()["logs"]
    assert len(logs) == 1 and logs[0]["source"] == "github" and logs[0]["event_type"] == "push"


def test_non_object_and_non_json_payloads(client):
    assert _post(client, [1, 2, 3]).status_code == 202
    raw = b"not json"
    r = client.post("/webhook", content=raw, headers={"X-Hub-Signature-256": main.compute_signature(SECRET, raw)})
    assert r.status_code == 202
    payloads = [e["payload"] for e in client.get("/logs", headers={"X-API-Key": API_KEY}).json()["logs"]]
    assert {"raw": "not json"} in payloads and [1, 2, 3] in payloads


def test_payload_too_large(client):
    assert _post(client, {"x": "y" * 2000}).status_code == 413


def test_logs_require_api_key_and_filter(client):
    assert client.get("/logs").status_code == 401
    _post(client, {}, **{"X-Event-Source": "a"})
    _post(client, {}, **{"X-Event-Source": "b"})
    r = client.get("/logs?source=b&limit=5", headers={"X-API-Key": API_KEY}).json()
    assert r["count"] == 1 and r["logs"][0]["source"] == "b"
    assert client.get("/logs?limit=0", headers={"X-API-Key": API_KEY}).status_code == 422


def test_metrics(client):
    _post(client, {})
    client.post("/webhook", content=b"{}", headers={"X-Hub-Signature-256": "sha256=00"})
    m = client.get("/metrics", headers={"X-API-Key": API_KEY}).json()
    assert m["received"] == 1 and m["rejected"] == 1


def test_bare_hex_signature_accepted():
    raw = b'{"a":1}'
    digest = main.compute_signature(SECRET, raw).removeprefix("sha256=")
    assert main.verify_signature(raw, digest, SECRET)
    assert not main.verify_signature(raw, "", SECRET)
