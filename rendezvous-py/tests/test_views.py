"""Pytest suite for the rendezvous API.

Mirrors the coverage of the Rust server test suite:
  - health check
  - register + fetch
  - upsert (re-registration updates the record, does not duplicate it)
  - multiple devices per user
  - user isolation
  - DELETE /register (deregister)
  - DELETE of unknown peer is a silent no-op
  - TTL: expired records are excluded from GET /peers
  - prune: registry.prune() removes expired entries
"""

import json
import time

from django.test import Client

from rendezvous import registry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _register(
    client: Client,
    username: str,
    node_id: str,
    addrs: list[str] | None = None,
    relay_url: str | None = None,
) -> None:
    resp = client.post(
        "/register",
        data=json.dumps(
            {"username": username, "node_id": node_id, "addrs": addrs or [], "relay_url": relay_url}
        ),
        content_type="application/json",
    )
    assert resp.status_code == 200


def _peers(client: Client, username: str) -> list[dict]:
    resp = client.get(f"/peers?username={username}")
    assert resp.status_code == 200
    return json.loads(resp.content)["peers"]


def _deregister(client: Client, username: str, node_id: str) -> int:
    resp = client.delete(
        "/register",
        data=json.dumps({"username": username, "node_id": node_id}),
        content_type="application/json",
    )
    return resp.status_code


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health_check_returns_200_empty_list(client: Client) -> None:
    resp = client.get("/peers?username=healthcheck")
    assert resp.status_code == 200
    assert json.loads(resp.content) == {"peers": []}


def test_register_and_fetch_peer(client: Client) -> None:
    _register(client, "alice", "node-abc", ["1.2.3.4:1234"], "https://relay.example.com")
    peers = _peers(client, "alice")
    assert len(peers) == 1
    assert peers[0]["node_id"] == "node-abc"
    assert peers[0]["addrs"] == ["1.2.3.4:1234"]
    assert peers[0]["relay_url"] == "https://relay.example.com"
    assert isinstance(peers[0]["last_seen"], int)


def test_register_upserts_existing_node(client: Client) -> None:
    _register(client, "bob", "node-bob", ["10.0.0.1:9000"])
    _register(client, "bob", "node-bob", ["10.0.0.2:9001"], "https://relay.example.com")
    peers = _peers(client, "bob")
    assert len(peers) == 1, "re-registration must upsert, not duplicate"
    assert peers[0]["addrs"] == ["10.0.0.2:9001"]
    assert peers[0]["relay_url"] == "https://relay.example.com"


def test_multiple_devices_returned_for_same_user(client: Client) -> None:
    _register(client, "carol", "node-1", ["1.0.0.1:1"])
    _register(client, "carol", "node-2", ["2.0.0.2:2"])
    assert len(_peers(client, "carol")) == 2


def test_users_are_isolated(client: Client) -> None:
    _register(client, "alice", "a1")
    _register(client, "bob", "b1")
    peers = _peers(client, "alice")
    assert len(peers) == 1
    assert peers[0]["node_id"] == "a1"


def test_deregister_removes_peer(client: Client) -> None:
    _register(client, "dave", "d1")
    _register(client, "dave", "d2")
    assert _deregister(client, "dave", "d1") == 200
    peers = _peers(client, "dave")
    assert len(peers) == 1
    assert peers[0]["node_id"] == "d2"


def test_deregister_nonexistent_is_noop(client: Client) -> None:
    assert _deregister(client, "nobody", "ghost") == 200


def test_expired_peer_is_excluded(client: Client) -> None:
    with registry._lock:
        registry._registry["eve"] = [
            {"node_id": "e1", "addrs": [], "relay_url": None, "last_seen": 0},
            {"node_id": "e2", "addrs": [], "relay_url": None, "last_seen": int(time.time())},
        ]
    peers = _peers(client, "eve")
    assert len(peers) == 1, "only the live record should be returned"
    assert peers[0]["node_id"] == "e2"


def test_prune_removes_expired_entries() -> None:
    with registry._lock:
        registry._registry["frank"] = [
            {"node_id": "f1", "addrs": [], "relay_url": None, "last_seen": 0},
        ]
    count = registry.prune()
    assert count == 1
    assert "frank" not in registry._registry
