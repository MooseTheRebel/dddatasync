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
  - auth: unauthenticated POST/DELETE return 401
"""

import json
import time
from datetime import timedelta

import pytest
from django.contrib.auth.hashers import make_password
from django.test import Client
from django.utils import timezone

from rendezvous import registry
from rendezvous.models import AccountStatus, SessionToken, UserAccount

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def bearer_token(db):
    """Create an approved user and return a valid Bearer token string."""
    user = UserAccount.objects.create(
        username="testuser",
        email="testuser@example.com",
        password_hash=make_password("pw"),
        status=AccountStatus.APPROVED,
    )
    token_str = "test-bearer-token-abc123"
    SessionToken.objects.create(
        user=user,
        token=token_str,
        expires_at=timezone.now() + timedelta(hours=1),
    )
    return token_str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _register(
    client: Client,
    username: str,
    node_id: str,
    addrs: list[str] | None = None,
    relay_url: str | None = None,
    *,
    token: str,
) -> None:
    body = json.dumps(
        {"username": username, "node_id": node_id, "addrs": addrs or [], "relay_url": relay_url}
    ).encode()
    resp = client.post(
        "/register",
        data=body,
        content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {token}",
    )
    assert resp.status_code == 200


def _peers(client: Client, username: str) -> list[dict]:
    resp = client.get(f"/peers?username={username}")
    assert resp.status_code == 200
    return json.loads(resp.content)["peers"]


def _deregister(client: Client, username: str, node_id: str, *, token: str) -> int:
    body = json.dumps({"username": username, "node_id": node_id}).encode()
    resp = client.delete(
        "/register",
        data=body,
        content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {token}",
    )
    return resp.status_code


# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------

def test_register_without_auth_returns_401(client: Client) -> None:
    body = json.dumps({"username": "alice", "node_id": "n1", "addrs": [], "relay_url": None})
    resp = client.post("/register", data=body, content_type="application/json")
    assert resp.status_code == 401


def test_deregister_without_auth_returns_401(client: Client) -> None:
    body = json.dumps({"username": "alice", "node_id": "n1"})
    resp = client.delete("/register", data=body, content_type="application/json")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Functional tests
# ---------------------------------------------------------------------------

def test_health_check_returns_200_empty_list(client: Client) -> None:
    resp = client.get("/peers?username=healthcheck")
    assert resp.status_code == 200
    assert json.loads(resp.content) == {"peers": []}


def test_register_and_fetch_peer(client: Client, bearer_token: str) -> None:
    _register(client, "alice", "node-abc", ["1.2.3.4:1234"], "https://relay.example.com", token=bearer_token)
    peers = _peers(client, "alice")
    assert len(peers) == 1
    assert peers[0]["node_id"] == "node-abc"
    assert peers[0]["addrs"] == ["1.2.3.4:1234"]
    assert peers[0]["relay_url"] == "https://relay.example.com"
    assert isinstance(peers[0]["last_seen"], int)


def test_register_upserts_existing_node(client: Client, bearer_token: str) -> None:
    _register(client, "bob", "node-bob", ["10.0.0.1:9000"], token=bearer_token)
    _register(client, "bob", "node-bob", ["10.0.0.2:9001"], "https://relay.example.com", token=bearer_token)
    peers = _peers(client, "bob")
    assert len(peers) == 1, "re-registration must upsert, not duplicate"
    assert peers[0]["addrs"] == ["10.0.0.2:9001"]
    assert peers[0]["relay_url"] == "https://relay.example.com"


def test_multiple_devices_returned_for_same_user(client: Client, bearer_token: str) -> None:
    _register(client, "carol", "node-1", ["1.0.0.1:1"], token=bearer_token)
    _register(client, "carol", "node-2", ["2.0.0.2:2"], token=bearer_token)
    assert len(_peers(client, "carol")) == 2


def test_users_are_isolated(client: Client, bearer_token: str) -> None:
    _register(client, "alice", "a1", token=bearer_token)
    _register(client, "bob", "b1", token=bearer_token)
    peers = _peers(client, "alice")
    assert len(peers) == 1
    assert peers[0]["node_id"] == "a1"


def test_deregister_removes_peer(client: Client, bearer_token: str) -> None:
    _register(client, "dave", "d1", token=bearer_token)
    _register(client, "dave", "d2", token=bearer_token)
    assert _deregister(client, "dave", "d1", token=bearer_token) == 200
    peers = _peers(client, "dave")
    assert len(peers) == 1
    assert peers[0]["node_id"] == "d2"


def test_deregister_nonexistent_is_noop(client: Client, bearer_token: str) -> None:
    assert _deregister(client, "nobody", "ghost", token=bearer_token) == 200


def test_expired_peer_is_excluded(client: Client) -> None:
    with registry._lock:
        registry._registry["eve"] = [
            {"node_id": "e1", "addrs": [], "relay_url": None, "last_seen": 0},
            {"node_id": "e2", "addrs": [], "relay_url": None, "last_seen": int(time.time())},
        ]
    peers = _peers(client, "eve")
    assert len(peers) == 1, "only the live record should be returned"
    assert peers[0]["node_id"] == "e2"


# ---------------------------------------------------------------------------
# Security-fix tests
# ---------------------------------------------------------------------------

def test_blocked_user_token_is_rejected(client: Client, db) -> None:
    """A token belonging to a blocked user must be rejected."""
    user = UserAccount.objects.create(
        username="blockeduser",
        email="blocked@example.com",
        password_hash=make_password("pw"),
        status=AccountStatus.BLOCKED,
    )
    token_str = "blocked-user-token"
    SessionToken.objects.create(
        user=user,
        token=token_str,
        expires_at=timezone.now() + timedelta(hours=1),
    )
    body = json.dumps(
        {"username": "blockeduser", "node_id": "n1", "addrs": [], "relay_url": None}
    ).encode()
    resp = client.post(
        "/register",
        data=body,
        content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {token_str}",
    )
    assert resp.status_code == 401


def test_pending_user_token_is_rejected(client: Client, db) -> None:
    """A token belonging to a pending (unverified) user must be rejected."""
    user = UserAccount.objects.create(
        username="pendinguser",
        email="pending@example.com",
        password_hash=make_password("pw"),
        status=AccountStatus.PENDING,
    )
    token_str = "pending-user-token"
    SessionToken.objects.create(
        user=user,
        token=token_str,
        expires_at=timezone.now() + timedelta(hours=1),
    )
    body = json.dumps(
        {"username": "pendinguser", "node_id": "n1", "addrs": [], "relay_url": None}
    ).encode()
    resp = client.post(
        "/register",
        data=body,
        content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {token_str}",
    )
    assert resp.status_code == 401


def test_verify_does_not_unblock_blocked_account(client: Client, db) -> None:
    """Email verification must not change the status of a blocked account."""
    UserAccount.objects.create(
        username="blockedverifier",
        email="bv@example.com",
        password_hash=make_password("pw"),
        status=AccountStatus.BLOCKED,
        verification_token="some-verify-token",
    )
    resp = client.get("/auth/verify/some-verify-token")
    assert resp.status_code == 404
    user = UserAccount.objects.get(username="blockedverifier")
    assert user.status == AccountStatus.BLOCKED


def test_prune_removes_expired_entries() -> None:
    with registry._lock:
        registry._registry["frank"] = [
            {"node_id": "f1", "addrs": [], "relay_url": None, "last_seen": 0},
        ]
    count = registry.prune()
    assert count == 1
    assert "frank" not in registry._registry
