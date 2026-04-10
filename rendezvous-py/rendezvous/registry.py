"""In-memory peer registry with TTL filtering and thread-safe access.

All state is stored in a module-level dict protected by a threading.Lock.
No database, no files — a restart clears all entries.  Enrolled devices
re-register within two minutes via their keepalive heartbeat.
"""

import threading
import time

PEER_TTL_SECS: int = 300  # 5 minutes, matching the Rust server


_lock = threading.Lock()
_registry: dict[str, list[dict]] = {}


def _now() -> int:
    return int(time.time())


def upsert(username: str, node_id: str, addrs: list[str], relay_url: str | None) -> None:
    """Register or refresh a peer record for *username* (upsert by node_id)."""
    record: dict = {
        "node_id": node_id,
        "addrs": addrs,
        "relay_url": relay_url,
        "last_seen": _now(),
    }
    with _lock:
        peers = _registry.setdefault(username, [])
        for i, peer in enumerate(peers):
            if peer["node_id"] == node_id:
                peers[i] = record
                return
        peers.append(record)


def fetch(username: str) -> list[dict]:
    """Return all live (non-expired) peers for *username*."""
    cutoff = _now() - PEER_TTL_SECS
    with _lock:
        return [p for p in _registry.get(username, []) if p["last_seen"] >= cutoff]


def remove(username: str, node_id: str) -> None:
    """Remove the peer identified by *node_id* from *username*'s list.

    No-op if the username or node_id is not found.
    """
    with _lock:
        if username not in _registry:
            return
        _registry[username] = [p for p in _registry[username] if p["node_id"] != node_id]
        if not _registry[username]:
            del _registry[username]


def prune() -> int:
    """Remove all expired records; return the count of pruned entries."""
    cutoff = _now() - PEER_TTL_SECS
    pruned = 0
    with _lock:
        for username in list(_registry.keys()):
            before = len(_registry[username])
            _registry[username] = [p for p in _registry[username] if p["last_seen"] >= cutoff]
            pruned += before - len(_registry[username])
            if not _registry[username]:
                del _registry[username]
    return pruned
