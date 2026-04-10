# dddatasync

`dddatasync` is a CLI tool that syncs files between a user's devices automatically.

The features are:
1. File sync, between nodes on the same network or different networks.
2. Careful handling of files, so that data is not lost.
    - Errors are presented to the user when anything goes wrong.
3. The service ONLY allows you to store 3 files, and up to 1 GB of data .
4. Data is stored on your machine at `~/dddatasync/` .

## Beta ⚠️

This projecet has several gaps, and shouldn't be used for critical data storage.

## Known limitations

### No authentication

No authentication — any client can register any username.  The node key is the
proof of identity; iroh rejects connections from nodes whose public key does not
match the `NodeId`.  TTL: 5 minutes per record; pruned every 60 seconds.

### Conflict resolution (clock skew)

When the same filename is modified on two devices concurrently, dddatasync
uses **last-write-wins (LWW)** based on mtime.  LWW correctness depends on
device clocks being in sync.  Clock skew of even a few seconds can cause the
wrong version to win silently.  The proper fix is a Hybrid Logical Clock (HLC);
this is deferred to a future version.  v1 recommendation: ensure NTP/time sync
on enrolled devices.
