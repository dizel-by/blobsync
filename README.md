# blobsync

`blobsync` is a small Go library for file synchronization between nodes using MySQL as the source of truth. NATS can be enabled as an optional wake-up bus.

## Installation

```bash
go get github.com/dizel-by/blobsync
```

```go
import "github.com/dizel-by/blobsync"
```

## Tables

See `schema.sql` for the expected MySQL schema:

- `bsfiles`: file list, size, sha256 and delete marker.
- `bsevents`: append-only add/remove events.
- `bsnodes`: node addresses, cursors, ACL fingerprint and liveness.

## Usage

```go
bs, err := blobsync.New(blobsync.Config{
    Node:             "node-a",
    DB:               db,
    BindAddress:      ":8080",
    AdvertiseAddress: "node-a.internal.example:8080",
    StoragePath:      "/var/lib/myapp/files",
    HTTPPrefix:       "/blobsync",
}, blobsync.WithACL(blobsync.ACL{
        Whitelist: []string{"public/", "avatars/"},
        Blacklist: []string{"public/tmp/"},
}), blobsync.WithNats(nc, "blobsync.files"), blobsync.WithLogger(logger))
if err != nil {
    return err
}

if err := bs.Start(ctx); err != nil {
    return err
}
defer bs.Close()

if err := bs.AddFile(ctx, "data/example.bin"); err != nil {
    return err
}
```

`Start(ctx)`, `AddFile(ctx, filename)`, `Scan(ctx)`, `RemoveFile(ctx, filename)`, `Resync(ctx)`, and `Cleanup(ctx)` use the caller context for cancellation and deadlines. `Start(ctx)` uses the context for startup work only; after a successful start, background workers run until `Close()`.

`StoragePath` defaults to `data`. Empty config values use that default, and `.` is rejected. Filenames are stored in MySQL as slash-separated paths relative to `StoragePath`. `AddFile` accepts either a relative path such as `data/example.bin` or an absolute path under `StoragePath`. Downloaded files are written under `StoragePath`, and files outside that directory are rejected.

`HTTPPrefix` changes the built-in HTTP download route. With `HTTPPrefix: "/blobsync"`, files are served as `http://node-address/blobsync/123`. All nodes in the cluster should use the same prefix.

`WithACL(acl)` sets filename prefixes before start. ACL cannot be changed on a running `BlobSync`; create a new instance with a different `WithACL` value and restart it. If whitelist is non-empty, only matching files are synchronized. If blacklist is non-empty, matching files are not synchronized. Blacklist wins over whitelist. The normalized ACL fingerprint is stored in `bsnodes.aclsha256`. Changing ACL in config and restarting the process runs a full `Resync`, so files that are no longer allowed are removed locally and newly allowed files are downloaded.

`Scan(ctx)` walks `StoragePath`, finds ACL-allowed local files that are missing from `bsfiles` or are marked deleted, upserts them into `bsfiles`, and creates `add` events. It does not publish NATS messages; other nodes will pick the new events up through normal reconcile.

`Cleanup(ctx)` walks every local file under `StoragePath` and removes files that are missing from `bsfiles` or are marked deleted there. It leaves directories in place. Use it with caution: it is destructive and should only run when `StoragePath` is dedicated to blobsync-managed files.

`BindAddress` is only used for `net.Listen`, so bind-style addresses such as `:8080` are fine there. `AdvertiseAddress` is written to `bsnodes` and is used by other nodes to download files over HTTP, so it must be reachable from the rest of the cluster. `AdvertiseAddress` must not be a wildcard or loopback address such as `0.0.0.0:8080`, `[::]:8080`, `127.0.0.1:8080`, or `localhost:8080`.

`Start` checks whether this node already exists in `bsnodes`. For a new node, it runs the initial `Resync` first, starts HTTP file serving, then inserts the node with the final cursor and advertised address. Existing nodes start HTTP first, then update their advertised address and `lastseen`. NATS messages are treated as reconcile kicks; the database event log remains authoritative.

Without `WithNats`, blobsync does not subscribe to NATS and does not publish NATS messages. Synchronization still happens through `Reconcile`, `Resync`, and the periodic reconcile tick.

`WithLogger` accepts any logger with `Printf(format string, v ...any)`. If omitted, background errors are not logged.

Files are served from the configured HTTP prefix by file id, for example `http://node-address/123` or `http://node-address/blobsync/123`.

The built-in HTTP server does not implement authentication or authorization. Run it only on a trusted network, or put external access control in front of it.

## Constraints

- Each node name must be unique across the cluster. Running two processes with the same `Node` value simultaneously is not supported and will cause undefined behaviour.
