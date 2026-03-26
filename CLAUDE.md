# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A CGO mini-driver for SQLCipher that implements `database/sql/driver` interfaces directly against the SQLite/SQLCipher C API. It exists because `mattn/go-sqlite3`'s `ConnectHook` fires too late — after internal setup reads `sqlite_master` — so `PRAGMA key` can't work on encrypted databases. This driver calls `sqlite3_key()` atomically right after `sqlite3_open_v2()`.

Used by KunipaMail and KunipaLedger. Intentionally limited scope: no named parameters, savepoints, backup API, custom functions, or interrupts.

## Build

Requires `libsqlcipher-dev` (Debian/Ubuntu) or `sqlcipher` (Homebrew):

```bash
go build ./...
```

CGO flags are embedded in `doc.go` via `#cgo` directives — no manual `CGO_CFLAGS`/`CGO_LDFLAGS` needed for standard installs.

## Test

```bash
go test -v ./...
```

All tests use random 32-byte keys and `t.TempDir()` for database files — no external state required beyond having `libsqlcipher-dev` installed.

## Architecture

Single package, flat structure. The C layer is minimal (`securedb.c`/`securedb.h`) — just the atomic open→key→verify sequence, rekey, close, and error helpers.

Go files map 1:1 to `database/sql/driver` interfaces:
- **`securedb.go`** — public API: `Open()`, `Available()`, `RotateKey()`, `Options`, `EncryptionMode`
- **`driver.go`** — `connector` (captures key in closure, applies on every `Connect()`) and `securedbDriver`
- **`conn.go`** — `conn` implementing `driver.Conn`, `ExecerContext`, `QueryerContext`; also contains `bindArgs()` for parameter binding
- **`stmt.go`** — `stmt` implementing `driver.Stmt`
- **`rows.go`** — `rows` implementing `driver.Rows` with SQLite type→Go type mapping
- **`tx.go`** — `tx` implementing `driver.Tx` (COMMIT/ROLLBACK)
- **`result.go`** — `result` implementing `driver.Result`
- **`verify.go`** — `LooksPlaintext()`, `CanOpenWithKey()`, `VerifyCipherMetadata()`
- **`errors.go`** — typed sentinel errors (`ErrWrongKey`, `ErrKeyRequired`, etc.)

## Key Design Decisions

- **No global driver registration**: uses `sql.OpenDB(connector)` so it coexists with `mattn/go-sqlite3` ("sqlite3") without conflicts.
- **Key never in DSN**: the encryption key is captured in the `connector` closure. It's copied from `Options.Key` to prevent caller mutation.
- **`MaxOpenConns(1)` by default**: SQLCipher with a single connection avoids locking complexity. Tests that need multiple connections temporarily bump this.
- **Context cancellation not propagated to C**: documented limitation. With `MaxOpenConns(1)` and local I/O, this is acceptable.
- **`runtime.KeepAlive`**: used after C calls that reference Go-managed key bytes to prevent GC from moving them during the call.
- **`SQLITE_TRANSIENT`**: bind helpers in `conn.go` use C wrapper functions because cgo can't express the `SQLITE_TRANSIENT` macro directly.
