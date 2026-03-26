# kunipa-securedb

Minimal Go `database/sql` driver for SQLCipher with atomic key application.

## Problem

`mattn/go-sqlite3`'s `ConnectHook` executes **after** internal setup (busy_timeout, sqlite_master read). On an encrypted database, `PRAGMA key` arrives too late — the driver has already tried to read the unkeyed file.

## Solution

This package provides a CGO mini-driver that calls `sqlite3_key()` atomically right after `sqlite3_open_v2()`, before any other operation. It implements `database/sql/driver` interfaces directly against the SQLite/SQLCipher C API.

## Features

- Atomic `sqlite3_open_v2()` → `sqlite3_key()` → verify sequence
- Key applied to every physical connection (not just the first)
- `MaxOpenConns(1)` enforced by default
- Key captured in closure, never in DSN strings
- `EncryptionMode` separates security intent from key data
- Typed sentinel errors (`ErrWrongKey`, `ErrKeyRequired`, etc.)
- Three-level verification: `LooksPlaintext`, `CanOpenWithKey`, `VerifyCipherMetadata`
- Runtime capability detection via `Available()`
- Key rotation via `RotateKey`
- FTS5 support (via system SQLCipher)

## Scope

This is intentionally **not** a general-purpose SQLite driver. It supports:

- Types: TEXT, INTEGER, REAL, BLOB, NULL
- Transactions, prepared statements, `ExecerContext`, `QueryerContext`

It does **not** support: named parameters, savepoints, backup API, custom functions, interrupts.

## Coexistence with mattn/go-sqlite3

This package is autonomous — it does not import `mattn/go-sqlite3`. Consumer binaries can import both:

- `mattn/go-sqlite3` registers as driver `"sqlite3"`
- `kunipa-securedb` uses `sql.OpenDB(connector)` — no global driver registration conflicts

## Install

```bash
# Debian/Ubuntu
sudo apt-get install libsqlcipher-dev

# macOS
brew install sqlcipher
```

## Usage

```go
import "github.com/KunipaLabs/kunipa-securedb"

// Open encrypted database
db, err := securedb.Open("/path/to/db", securedb.Options{
    Key:        myKey,  // 32-byte random key
    Encryption: securedb.EncryptionRequired,
})

// Check SQLCipher availability
if err := securedb.Available(); err != nil {
    log.Fatal("SQLCipher not available:", err)
}

// Verify an existing database
version, err := securedb.VerifyCipherMetadata(db)

// Rotate key
err = securedb.RotateKey(db, newKey)
```

## Build

```bash
CGO_CFLAGS="-I/usr/include/sqlcipher -DSQLITE_HAS_CODEC" \
CGO_LDFLAGS="-lsqlcipher" \
go build ./...
```

## Test

```bash
go test -v ./...
```

## License

MIT
