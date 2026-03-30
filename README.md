# kunipa-securedb

Minimal Rust crate for SQLCipher with atomic key application.

## Problem

When using SQLCipher, the encryption key must be applied immediately after opening the database — before any reads (including internal reads of `sqlite_master`). Most SQLite wrappers don't guarantee this ordering.

## Solution

This crate wraps `rusqlite` with `bundled-sqlcipher` to provide a single-connection `Database` type that applies the encryption key atomically right after opening, then verifies it with a probe query before returning.

## Features

- Atomic open → `PRAGMA key` → verify sequence
- Key applied on every connection open (not just the first)
- Single-connection model enforced structurally via `Mutex`
- Key stored in `SecretBox` with deterministic zeroing on drop (`zeroize`)
- `EncryptionMode` separates security intent from key data
- Typed errors (`WrongKey`, `KeyRequired`, `NotDatabase`, etc.)
- Three-level verification: `looks_plaintext`, `can_open_with_key`, `verify_cipher_metadata`
- Runtime capability detection via `available()`
- Key rotation via `rotate_key`
- Full `rusqlite` access via `with_connection` / `with_connection_mut` closures
- FTS5 support (via bundled SQLCipher)

## Scope

This is intentionally **not** a general-purpose SQLite wrapper. It does **not** support: savepoints, backup API, custom functions, or interrupts.

## Install

Add to `Cargo.toml`:

```toml
[dependencies]
kunipa-securedb = { path = "../kunipa-securedb" }
```

No system libraries required — `bundled-sqlcipher` is the default.

## Usage

```rust
use kunipa_securedb::{open, Options, EncryptionMode};
use secrecy::SecretBox;

// Open encrypted database
let db = open("/path/to/db", Options {
    key: Some(SecretBox::new(Box::new(my_key))),
    encryption: EncryptionMode::Required,
    ..Options::default()
})?;

// Use the connection
db.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)", [])?;
db.execute("INSERT INTO t (val) VALUES (?1)", ["hello"])?;

// Full rusqlite access (including transactions)
db.with_connection_mut(|conn| {
    let tx = conn.transaction()?;
    tx.execute("INSERT INTO t (val) VALUES (?1)", ["world"])?;
    tx.commit()
})?;

// Check SQLCipher availability
kunipa_securedb::available()?;

// Verify an existing database
let version = kunipa_securedb::verify_cipher_metadata(&db)?;

// Rotate key
db.rotate_key(&new_key)?;
```

## Build

```bash
cargo build
```

## Test

```bash
cargo test
```

## License

MIT
