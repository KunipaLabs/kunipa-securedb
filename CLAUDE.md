# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A Rust crate wrapping SQLCipher (via `rusqlite` + `bundled-sqlcipher`) with atomic key application. It exists to guarantee that the encryption key is applied immediately after opening the database, before any other operation reads `sqlite_master`.

Used by KunipaMail and KunipaLedger (Rust + Tauri). Intentionally limited scope: no savepoints, backup API, custom functions, or interrupts.

Reimplemented from Go — the original Go implementation lives on the `main` branch (to be archived as `main-go`).

## Build

```bash
cargo build
```

Uses `bundled-sqlcipher` by default — no system libraries required. For system-linked SQLCipher, use the `system-sqlcipher` feature.

## Test

```bash
cargo test
```

All tests use random 32-byte keys and `tempfile::TempDir` for database files — no external state required.

## Lint

```bash
cargo clippy -- -D warnings
```

## Architecture

Single crate, flat module structure. No custom C layer — `rusqlite` handles all FFI.

- **`src/lib.rs`** — public API: `open()`, `available()`, re-exports
- **`src/connection.rs`** — `Database` struct with single `Mutex<Option<Inner>>` state, `with_connection()`, `with_connection_mut()`, `rotate_key()`, `close()`, `Drop`
- **`src/options.rs`** — `Options`, `EncryptionMode` (Required/Disabled)
- **`src/error.rs`** — `Error` enum with `thiserror`: `KeyRequired`, `WrongKey`, `NotDatabase`, `FileNotFound`, `CipherUnavailable`, `Closed`, `Sqlite`, `Io`
- **`src/verify.rs`** — `looks_plaintext()`, `can_open_with_key()`, `verify_cipher_metadata()`
- **`tests/integration.rs`** — 27 integration tests (ported from Go + Rust-specific additions)

## Key Design Decisions

- **Single `Mutex<Inner>` state**: one mutex guards both the connection and the key, preventing inconsistent intermediate states during close/rotate/Drop.
- **Key never in DSN**: the encryption key is stored in `SecretBox<Vec<u8>>` (from the `secrecy` crate) inside the `Database` struct. It's zeroed on drop via `zeroize`.
- **PRAGMA key (not raw FFI)**: key application uses `PRAGMA key = "x'hex'"` for simplicity and portability across SQLCipher versions.
- **Single-connection model**: `Database` owns one `rusqlite::Connection` behind a mutex — structural enforcement of the Go `MaxOpenConns(1)` pattern.
- **`with_connection` closure pattern**: callers get `&Connection` (or `&mut Connection` for transactions) without the reference escaping the lock.
- **Deterministic key zeroing**: `SecretBox` + `zeroize` on `Drop` replaces Go's best-effort manual zeroing. No GC copies — Rust's ownership model ensures the key lives in one place.
- **Idempotent `close()`**: all methods return `Error::Closed` after close. `Drop` is a safety net, not the primary close path.
