# ADR: Reimplementation of kunipa-securedb in Rust

**Status**: Implemented — development complete, pending migration and full security audit
**Date**: 2026-03-30
**Branch**: `rust-reimplementation`

## Context

KunipaMail and KunipaLedger are planned to migrate from Go + Wails to Rust +
Tauri. kunipa-securedb is chosen as the first reimplementation target because
of its small scope, high criticality, and shared usage by both applications.

The current Go implementation is production-ready, audited, and stable. This
migration is a strategic decision, not a reaction to deficiencies.

## Decision

Reimplement kunipa-securedb as a Rust crate wrapping SQLCipher with the same
atomic open-then-key guarantee the Go driver provides.

### Key requirements carried forward

- Atomic `sqlite3_open_v2()` + `sqlite3_key()` sequence (raison d'etre)
- Encryption key never in DSN / connection string
- Key zeroing on close (Rust's `Drop` + `Zeroize` trait improve on Go's
  best-effort approach)
- Per-connection PRAGMAs (`busy_timeout`, `journal_mode = WAL`,
  `foreign_keys = ON`) applied on every connection open
- Intentionally limited scope (no savepoints, backup API, custom functions,
  or interrupts — unless Tauri integration requires them). Note: the Go
  driver's "no named parameters" limitation is Go-specific; `rusqlite`
  supports both named and positional parameters natively

### Rust-specific considerations

- Use `rusqlite` with the `bundled-sqlcipher` feature, or link against system
  `libsqlcipher` via `pkg-config` (to be decided during development)
- Expose a safe API; keep `unsafe` confined to the FFI boundary
- Leverage `zeroize` crate for deterministic key erasure (replaces Go's
  best-effort manual key zeroing — see `docs/TODO/watch-runtime-secret.md`
  for the Go-side tracking of `runtime/secret`)
- Consider `secrecy` crate for type-level secret management

## Consequences

- The Go implementation remains on `main` (and later `main-go` / `archived-main-go`)
  until the Rust version is verified and merged
- Both KunipaMail and KunipaLedger will need their import paths updated once
  the Rust crate is ready
- The backup API strategy (tracked in `kunipachronos-internal`) should be
  finalized before or during Rust development to avoid rework
- Lessons from the Go security audit (`docs/archived/audit-2026-03-26.md`)
  — TOCTOU on key rotation, mutex discipline on finalize calls, defensive
  key copying — should inform the Rust design from the start
