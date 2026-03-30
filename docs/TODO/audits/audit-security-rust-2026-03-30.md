# Security Audit: kunipa-securedb Rust Crate

**Date**: 2026-03-30
**Branch**: `rust-reimplementation`
**Commit**: `e226bcc`
**Auditor**: Senior Security Reviewer (automated)
**Scope**: Full source review of `src/`, `tests/`, and `Cargo.toml`

## Executive Summary

The crate is well-designed for its purpose. The single-mutex `Inner` pattern,
closure-based connection access, and `SecretBox<Zeroizing<Vec<u8>>>` key type
form a solid foundation. All Critical and High findings from the previous audit
have been resolved. This audit identifies **zero new Critical or High findings**.

Overall security posture: **Good** — suitable for production use in its stated
scope (single-connection SQLCipher wrapper for Tauri desktop applications).

## Status of Previous Audit Findings

### Previously Resolved (Confirmed Fixed)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| C1 | Critical | Key material not zeroed on drop | Fixed |
| C2 | Critical | SQL injection in `rotate_key` via `format!()` | Fixed |
| H2 | High | Poisoned mutex mapped to `Error::Closed` | Fixed |
| H3 | High | `read_only + create_if_missing` silently accepted | Fixed |
| H4 | High | `Disabled` with key silently ignored | Fixed |
| M2 | Medium | Redundant `sqlite_master` query in `can_open_with_key` | Fixed |
| M4 | Medium | `busy_timeout` truncation | Fixed |
| L5 | Low | Missing `#[must_use]` on `close()` | Fixed |
| L2 | Low | Missing `Send + Sync` documentation | Fixed |

## Resolved in This Audit

### M-NEW-1 (Medium, Fixed): `hex_key` Intermediate Allocations Not Zeroed

**File**: `src/connection.rs`

Each `format!("{:02x}", b)` call allocated a small `String` per byte. These
intermediates were dropped without zeroing, leaving hex fragments on the heap.

**Fix**: Replaced with a single pre-allocated `Zeroizing<String>` written via
`std::fmt::Write`, eliminating intermediate allocations entirely.

### M-NEW-2 (Medium, Fixed): No Minimum Key Length Validation

**File**: `src/connection.rs`

Both `open_database` and `rotate_key` accepted any non-empty key, including
1-byte keys with negligible security.

**Fix**: Added `MIN_KEY_LEN = 16` constant. Both paths now reject keys shorter
than 16 bytes with `Error::InvalidOptions`.

## Deferred Findings

### Medium

- **M-NEW-3**: `set_permissions` on parent directory ignores errors silently
  (`let _ =`). On shared systems the database file could be created in a
  world-readable directory. Recommendation: propagate or document.

- **M-1** (carried over): `PartialEq` for `Error` incomplete — `Sqlite` and
  `Io` variants always return `false`. Recommendation: document or remove
  `PartialEq` in favor of `is_*` methods.

- **M-2** (carried over): `is_memory_path` only checks `:memory:` literal.
  SQLite also recognizes `file::memory:` and URI forms. Recommendation: document
  that only `:memory:` is supported.

### Low

- **L-NEW-1**: `available()` creates a transient key copy via `.to_vec()` before
  wrapping in `SecureKey`. Minimal impact (diagnostic function, throwaway random
  key on in-memory database).

- **L-NEW-2**: No `#![deny(unsafe_op_in_unsafe_fn)]` lint enabled. The single
  `unsafe` block (`sqlite3_randomness`) is correct but the lint would improve
  auditability.

- **L-1** (carried over): `#[allow(dead_code)]` on `Database` fields (`flags`,
  `busy_timeout`, `wal`).

- **L-3** (carried over): Test helper `test_key_raw()` returns unzeroed
  `Vec<u8>`. Acceptable for test code.

- **L-4** (carried over): No concurrent/poisoned-mutex tests.

### Test Coverage Gaps

- Concurrent `with_connection` + `close` from multiple threads
- Poisoned mutex simulation (panic inside `with_connection`)
- `rotate_key` followed by `Drop` without explicit `close`
- Non-standard key lengths (< 16 bytes, > 32 bytes)
- `rotate_key` with empty key
- Unicode / special characters in database path

## Unsafe Code Review

One `unsafe` block in production code (`src/lib.rs` line 50): call to
`sqlite3_randomness`. Correct — well-defined C API, buffer correctly sized,
length cast safe for 32 bytes. Same pattern in test code, also safe.

No other `unsafe` blocks. `rusqlite` handles all SQLCipher FFI internally.

## Cryptographic Correctness

- `PRAGMA key`/`rekey` use `pragma_update` with `x'<hex>'` format (raw key
  bytes, not passphrase). Correct.
- `SELECT count(*) FROM sqlite_master` probe immediately after keying. Correct.
- Stored key updated only after successful rekey. Correct.
- Hex strings wrapped in `Zeroizing<String>`. Correct.

## Dependency Assessment

| Dependency | Version | Risk |
|-----------|---------|------|
| `rusqlite` | 0.33 (`bundled-sqlcipher`) | Low |
| `zeroize` | 1.x | Low |
| `secrecy` | 0.10 | Low |
| `thiserror` | 2.x | Low (compile-time only) |
| `tempfile` | 3.x (dev) | N/A |

`cargo audit` reports no known vulnerabilities (verified 2026-03-30).

## Conclusion

Strong security posture. Atomic key application, deterministic zeroing,
single-mutex state, correct PRAGMA usage. All prior Critical/High findings
confirmed fixed. Two new Medium findings resolved in this cycle (hex_key
intermediates, minimum key length). Remaining Medium/Low items are documented
for future work.
