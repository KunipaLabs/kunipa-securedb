# Audit: Rust Reimplementation of kunipa-securedb

**Date**: 2026-03-30
**Branch**: `rust-reimplementation`
**Auditor**: Senior Code Reviewer (automated)

## Summary

The Rust reimplementation is well-structured with a single-mutex `Inner` pattern,
closure-based connection access, and deterministic key zeroing. All critical and
high-severity findings were resolved immediately. Medium and low findings are
tracked below for future work.

## Resolved Findings

### Critical (Fixed)

- **C1**: `zeroize` dependency was declared but never used — key material was
  not zeroed on drop. **Fix**: Key type changed to `SecretBox<Zeroizing<Vec<u8>>>`
  and hex-encoded key strings use `Zeroizing<String>`.

- **C2**: `rotate_key` used `execute_batch` with `format!()` string interpolation
  for `PRAGMA rekey` — SQL injection risk pattern. **Fix**: Changed to
  `pragma_update(None, "rekey", ...)` matching the `PRAGMA key` pattern.

### High (Fixed)

- **H2**: Poisoned mutex was silently mapped to `Error::Closed`. **Fix**: Added
  distinct `Error::Poisoned` variant.

- **H3**: `read_only + create_if_missing` was silently accepted. **Fix**: Added
  explicit validation returning `Error::InvalidOptions`.

- **H4**: `EncryptionMode::Disabled` with key provided was silently ignored.
  **Fix**: Now returns `Error::InvalidOptions`.

### Medium (Fixed)

- **M2**: Redundant `sqlite_master` query in `can_open_with_key` (already
  verified by `open()`). **Fix**: Removed redundant query.

- **M4**: `busy_timeout` truncation on `u128 -> i64` cast. **Fix**: Added
  `.min(i64::MAX as u128)` guard.

### Low (Fixed)

- **L5**: Missing `#[must_use]` on `Database::close()`. **Fix**: Added.

- **L2**: Missing `Send + Sync` documentation. **Fix**: Added static assertion
  and doc comment.

## Deferred Findings

### Medium

- **M1**: `PartialEq` for `Error` does not compare `Sqlite` or `Io` variants
  (catch-all returns `false`). Only sentinel variants support equality. Should
  be documented or replaced with dedicated `is_*` methods.

- **M3**: `is_memory_path` only checks `:memory:` literal. SQLite also supports
  `file::memory:` and `file::memory:?cache=shared` URI forms. Should document
  or extend.

- **M5**: `available()` key bytes use `Zeroizing<Vec<u8>>` but the `.to_vec()`
  call creates a transient copy before wrapping in `SecureKey`. Minor — the
  function is diagnostic-only.

### Low

- **L1**: `#[allow(dead_code)]` on `Database` fields (`flags`, `busy_timeout`,
  `wal`). Stored for potential future reconnection logic. Should be removed if
  reconnection is not planned.

- **L3**: Test helper `test_key_raw()` returns unzeroed `Vec<u8>`. Acceptable
  for test code but establishes a pattern of raw key handling.

- **L4**: No test for concurrent access to `with_connection` from multiple
  threads, nor for poisoned mutex behavior. The mutex is standard and
  well-tested, but a concurrent stress test would validate the error path.

### Test Coverage Gaps

- Concurrent `with_connection` + `close` from multiple threads
- Poisoned mutex simulation (panic inside `with_connection`)
- `rotate_key` followed by `Drop` without explicit `close`
- Non-32-byte keys (larger, smaller)
- Unicode / special characters in database path
- `EncryptionMode::Disabled` with key provided (now returns error — test needed)
- `read_only` + `create_if_missing` (now returns error — test needed)
