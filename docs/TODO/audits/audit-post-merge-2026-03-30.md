# Post-Merge Audit: kunipa-securedb Rust Crate

**Date**: 2026-03-30
**Branch**: `main` (post-merge from `rust-reimplementation`)
**Commit**: `9171369`
**Auditor**: Senior Code Reviewer (automated)
**Scope**: Full source review of `src/`, `tests/`, `Cargo.toml`, `.github/workflows/ci.yml`
**Prior audits**: `audit-security-rust-2026-03-30.md`, `audit-rust-reimplementation.md`

## Executive Summary

Post-merge review following `rust-reimplementation` → `main` merge. All prior
Critical and High findings remain resolved. **Zero new Critical or High findings.**
Six Medium and five Low findings identified (mix of carried-over and new).

Overall assessment: **Good** — production-ready for its intended scope.

## Findings

### Critical — None

Prior C1 (key not zeroed) and C2 (SQL injection in rotate_key) confirmed fixed.

### High — None

Prior H2 (poisoned mutex), H3 (read_only+create_if_missing), H4 (disabled+key)
confirmed fixed.

### Medium

| ID | Status | Finding | File | Recommendation |
|----|--------|---------|------|----------------|
| M1 | Carried | `set_permissions` failure silently ignored | `connection.rs:219` | Propagate error or document as best-effort |
| M2 | Carried | `is_memory_path` only checks `:memory:` literal | `connection.rs:282` | Document that URI forms (`file::memory:`) are unsupported |
| M3 | Carried | `PartialEq for Error` incomplete (`Sqlite`/`Io` always `false`) | `error.rs:81-96` | Remove `PartialEq` or document limitation |
| M4 | New | `available()` copies key via `.to_vec()` before wrapping | `lib.rs:60` | Negligible risk (diagnostic fn, random key, in-memory) |
| M5 | New | `SQLITE_OPEN_NO_MUTEX` flag undocumented re: mutex invariant | `connection.rs:225` | Add safety comment explaining the invariant |
| M6 | New | `system-sqlcipher` feature referenced in CLAUDE.md but absent from Cargo.toml | `Cargo.toml` | Add feature or remove doc reference |

### Low

| ID | Status | Finding | Recommendation |
|----|--------|---------|----------------|
| L1 | Carried | `#[allow(dead_code)]` on `flags`, `busy_timeout`, `wal` | Remove if reconnection not planned |
| L2 | New | `close()` takes `&self` not `self` | Document rationale (Arc shared ownership) |
| L3 | New | No MSRV declared; edition 2024 requires Rust 1.85+ | Add `rust-version = "1.85"` to Cargo.toml |
| L4 | Carried | No concurrent/poisoned-mutex tests | Add at least one multi-threaded test |
| L5 | New | `open()` accepts `&str` not `AsRef<Path>` | Low priority for Tauri apps (UTF-8 paths) |

### Info (Positive)

- **I1**: Key handling correct — `SecretBox<Zeroizing<Vec<u8>>>` with hex via `std::fmt::Write`
- **I2**: Atomic key application correct — PRAGMA key → sqlite_master probe → PRAGMAs
- **I3**: Single `Mutex<Option<Inner>>` pattern prevents inconsistent state
- **I4**: `Drop` uses `get_mut()` to avoid locking — correct
- **I5**: `map_sqlite_error` correctly distinguishes WrongKey from NotDatabase
- **I6**: 27 integration tests provide strong functional coverage
- **I7**: CI pipeline covers format, clippy, test, and cargo audit

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 6 |
| Low | 5 |
| Info | 7 |

## Prioritized Recommendations

1. **M6**: Fix `system-sqlcipher` feature discrepancy (doc accuracy)
2. **M5**: Add safety comment on `SQLITE_OPEN_NO_MUTEX` (maintenance safety)
3. **M1**: Decide on `set_permissions` error handling strategy
4. **L4**: Add concurrent access test
5. **M2**: Document `:memory:` limitation
6. **L3**: Add MSRV to Cargo.toml
