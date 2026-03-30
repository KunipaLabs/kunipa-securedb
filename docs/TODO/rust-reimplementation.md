# TODO: Rust Reimplementation of kunipa-securedb

**Branch**: `rust-reimplementation`
**ADR**: `docs/adr-rust-reimplementation.md`
**Origin**: Archived from `docs/TODO/archived/reimplementation_guidee.md`

## Prerequisites

- [ ] Finalize backup API strategy (see `kunipachronos-internal` repo,
      `docs/TODO/adr-strategie-backup-kunipa.md`)
- [ ] Install Rust toolchain and `sqlcipher` dev headers on build machine
- [ ] Review Go security audit lessons (`docs/archived/audit-2026-03-26.md`)
      to inform Rust design

## Development

- [ ] Initialize Cargo project on `rust-reimplementation` branch
- [ ] Implement atomic open + key sequence (FFI wrapper or `rusqlite` +
      `bundled-sqlcipher`)
- [ ] Implement key zeroing with `zeroize` / `secrecy` crates (defensive
      copy on construction — Rust ownership may simplify this)
- [ ] Design `Options` / configuration API (`EncryptionMode`, `ReadOnly`,
      `CreateIfMissing`, `BusyTimeout`, `WAL`, in-memory path handling)
- [ ] Implement per-connection PRAGMAs (`busy_timeout`, `journal_mode = WAL`,
      `foreign_keys = ON`)
- [ ] Design error type enum (equivalent to Go sentinel errors:
      `ErrKeyRequired`, `ErrWrongKey`, `ErrNotDatabase`, `ErrFileNotFound`,
      `ErrCipherUnavailable`, `ErrClosed`)
- [ ] Port `Available()` function (runtime SQLCipher support check)
- [ ] Port verification utilities (`LooksPlaintext`, `CanOpenWithKey`,
      `VerifyCipherMetadata`)
- [ ] Port `RotateKey` functionality
- [ ] Design single-connection enforcement (equivalent to Go's
      `MaxOpenConns(1)` default)
- [ ] Write test suite (equivalent coverage to current Go tests)
- [ ] Set up CI pipeline (`cargo build`, `cargo test`, `cargo clippy`,
      `cargo audit`)
- [ ] Security audit of the Rust implementation

## Migration

- [ ] Relocate Go `main` branch to `main-go` or `archived-main-go`
- [ ] Merge `rust-reimplementation` into `main` after verification
- [ ] Update `CLAUDE.md` to describe Rust architecture
- [ ] Update KunipaMail and KunipaLedger to use the Rust crate
