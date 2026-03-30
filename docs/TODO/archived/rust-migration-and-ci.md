# TODO: Rust Migration, CI, and Security Audit

**Branch**: `rust-reimplementation`
**Origin**: Deferred items from `docs/TODO/archived/rust-reimplementation.md`

## CI Pipeline

- [ ] Set up GitHub Actions workflow:
  - `cargo build`
  - `cargo build --features system-sqlcipher --no-default-features`
  - `cargo test`
  - `cargo clippy -- -D warnings`
  - `cargo audit`
  - `cargo fmt -- --check`

## Security Audit

- [ ] Security audit of the Rust implementation (equivalent to
      `docs/archived/audit-2026-03-26.md` for Go)

## Migration

- [ ] Relocate Go `main` branch to `main-go` or `archived-main-go`
- [ ] Merge `rust-reimplementation` into `main` after verification
- [ ] Update KunipaMail to use the Rust crate
- [ ] Update KunipaLedger to use the Rust crate

## Prerequisites (External)

- [ ] Finalize backup API strategy (see `kunipachronos-internal` repo,
      `docs/TODO/adr-strategie-backup-kunipa.md`)
