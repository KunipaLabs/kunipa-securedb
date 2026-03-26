# Low-Priority Audit Findings — 2026-03-26

Remaining items from the security/quality audit. None are urgent.

## L1 — `stmt.NumInput()` lacks locking

`stmt.go`: `NumInput()` calls `sqlite3_bind_parameter_count` without holding
`conn.mu`. `database/sql` may call this from any goroutine. While the C function
is likely safe on a valid statement, it is inconsistent with locking discipline.

## L2 — `stmt.Close()` discards finalize return code

`stmt.go`: `sqlite3_finalize()` return code is ignored. This is common SQLite
practice (finalize still succeeds), but logging could surface hidden issues.

## L3 — No `len(dest)` validation in `rows.Next()`

`rows.go`: `Next()` iterates `len(dest)` without verifying it matches the column
count. The `database/sql` layer ensures correct sizing, but a defensive check
would prevent undefined C behavior if the driver is used directly.

## L4 — Test coverage for type bindings

Missing explicit tests for: `[]byte` (blob), `float64`, `bool`, `nil` binding,
unsupported type error path, `BeginTx` with non-default isolation (error path),
`ExecContext` with parameterized arguments.

## L5 — `execLocked` naming

`conn.go`: The name `execLocked` suggests it acquires a lock, but the caller
must hold `c.mu`. Consider renaming to `execUnlocked` or documenting more
prominently that the lock is the caller's responsibility.
