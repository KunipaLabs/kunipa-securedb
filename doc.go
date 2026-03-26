// Package securedb provides a minimal database/sql driver for SQLCipher.
//
// It solves a fundamental ordering issue in mattn/go-sqlite3: the ConnectHook
// executes AFTER internal setup (busy_timeout, sqlite_master read), so PRAGMA key
// arrives too late on an encrypted database. This package calls sqlite3_key()
// atomically right after sqlite3_open_v2(), before any other operation.
//
// This package is intentionally limited in scope. It implements only the
// database/sql/driver interfaces needed by KunipaMail and KunipaLedger.
// It does NOT aim to be a general-purpose replacement for go-sqlite3.
//
// Supported types: TEXT, INTEGER, REAL, BLOB, NULL.
// Not supported: named parameters, savepoints, backup API, custom functions.
//
// Limitation: context cancellation is not propagated to the C layer.
// Operations will complete regardless of context deadlines or cancellation.
// With MaxOpenConns(1) and local I/O, this is unlikely to cause issues.
//
// Limitation: key zeroing on Close is best-effort. Go's garbage collector may
// copy the key's backing array during heap compaction; prior copies are
// unreachable and cannot be zeroed. See connector.Close documentation.
//
// Build requirements:
//
//	# Debian/Ubuntu
//	sudo apt-get install libsqlcipher-dev
//
//	# macOS (Apple Silicon — default Homebrew prefix)
//	brew install sqlcipher
//
// On Intel Macs, Homebrew installs to /usr/local/opt/sqlcipher instead of
// /opt/homebrew/opt/sqlcipher. Set CGO_CFLAGS and CGO_LDFLAGS manually
// or use pkg-config in that case.
//
// Coexistence with mattn/go-sqlite3:
//
// This package is autonomous — it does NOT import mattn/go-sqlite3. It implements
// its own database/sql/driver interfaces directly against the SQLite/SQLCipher C API.
// Consumer binaries (KunipaMail, KunipaLedger) can also import mattn/go-sqlite3 for
// legacy or test usage. The two drivers coexist without conflict:
//   - mattn/go-sqlite3 registers as driver "sqlite3"
//   - kunipa-securedb registers with a unique name per instance ("securedb-{uuid}")
//   - No cross-dependency between the two
package securedb

// #cgo CFLAGS: -I/usr/include/sqlcipher -DSQLITE_HAS_CODEC
// #cgo LDFLAGS: -lsqlcipher
// #cgo darwin CFLAGS: -I/opt/homebrew/opt/sqlcipher/include -DSQLITE_HAS_CODEC
// #cgo darwin LDFLAGS: -L/opt/homebrew/opt/sqlcipher/lib -lsqlcipher
// #cgo windows CFLAGS: -DSQLITE_HAS_CODEC
import "C"
