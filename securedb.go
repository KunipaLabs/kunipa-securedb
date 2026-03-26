package securedb

/*
#include "securedb.h"
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"
)

// EncryptionMode indicates the security intent, distinct from the key itself.
type EncryptionMode int

const (
	// EncryptionRequired means a key MUST be provided, otherwise ErrKeyRequired is returned.
	// This is the default mode for production use.
	EncryptionRequired EncryptionMode = iota

	// EncryptionDisabled means the database is opened without encryption.
	// The Key field is ignored. For tests or migration only.
	EncryptionDisabled
)

// Options configures the opening of a SQLCipher database.
type Options struct {
	// Key is the raw binary encryption key (32 bytes recommended).
	// Ignored when Encryption is EncryptionDisabled.
	Key []byte

	// Encryption indicates whether encryption is required or disabled.
	// Default: EncryptionRequired.
	Encryption EncryptionMode

	// ReadOnly opens the database in read-only mode.
	ReadOnly bool

	// CreateIfMissing creates the database file if it does not exist.
	// Default: true (zero value creates).
	CreateIfMissing *bool

	// BusyTimeout is the busy timeout for the database.
	// Default: 5 seconds.
	BusyTimeout time.Duration

	// WAL enables Write-Ahead Logging journal mode.
	// Default: true (zero value enables).
	WAL *bool
}

func (o *Options) createIfMissing() bool {
	if o.CreateIfMissing == nil {
		return true
	}
	return *o.CreateIfMissing
}

func (o *Options) walEnabled() bool {
	if o.WAL == nil {
		return true
	}
	return *o.WAL
}

func (o *Options) busyTimeout() time.Duration {
	if o.BusyTimeout == 0 {
		return 5 * time.Second
	}
	return o.BusyTimeout
}

// isMemoryPath reports whether path requests an in-memory database.
func isMemoryPath(path string) bool {
	return path == ":memory:"
}

// Open opens a SQLCipher database with atomic key application.
//
// The special path ":memory:" creates a private in-memory database.
// In-memory databases ignore CreateIfMissing, WAL, and ReadOnly options.
//
// When Encryption is EncryptionRequired (default):
//   - Key must be non-nil, otherwise ErrKeyRequired is returned.
//   - Every physical connection receives the key via securedb_open().
//
// When Encryption is EncryptionDisabled:
//   - Key is ignored; the database is opened without encryption.
//
// MaxOpenConns(1) is enforced by default.
func Open(path string, opts Options) (*sql.DB, error) {
	cn, err := buildConnector(path, opts)
	if err != nil {
		return nil, err
	}

	db := registerDriver(cn)
	db.SetMaxOpenConns(1)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// buildConnector validates options and returns a configured connector.
func buildConnector(path string, opts Options) (*connector, error) {
	if opts.Encryption == EncryptionRequired && len(opts.Key) == 0 {
		return nil, ErrKeyRequired
	}

	inMemory := isMemoryPath(path)

	// File-based checks — skip for in-memory databases.
	if !inMemory {
		if !opts.createIfMissing() {
			if _, err := os.Stat(path); os.IsNotExist(err) {
				return nil, ErrFileNotFound
			}
		}

		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("securedb: create directory: %w", err)
		}
	}

	// Build SQLite open flags.
	flags := C.SQLITE_OPEN_NOMUTEX // we manage our own mutex
	if inMemory {
		// SQLite handles ":memory:" as a path — just need READWRITE|CREATE.
		flags |= C.SQLITE_OPEN_READWRITE | C.SQLITE_OPEN_CREATE
	} else if opts.ReadOnly {
		flags |= C.SQLITE_OPEN_READONLY
	} else {
		flags |= C.SQLITE_OPEN_READWRITE
		if opts.createIfMissing() {
			flags |= C.SQLITE_OPEN_CREATE
		}
	}

	// Copy key to prevent caller mutation.
	var key []byte
	if opts.Encryption == EncryptionRequired {
		key = make([]byte, len(opts.Key))
		copy(key, opts.Key)
	}

	return &connector{
		path:        path,
		key:         key,
		flags:       C.int(flags),
		busyTimeout: opts.busyTimeout(),
		wal:         !inMemory && opts.walEnabled(), // WAL is not applicable to in-memory databases
	}, nil
}

// Available verifies that the current binary supports SQLCipher by opening
// a temporary encrypted database and checking PRAGMA cipher_version.
func Available() error {
	tmpDir, err := os.MkdirTemp("", "securedb-check-*")
	if err != nil {
		return fmt.Errorf("securedb: create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	testPath := filepath.Join(tmpDir, "check.db")
	testKey := []byte("securedb-availability-check-key!") // 32 bytes

	db, err := Open(testPath, Options{
		Key:        testKey,
		Encryption: EncryptionRequired,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCipherUnavailable, err)
	}
	defer db.Close()

	var version string
	if err := db.QueryRow("PRAGMA cipher_version").Scan(&version); err != nil {
		return fmt.Errorf("%w: cipher_version query failed: %v", ErrCipherUnavailable, err)
	}
	if version == "" {
		return ErrCipherUnavailable
	}

	return nil
}

// RotateKey changes the encryption key of an open database.
// The database must have been opened with encryption enabled.
//
// IMPORTANT: After RotateKey succeeds, the caller MUST close the *sql.DB
// and re-open it with the new key. The internal connector still holds the old
// key, so any new physical connection created by the pool would fail.
// Pattern: RotateKey(db, newKey) → db.Close() → Open(path, Options{Key: newKey})
func RotateKey(db *sql.DB, newKey []byte) error {
	if len(newKey) == 0 {
		return fmt.Errorf("securedb: new key must not be empty")
	}

	// Copy to prevent caller mutation during the C call.
	keyCopy := make([]byte, len(newKey))
	copy(keyCopy, newKey)
	defer func() {
		for i := range keyCopy {
			keyCopy[i] = 0
		}
	}()

	rawConn, err := db.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("securedb: get connection: %w", err)
	}
	defer rawConn.Close()

	return rawConn.Raw(func(driverConn any) error {
		c, ok := driverConn.(*conn)
		if !ok {
			return fmt.Errorf("securedb: unexpected driver connection type %T", driverConn)
		}

		c.mu.Lock()
		defer c.mu.Unlock()

		cKey := (*C.char)(unsafe.Pointer(&keyCopy[0]))
		rc := C.securedb_rekey(c.db, cKey, C.int(len(keyCopy)))
		runtime.KeepAlive(keyCopy)
		if rc != C.SQLITE_OK {
			return c.lastError("rekey")
		}
		return nil
	})
}
