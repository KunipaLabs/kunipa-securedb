package securedb

/*
#include "securedb.h"
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"runtime"
	"time"
	"unsafe"
)

// connector implements driver.Connector.
// It captures the key and options in a closure so the key never appears in a DSN string.
// Every call to Connect() applies the key atomically via securedb_open().
type connector struct {
	path        string
	key         []byte
	flags       C.int
	busyTimeout time.Duration
	wal         bool
}

// Connect opens a new connection to the database.
// The encryption key is applied atomically on every physical connection.
func (cn *connector) Connect(_ context.Context) (driver.Conn, error) {
	cPath := C.CString(cn.path)
	defer C.free(unsafe.Pointer(cPath))

	var cKey *C.char
	var cKeyLen C.int
	if len(cn.key) > 0 {
		cKey = (*C.char)(unsafe.Pointer(&cn.key[0]))
		cKeyLen = C.int(len(cn.key))
	}

	var db *C.sqlite3
	rc := C.securedb_open(cPath, cKey, cKeyLen, cn.flags, &db)
	runtime.KeepAlive(cn.key) // prevent GC from moving key during C call
	if rc != C.SQLITE_OK {
		if rc == C.SQLITE_NOTADB {
			if len(cn.key) > 0 {
				return nil, ErrWrongKey
			}
			return nil, ErrNotDatabase
		}
		errMsg := "unknown error"
		if db != nil {
			errMsg = C.GoString(C.securedb_errmsg(db))
		}
		return nil, fmt.Errorf("securedb: open: [%d] %s", int(rc), errMsg)
	}

	c := &conn{db: db}

	// Apply per-connection PRAGMAs.
	if cn.busyTimeout > 0 {
		ms := int(cn.busyTimeout / time.Millisecond)
		if err := c.execLocked(fmt.Sprintf("PRAGMA busy_timeout = %d", ms)); err != nil {
			C.securedb_close(db)
			return nil, fmt.Errorf("securedb: set busy_timeout: %w", err)
		}
	}

	if cn.wal {
		if err := c.execLocked("PRAGMA journal_mode = WAL"); err != nil {
			C.securedb_close(db)
			return nil, fmt.Errorf("securedb: set journal_mode: %w", err)
		}
	}

	if err := c.execLocked("PRAGMA foreign_keys = ON"); err != nil {
		C.securedb_close(db)
		return nil, fmt.Errorf("securedb: set foreign_keys: %w", err)
	}

	return c, nil
}

// Driver returns the underlying driver (required by driver.Connector).
func (cn *connector) Driver() driver.Driver {
	return &securedbDriver{}
}

// securedbDriver implements driver.Driver.
// It is only used as a fallback — the primary path is via connector.
type securedbDriver struct{}

// Open is required by driver.Driver but should not be used directly.
// Use sql.OpenDB(connector) instead.
func (d *securedbDriver) Open(_ string) (driver.Conn, error) {
	return nil, fmt.Errorf("securedb: driver.Open not supported; use sql.OpenDB")
}

// registerDriver returns an *sql.DB backed by the connector.
func registerDriver(cn *connector) *sql.DB {
	return sql.OpenDB(cn)
}
