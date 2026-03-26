package securedb

/*
#include "securedb.h"
#include <stdlib.h>

// SQLITE_TRANSIENT_PTR is a helper because cgo cannot represent the
// SQLITE_TRANSIENT macro ((sqlite3_destructor_type)-1) directly.
static int securedb_bind_text(sqlite3_stmt *stmt, int idx, const char *val, int n) {
    return sqlite3_bind_text(stmt, idx, val, n, SQLITE_TRANSIENT);
}

static int securedb_bind_blob(sqlite3_stmt *stmt, int idx, const void *val, int n) {
    return sqlite3_bind_blob(stmt, idx, val, n, SQLITE_TRANSIENT);
}
*/
import "C"

import (
	"context"
	"database/sql/driver"
	"fmt"
	"sync"
	"unsafe"
)

// conn implements driver.Conn, driver.ExecerContext, and driver.QueryerContext.
type conn struct {
	db     *C.sqlite3
	mu     sync.Mutex
	closed bool
}

// Prepare returns a prepared statement bound to this connection.
func (c *conn) Prepare(query string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), query)
}

// PrepareContext returns a prepared statement bound to this connection.
func (c *conn) PrepareContext(_ context.Context, query string) (driver.Stmt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, ErrClosed
	}

	cQuery := C.CString(query)
	defer C.free(unsafe.Pointer(cQuery))

	var cStmt *C.sqlite3_stmt
	rc := C.sqlite3_prepare_v2(c.db, cQuery, C.int(len(query)), &cStmt, nil)
	if rc != C.SQLITE_OK {
		return nil, c.lastError("prepare")
	}

	return &stmt{
		conn: c,
		s:    cStmt,
	}, nil
}

// Close closes the connection.
func (c *conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	// Capture error message BEFORE closing — the handle may be
	// invalid after sqlite3_close_v2 returns.
	var errMsg string
	rc := C.securedb_close(c.db)
	if rc != C.SQLITE_OK {
		errMsg = fmt.Sprintf("securedb: close: [%d]", int(rc))
	}
	c.db = nil

	if errMsg != "" {
		return fmt.Errorf("%s", errMsg)
	}
	return nil
}

// Begin starts a transaction.
func (c *conn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

// BeginTx starts a transaction with context and options.
// SQLite does not support isolation levels — only the default level is accepted.
func (c *conn) BeginTx(_ context.Context, opts driver.TxOptions) (driver.Tx, error) {
	// Reject non-default isolation levels (SQLite has a single isolation model).
	if opts.Isolation != 0 { // 0 = driver.IsolationLevel default
		return nil, fmt.Errorf("securedb: unsupported isolation level %d; SQLite uses serializable transactions", opts.Isolation)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, ErrClosed
	}

	beginSQL := "BEGIN"
	if opts.ReadOnly {
		beginSQL = "BEGIN DEFERRED"
	}

	if err := c.execLocked(beginSQL); err != nil {
		return nil, err
	}

	return &tx{conn: c}, nil
}

// ExecContext executes a query that doesn't return rows.
func (c *conn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, ErrClosed
	}

	if len(args) == 0 {
		// Fast path: no arguments, use sqlite3_exec.
		if err := c.execLocked(query); err != nil {
			return nil, err
		}
		rowsAffected := int64(C.sqlite3_changes(c.db))
		lastID := int64(C.sqlite3_last_insert_rowid(c.db))
		return &result{lastID: lastID, rowsAffected: rowsAffected}, nil
	}

	// Slow path: prepare + bind + step.
	cQuery := C.CString(query)
	defer C.free(unsafe.Pointer(cQuery))

	var cStmt *C.sqlite3_stmt
	rc := C.sqlite3_prepare_v2(c.db, cQuery, C.int(len(query)), &cStmt, nil)
	if rc != C.SQLITE_OK {
		return nil, c.lastError("exec prepare")
	}
	defer C.sqlite3_finalize(cStmt)

	if err := bindArgs(cStmt, args); err != nil {
		return nil, err
	}

	rc = C.sqlite3_step(cStmt)
	if rc != C.SQLITE_DONE && rc != C.SQLITE_ROW {
		return nil, c.lastError("exec step")
	}

	rowsAffected := int64(C.sqlite3_changes(c.db))
	lastID := int64(C.sqlite3_last_insert_rowid(c.db))
	return &result{lastID: lastID, rowsAffected: rowsAffected}, nil
}

// QueryContext executes a query that returns rows.
func (c *conn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, ErrClosed
	}

	cQuery := C.CString(query)
	defer C.free(unsafe.Pointer(cQuery))

	var cStmt *C.sqlite3_stmt
	rc := C.sqlite3_prepare_v2(c.db, cQuery, C.int(len(query)), &cStmt, nil)
	if rc != C.SQLITE_OK {
		return nil, c.lastError("query prepare")
	}

	if err := bindArgs(cStmt, args); err != nil {
		C.sqlite3_finalize(cStmt)
		return nil, err
	}

	// Determine column count and names.
	colCount := int(C.sqlite3_column_count(cStmt))
	cols := make([]string, colCount)
	for i := 0; i < colCount; i++ {
		cols[i] = C.GoString(C.sqlite3_column_name(cStmt, C.int(i)))
	}

	return &rows{
		conn:  c,
		s:     cStmt,
		cols:  cols,
		owned: true, // rows from QueryContext own the stmt
	}, nil
}

// execLocked executes a simple SQL statement without arguments.
// Caller must hold c.mu.
func (c *conn) execLocked(sql string) error {
	cSQL := C.CString(sql)
	defer C.free(unsafe.Pointer(cSQL))

	rc := C.sqlite3_exec(c.db, cSQL, nil, nil, nil)
	if rc != C.SQLITE_OK {
		return c.lastError("exec")
	}
	return nil
}

// lastError returns an error from the database handle's last error message.
func (c *conn) lastError(op string) error {
	msg := C.GoString(C.securedb_errmsg(c.db))
	code := int(C.securedb_errcode(c.db))

	// Map specific SQLite error codes to sentinel errors.
	if code == C.SQLITE_NOTADB {
		return fmt.Errorf("%w: %s", ErrNotDatabase, msg)
	}

	return fmt.Errorf("securedb: %s: [%d] %s", op, code, msg)
}

// bindArgs binds driver.NamedValue arguments to a prepared statement.
func bindArgs(s *C.sqlite3_stmt, args []driver.NamedValue) error {
	for _, arg := range args {
		idx := C.int(arg.Ordinal)

		var rc C.int
		switch v := arg.Value.(type) {
		case nil:
			rc = C.sqlite3_bind_null(s, idx)
		case int64:
			rc = C.sqlite3_bind_int64(s, idx, C.sqlite3_int64(v))
		case float64:
			rc = C.sqlite3_bind_double(s, idx, C.double(v))
		case bool:
			if v {
				rc = C.sqlite3_bind_int64(s, idx, 1)
			} else {
				rc = C.sqlite3_bind_int64(s, idx, 0)
			}
		case string:
			cVal := C.CString(v)
			rc = C.securedb_bind_text(s, idx, cVal, C.int(len(v)))
			C.free(unsafe.Pointer(cVal))
		case []byte:
			if len(v) == 0 {
				rc = C.sqlite3_bind_zeroblob(s, idx, 0)
			} else {
				rc = C.securedb_bind_blob(s, idx, unsafe.Pointer(&v[0]), C.int(len(v)))
			}
		default:
			return fmt.Errorf("securedb: unsupported type %T for parameter %d", v, arg.Ordinal)
		}

		if rc != C.SQLITE_OK {
			return fmt.Errorf("securedb: bind parameter %d failed: sqlite error %d", arg.Ordinal, int(rc))
		}
	}
	return nil
}
