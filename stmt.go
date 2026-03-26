package securedb

/*
#include "securedb.h"
*/
import "C"

import (
	"database/sql/driver"
	"fmt"
)

// stmt implements driver.Stmt.
type stmt struct {
	conn *conn
	s    *C.sqlite3_stmt
}

// Close finalizes the prepared statement.
// Note: sqlite3_finalize() always deallocates the statement. The return code
// reflects the last sqlite3_step() evaluation, not a cleanup failure.
func (st *stmt) Close() error {
	st.conn.mu.Lock()
	defer st.conn.mu.Unlock()

	if st.s == nil {
		return nil
	}
	rc := C.sqlite3_finalize(st.s)
	st.s = nil

	if rc != C.SQLITE_OK {
		return fmt.Errorf("securedb: finalize: sqlite error %d", int(rc))
	}
	return nil
}

// NumInput returns the number of placeholder parameters.
func (st *stmt) NumInput() int {
	st.conn.mu.Lock()
	defer st.conn.mu.Unlock()

	if st.s == nil {
		return 0
	}
	return int(C.sqlite3_bind_parameter_count(st.s))
}

// Exec executes a prepared statement with the given arguments.
func (st *stmt) Exec(args []driver.Value) (driver.Result, error) {
	named := make([]driver.NamedValue, len(args))
	for i, v := range args {
		named[i] = driver.NamedValue{Ordinal: i + 1, Value: v}
	}

	st.conn.mu.Lock()
	defer st.conn.mu.Unlock()

	if st.conn.closed {
		return nil, ErrClosed
	}

	C.sqlite3_reset(st.s)
	C.sqlite3_clear_bindings(st.s)

	if err := bindArgs(st.s, named); err != nil {
		return nil, err
	}

	rc := C.sqlite3_step(st.s)
	if rc != C.SQLITE_DONE && rc != C.SQLITE_ROW {
		return nil, st.conn.lastError("stmt exec")
	}

	rowsAffected := int64(C.sqlite3_changes(st.conn.db))
	lastID := int64(C.sqlite3_last_insert_rowid(st.conn.db))
	return &result{lastID: lastID, rowsAffected: rowsAffected}, nil
}

// Query executes a prepared statement with the given arguments and returns rows.
func (st *stmt) Query(args []driver.Value) (driver.Rows, error) {
	named := make([]driver.NamedValue, len(args))
	for i, v := range args {
		named[i] = driver.NamedValue{Ordinal: i + 1, Value: v}
	}

	st.conn.mu.Lock()
	defer st.conn.mu.Unlock()

	if st.conn.closed {
		return nil, ErrClosed
	}

	C.sqlite3_reset(st.s)
	C.sqlite3_clear_bindings(st.s)

	if err := bindArgs(st.s, named); err != nil {
		return nil, err
	}

	colCount := int(C.sqlite3_column_count(st.s))
	cols := make([]string, colCount)
	for i := 0; i < colCount; i++ {
		cols[i] = C.GoString(C.sqlite3_column_name(st.s, C.int(i)))
	}

	return &rows{
		conn:   st.conn,
		s:      st.s,
		cols:   cols,
		owned:  false, // stmt owns the sqlite3_stmt, not rows
	}, nil
}
