package securedb

/*
#include "securedb.h"
*/
import "C"

import (
	"database/sql/driver"
	"fmt"
	"io"
	"unsafe"
)

// rows implements driver.Rows.
type rows struct {
	conn  *conn
	s     *C.sqlite3_stmt
	cols  []string
	owned bool // if true, rows owns s and will finalize it on Close
}

// Columns returns the column names.
func (r *rows) Columns() []string {
	return r.cols
}

// Close finalizes the statement if owned.
// Note: sqlite3_finalize() always deallocates the statement. The return code
// reflects the last sqlite3_step() evaluation, not a cleanup failure.
func (r *rows) Close() error {
	if !r.owned {
		return nil
	}
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()

	if r.s == nil {
		return nil
	}
	rc := C.sqlite3_finalize(r.s)
	r.s = nil

	if rc != C.SQLITE_OK {
		return fmt.Errorf("securedb: finalize: sqlite error %d", int(rc))
	}
	return nil
}

// Next advances to the next row, populating dest with column values.
func (r *rows) Next(dest []driver.Value) error {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()

	if r.conn.closed {
		return ErrClosed
	}

	rc := C.sqlite3_step(r.s)
	if rc == C.SQLITE_DONE {
		return io.EOF
	}
	if rc != C.SQLITE_ROW {
		return r.conn.lastError("rows next")
	}

	if len(dest) != len(r.cols) {
		return fmt.Errorf("securedb: rows.Next: dest length %d does not match column count %d", len(dest), len(r.cols))
	}

	for i := 0; i < len(dest); i++ {
		ci := C.int(i)
		colType := C.sqlite3_column_type(r.s, ci)

		switch colType {
		case C.SQLITE_NULL:
			dest[i] = nil
		case C.SQLITE_INTEGER:
			dest[i] = int64(C.sqlite3_column_int64(r.s, ci))
		case C.SQLITE_FLOAT:
			dest[i] = float64(C.sqlite3_column_double(r.s, ci))
		case C.SQLITE_TEXT:
			n := C.sqlite3_column_bytes(r.s, ci)
			p := C.sqlite3_column_text(r.s, ci)
			dest[i] = C.GoStringN((*C.char)(unsafe.Pointer(p)), n)
		case C.SQLITE_BLOB:
			n := int(C.sqlite3_column_bytes(r.s, ci))
			if n == 0 {
				dest[i] = []byte{}
			} else {
				p := C.sqlite3_column_blob(r.s, ci)
				dest[i] = C.GoBytes(p, C.int(n))
			}
		default:
			dest[i] = nil
		}
	}

	return nil
}
