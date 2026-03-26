package securedb

// tx implements driver.Tx.
type tx struct {
	conn *conn
}

// Commit commits the transaction.
func (t *tx) Commit() error {
	t.conn.mu.Lock()
	defer t.conn.mu.Unlock()

	if t.conn.closed {
		return ErrClosed
	}
	return t.conn.execRaw("COMMIT")
}

// Rollback aborts the transaction.
func (t *tx) Rollback() error {
	t.conn.mu.Lock()
	defer t.conn.mu.Unlock()

	if t.conn.closed {
		return ErrClosed
	}
	return t.conn.execRaw("ROLLBACK")
}
