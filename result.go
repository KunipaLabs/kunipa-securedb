package securedb

// result implements driver.Result.
type result struct {
	lastID       int64
	rowsAffected int64
}

// LastInsertId returns the database's auto-generated ID after an insert.
func (r *result) LastInsertId() (int64, error) {
	return r.lastID, nil
}

// RowsAffected returns the number of rows affected by the query.
func (r *result) RowsAffected() (int64, error) {
	return r.rowsAffected, nil
}
