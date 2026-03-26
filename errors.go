package securedb

import "errors"

// Sentinel errors for diagnostic-rich error handling.
var (
	// ErrKeyRequired is returned when EncryptionRequired is set but no key is provided.
	ErrKeyRequired = errors.New("securedb: encryption required but no key provided")

	// ErrWrongKey is returned when the provided key cannot decrypt the database.
	ErrWrongKey = errors.New("securedb: wrong encryption key")

	// ErrNotDatabase is returned when the file is not a valid SQLite/SQLCipher database.
	ErrNotDatabase = errors.New("securedb: file is not a valid SQLite/SQLCipher database")

	// ErrFileNotFound is returned when the database file does not exist and
	// CreateIfMissing is false.
	ErrFileNotFound = errors.New("securedb: database file not found")

	// ErrCipherUnavailable is returned when SQLCipher is not available in this build.
	ErrCipherUnavailable = errors.New("securedb: SQLCipher not available in this build")

	// ErrClosed is returned when an operation is attempted on a closed connection.
	ErrClosed = errors.New("securedb: connection is closed")
)
