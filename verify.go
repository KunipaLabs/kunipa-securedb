package securedb

import (
	"database/sql"
	"fmt"
	"os"
)

// sqliteHeaderMagic is the first 16 bytes of an unencrypted SQLite database file.
const sqliteHeaderMagic = "SQLite format 3\x00"

// LooksPlaintext checks if a file starts with the SQLite plaintext header.
// Returns true if the file is an unencrypted SQLite database.
// Returns false if the file does not exist or does not match.
func LooksPlaintext(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("securedb: open file: %w", err)
	}
	defer f.Close()

	header := make([]byte, 16)
	n, err := f.Read(header)
	if err != nil || n < 16 {
		return false, nil
	}

	return string(header) == sqliteHeaderMagic, nil
}

// CanOpenWithKey attempts to open the database with the given key,
// verifies it can read, then closes. Returns a typed error on failure.
//
// Possible errors:
//   - ErrFileNotFound: file does not exist
//   - ErrWrongKey: key cannot decrypt the database
//   - ErrNotDatabase: file is not a valid SQLite/SQLCipher database
//   - ErrCipherUnavailable: SQLCipher not available
func CanOpenWithKey(path string, key []byte) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return ErrFileNotFound
	}

	noCreate := false
	db, err := Open(path, Options{
		Key:             key,
		Encryption:      EncryptionRequired,
		CreateIfMissing: &noCreate,
		ReadOnly:        true,
	})
	if err != nil {
		return err
	}
	defer db.Close()

	// Double-check: try to read.
	var count int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&count); err != nil {
		return fmt.Errorf("%w: verification query failed", ErrWrongKey)
	}

	return nil
}

// VerifyCipherMetadata checks that PRAGMA cipher_version returns a valid
// version string on an open database. Returns the version on success.
func VerifyCipherMetadata(db *sql.DB) (string, error) {
	var version string
	err := db.QueryRow("PRAGMA cipher_version").Scan(&version)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrCipherUnavailable, err)
	}
	if version == "" {
		return "", ErrCipherUnavailable
	}
	return version, nil
}
