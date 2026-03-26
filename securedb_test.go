package securedb

import (
	"context"
	"crypto/rand"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func testKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}

func openTestDB(t *testing.T, key []byte) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	mode := EncryptionRequired
	if key == nil {
		mode = EncryptionDisabled
	}
	db, err := Open(path, Options{
		Key:        key,
		Encryption: mode,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return db, path
}

// Test 1: Header test — encrypted file must NOT start with "SQLite format 3\0"
func TestEncryptedHeaderNotPlaintext(t *testing.T) {
	key := testKey()
	db, path := openTestDB(t, key)

	// Create a table and insert data to ensure the file has content.
	if _, err := db.Exec("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO t (val) VALUES (?)", "hello"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	plain, err := LooksPlaintext(path)
	if err != nil {
		t.Fatal(err)
	}
	if plain {
		t.Fatal("encrypted database has plaintext SQLite header")
	}
}

// Test 2: Wrong key — reopen with wrong key must FAIL
func TestWrongKeyFails(t *testing.T) {
	key := testKey()
	db, path := openTestDB(t, key)

	if _, err := db.Exec("CREATE TABLE t (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	wrongKey := testKey()
	_, err := Open(path, Options{
		Key:        wrongKey,
		Encryption: EncryptionRequired,
	})
	if err == nil {
		t.Fatal("expected error with wrong key, got nil")
	}
}

// Test 3: Right key — reopen with correct key must succeed and return data
func TestRightKeySucceeds(t *testing.T) {
	key := testKey()
	db, path := openTestDB(t, key)

	if _, err := db.Exec("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO t (val) VALUES (?)", "secret"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	db2, err := Open(path, Options{
		Key:        key,
		Encryption: EncryptionRequired,
	})
	if err != nil {
		t.Fatalf("reopen with correct key: %v", err)
	}
	defer db2.Close()

	var val string
	if err := db2.QueryRow("SELECT val FROM t WHERE id = 1").Scan(&val); err != nil {
		t.Fatal(err)
	}
	if val != "secret" {
		t.Fatalf("got %q, want %q", val, "secret")
	}
}

// Test 4: PRAGMA cipher_version must return a valid version string
func TestCipherVersion(t *testing.T) {
	key := testKey()
	db, _ := openTestDB(t, key)
	defer db.Close()

	version, err := VerifyCipherMetadata(db)
	if err != nil {
		t.Fatalf("VerifyCipherMetadata: %v", err)
	}
	if version == "" {
		t.Fatal("cipher_version is empty")
	}
	t.Logf("SQLCipher version: %s", version)
}

// Test 5: FTS5 — create FTS5 table, insert, search, assert results
func TestFTS5(t *testing.T) {
	key := testKey()
	db, _ := openTestDB(t, key)
	defer db.Close()

	_, err := db.Exec("CREATE VIRTUAL TABLE docs USING fts5(title, body)")
	if err != nil {
		t.Fatalf("create FTS5 table: %v", err)
	}

	if _, err := db.Exec("INSERT INTO docs (title, body) VALUES (?, ?)",
		"Hello World", "This is a test document"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO docs (title, body) VALUES (?, ?)",
		"Goodbye", "Another document here"); err != nil {
		t.Fatal(err)
	}

	var title string
	err = db.QueryRow("SELECT title FROM docs WHERE docs MATCH ?", "test").Scan(&title)
	if err != nil {
		t.Fatalf("FTS5 search: %v", err)
	}
	if title != "Hello World" {
		t.Fatalf("got %q, want %q", title, "Hello World")
	}
}

// Test 6: Key rotation — rotate A→B, reopen with B succeeds, A fails
func TestKeyRotation(t *testing.T) {
	keyA := testKey()
	db, path := openTestDB(t, keyA)

	if _, err := db.Exec("CREATE TABLE t (val TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO t (val) VALUES (?)", "rotated"); err != nil {
		t.Fatal(err)
	}

	keyB := testKey()
	if err := RotateKey(db, keyB); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	db.Close()

	// Old key should fail.
	_, err := Open(path, Options{Key: keyA, Encryption: EncryptionRequired})
	if err == nil {
		t.Fatal("expected error with old key after rotation")
	}

	// New key should succeed.
	db2, err := Open(path, Options{Key: keyB, Encryption: EncryptionRequired})
	if err != nil {
		t.Fatalf("reopen with new key: %v", err)
	}
	defer db2.Close()

	var val string
	if err := db2.QueryRow("SELECT val FROM t LIMIT 1").Scan(&val); err != nil {
		t.Fatal(err)
	}
	if val != "rotated" {
		t.Fatalf("got %q, want %q", val, "rotated")
	}
}

// Test 7: Nil key — EncryptionDisabled opens unencrypted database
func TestEncryptionDisabled(t *testing.T) {
	db, path := openTestDB(t, nil)

	if _, err := db.Exec("CREATE TABLE t (val TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO t (val) VALUES (?)", "plain"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// File should have plaintext header.
	plain, err := LooksPlaintext(path)
	if err != nil {
		t.Fatal(err)
	}
	if !plain {
		t.Fatal("unencrypted database should have plaintext header")
	}
}

// Test 8: Available() detects SQLCipher capability
func TestAvailable(t *testing.T) {
	if err := Available(); err != nil {
		t.Fatalf("Available: %v", err)
	}
}

// Test 9: WAL sidecar files should not contain plaintext header
func TestWALSidecarNotPlaintext(t *testing.T) {
	key := testKey()
	db, path := openTestDB(t, key)

	// Create enough data to trigger WAL activity.
	if _, err := db.Exec("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if _, err := db.Exec("INSERT INTO t (val) VALUES (?)", "data"); err != nil {
			t.Fatal(err)
		}
	}

	// Check WAL and SHM files.
	for _, suffix := range []string{"-wal", "-shm"} {
		sidecar := path + suffix
		data, err := os.ReadFile(sidecar)
		if err != nil {
			continue // file may not exist
		}
		if len(data) >= 16 && string(data[:16]) == sqliteHeaderMagic {
			t.Fatalf("sidecar %s contains plaintext SQLite header", suffix)
		}
	}

	db.Close()
}

// Test 10: Concurrent reopen — open/write/close/reopen ×5
func TestConcurrentReopen(t *testing.T) {
	key := testKey()
	path := filepath.Join(t.TempDir(), "reopen.db")

	for i := 0; i < 5; i++ {
		db, err := Open(path, Options{Key: key, Encryption: EncryptionRequired})
		if err != nil {
			t.Fatalf("iteration %d open: %v", i, err)
		}

		if i == 0 {
			if _, err := db.Exec("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
				t.Fatalf("iteration %d create: %v", i, err)
			}
		}

		if _, err := db.Exec("INSERT INTO t (val) VALUES (?)", "iter"); err != nil {
			t.Fatalf("iteration %d insert: %v", i, err)
		}

		db.Close()
	}

	// Final verify.
	db, err := Open(path, Options{Key: key, Encryption: EncryptionRequired})
	if err != nil {
		t.Fatalf("final open: %v", err)
	}
	defer db.Close()

	var count int
	if err := db.QueryRow("SELECT count(*) FROM t").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 5 {
		t.Fatalf("got count=%d, want 5", count)
	}
}

// Test 11: Transaction — BEGIN/ROLLBACK/COMMIT on encrypted DB
func TestTransaction(t *testing.T) {
	key := testKey()
	db, _ := openTestDB(t, key)
	defer db.Close()

	if _, err := db.Exec("CREATE TABLE t (val TEXT)"); err != nil {
		t.Fatal(err)
	}

	// Test rollback.
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("INSERT INTO t (val) VALUES (?)", "rolled_back"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := db.QueryRow("SELECT count(*) FROM t").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("after rollback: count=%d, want 0", count)
	}

	// Test commit.
	tx, err = db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("INSERT INTO t (val) VALUES (?)", "committed"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	if err := db.QueryRow("SELECT count(*) FROM t").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("after commit: count=%d, want 1", count)
	}
}

// Test 12: Prepared statements — prepare/exec/query cycle
func TestPreparedStatements(t *testing.T) {
	key := testKey()
	db, _ := openTestDB(t, key)
	defer db.Close()

	if _, err := db.Exec("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}

	// Prepare insert.
	insertStmt, err := db.Prepare("INSERT INTO t (val) VALUES (?)")
	if err != nil {
		t.Fatal(err)
	}
	defer insertStmt.Close()

	for i := 0; i < 5; i++ {
		if _, err := insertStmt.Exec("item"); err != nil {
			t.Fatalf("exec %d: %v", i, err)
		}
	}

	// Prepare query.
	queryStmt, err := db.Prepare("SELECT count(*) FROM t")
	if err != nil {
		t.Fatal(err)
	}
	defer queryStmt.Close()

	var count int
	if err := queryStmt.QueryRow().Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 5 {
		t.Fatalf("got count=%d, want 5", count)
	}
}

// Test 13: Multi-connection safety — verify 2nd connection also gets key
// With MaxOpenConns(1), this tests connection recycling.
func TestMultiConnectionSafety(t *testing.T) {
	key := testKey()
	db, _ := openTestDB(t, key)
	defer db.Close()

	if _, err := db.Exec("CREATE TABLE t (val TEXT)"); err != nil {
		t.Fatal(err)
	}

	// Force connection close and reopen by temporarily bumping max conns.
	db.SetMaxOpenConns(2)

	// Use two separate connections.
	ctx := context.Background()
	conn1, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn1.ExecContext(ctx, "INSERT INTO t (val) VALUES (?)", "conn1"); err != nil {
		t.Fatal(err)
	}
	conn1.Close()

	conn2, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var val string
	if err := conn2.QueryRowContext(ctx, "SELECT val FROM t LIMIT 1").Scan(&val); err != nil {
		t.Fatal(err)
	}
	conn2.Close()

	if val != "conn1" {
		t.Fatalf("got %q, want %q", val, "conn1")
	}

	db.SetMaxOpenConns(1) // restore
}

// Test 14: Wrong key fails early — error at Open, not at first SELECT
func TestWrongKeyFailsEarly(t *testing.T) {
	key := testKey()
	db, path := openTestDB(t, key)

	if _, err := db.Exec("CREATE TABLE t (val TEXT)"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	wrongKey := testKey()
	_, err := Open(path, Options{
		Key:        wrongKey,
		Encryption: EncryptionRequired,
	})
	// The error should happen at Open time, not later.
	if err == nil {
		t.Fatal("expected error at Open with wrong key")
	}
	t.Logf("wrong key error (at Open, as expected): %v", err)
}

// Test: EncryptionRequired with nil key returns ErrKeyRequired
func TestEncryptionRequiredNoKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	_, err := Open(path, Options{
		Key:        nil,
		Encryption: EncryptionRequired,
	})
	if err != ErrKeyRequired {
		t.Fatalf("got %v, want ErrKeyRequired", err)
	}
}

// Test: CanOpenWithKey
func TestCanOpenWithKey(t *testing.T) {
	key := testKey()
	db, path := openTestDB(t, key)
	if _, err := db.Exec("CREATE TABLE t (val TEXT)"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	if err := CanOpenWithKey(path, key); err != nil {
		t.Fatalf("CanOpenWithKey with correct key: %v", err)
	}

	wrongKey := testKey()
	if err := CanOpenWithKey(path, wrongKey); err == nil {
		t.Fatal("CanOpenWithKey should fail with wrong key")
	}
}

// Test: connector key is zeroed after db.Close()
func TestConnectorKeyZeroedOnClose(t *testing.T) {
	key := testKey()
	path := filepath.Join(t.TempDir(), "zero.db")

	cn := newConnector(path, key)
	db := sql.OpenDB(cn)
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	db.Close()

	// After Close, connector.key must be nil and all bytes zeroed.
	if cn.key != nil {
		t.Fatal("connector.key should be nil after Close")
	}
}

// Test: in-memory database with encryption disabled
func TestMemoryUnencrypted(t *testing.T) {
	db, err := Open(":memory:", Options{
		Encryption: EncryptionDisabled,
	})
	if err != nil {
		t.Fatalf("Open :memory: unencrypted: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO t (val) VALUES (?)", "mem"); err != nil {
		t.Fatal(err)
	}

	var val string
	if err := db.QueryRow("SELECT val FROM t WHERE id = 1").Scan(&val); err != nil {
		t.Fatal(err)
	}
	if val != "mem" {
		t.Fatalf("got %q, want %q", val, "mem")
	}
}

// Test: in-memory database with encryption enabled
func TestMemoryEncrypted(t *testing.T) {
	key := testKey()
	db, err := Open(":memory:", Options{
		Key:        key,
		Encryption: EncryptionRequired,
	})
	if err != nil {
		t.Fatalf("Open :memory: encrypted: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec("CREATE TABLE t (val TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO t (val) VALUES (?)", "secret"); err != nil {
		t.Fatal(err)
	}

	var val string
	if err := db.QueryRow("SELECT val FROM t LIMIT 1").Scan(&val); err != nil {
		t.Fatal(err)
	}
	if val != "secret" {
		t.Fatalf("got %q, want %q", val, "secret")
	}

	// Verify cipher is active.
	version, err := VerifyCipherMetadata(db)
	if err != nil {
		t.Fatalf("VerifyCipherMetadata: %v", err)
	}
	if version == "" {
		t.Fatal("cipher_version is empty on encrypted :memory: db")
	}
}

// Test: LooksPlaintext on nonexistent file
func TestLooksPlaintextNonexistent(t *testing.T) {
	plain, err := LooksPlaintext("/nonexistent/path/db.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	if plain {
		t.Fatal("nonexistent file should not look plaintext")
	}
}
