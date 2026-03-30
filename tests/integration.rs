use kunipa_securedb::{
    can_open_with_key, looks_plaintext, open, verify_cipher_metadata, wrap_key, Database,
    EncryptionMode, Error, Options,
};
use tempfile::TempDir;

fn test_key() -> kunipa_securedb::SecureKey {
    wrap_key(test_key_raw())
}

fn test_key_raw() -> Vec<u8> {
    let mut key = vec![0u8; 32];
    unsafe {
        rusqlite::ffi::sqlite3_randomness(
            key.len() as i32,
            key.as_mut_ptr() as *mut std::ffi::c_void,
        );
    }
    key
}

fn db_path(dir: &TempDir) -> String {
    dir.path().join("test.db").to_str().unwrap().to_string()
}

fn open_test_db(dir: &TempDir, key: kunipa_securedb::SecureKey, mode: EncryptionMode) -> Database {
    open(
        &db_path(dir),
        Options {
            key: if mode == EncryptionMode::Required {
                Some(key)
            } else {
                None
            },
            encryption: mode,
            ..Options::default()
        },
    )
    .expect("failed to open test db")
}

fn create_test_table(db: &Database) {
    db.execute(
        "CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, val TEXT)",
        [],
    )
    .unwrap();
}

// --- Port of Go tests ---

#[test]
fn test_encrypted_header_not_plaintext() {
    let dir = TempDir::new().unwrap();
    let key = test_key();
    let path = db_path(&dir);

    let db = open_test_db(&dir, key, EncryptionMode::Required);
    create_test_table(&db);
    db.execute("INSERT INTO t (val) VALUES (?1)", ["hello"]).unwrap();
    db.close().unwrap();

    let plain = looks_plaintext(&path).unwrap();
    assert!(!plain, "encrypted database should not have plaintext header");
}

#[test]
fn test_wrong_key_fails() {
    let dir = TempDir::new().unwrap();
    let key = test_key();
    let path = db_path(&dir);

    let db = open_test_db(&dir, key, EncryptionMode::Required);
    create_test_table(&db);
    db.close().unwrap();

    let wrong_key = test_key();
    let err = open(
        &path,
        Options {
            key: Some(wrong_key),
            encryption: EncryptionMode::Required,
            ..Options::default()
        },
    )
    .unwrap_err();

    assert_eq!(err, Error::WrongKey);
}

#[test]
fn test_right_key_succeeds() {
    let dir = TempDir::new().unwrap();
    let raw_key = test_key_raw();
    let path = db_path(&dir);

    // Create and populate.
    let db = open(
        &path,
        Options {
            key: Some(wrap_key(raw_key.clone())),
            encryption: EncryptionMode::Required,
            ..Options::default()
        },
    )
    .unwrap();
    create_test_table(&db);
    db.execute("INSERT INTO t (val) VALUES (?1)", ["world"]).unwrap();
    db.close().unwrap();

    // Reopen with same key.
    let db2 = open(
        &path,
        Options {
            key: Some(wrap_key(raw_key)),
            encryption: EncryptionMode::Required,
            ..Options::default()
        },
    )
    .unwrap();
    let val: String = db2
        .query_row("SELECT val FROM t WHERE id = 1", [], |row| row.get(0))
        .unwrap();
    assert_eq!(val, "world");
}

#[test]
fn test_cipher_version() {
    let dir = TempDir::new().unwrap();
    let key = test_key();
    let db = open_test_db(&dir, key, EncryptionMode::Required);

    let version = verify_cipher_metadata(&db).unwrap();
    assert!(!version.is_empty(), "cipher_version should not be empty");
}

#[test]
fn test_fts5() {
    let dir = TempDir::new().unwrap();
    let key = test_key();
    let db = open_test_db(&dir, key, EncryptionMode::Required);

    db.with_connection(|conn| {
        conn.execute_batch(
            "CREATE VIRTUAL TABLE docs USING fts5(title, body);
             INSERT INTO docs (title, body) VALUES ('hello', 'world of rust');
             INSERT INTO docs (title, body) VALUES ('goodbye', 'cruel world');",
        )?;
        let count: i64 =
            conn.query_row("SELECT count(*) FROM docs WHERE docs MATCH 'world'", [], |r| {
                r.get(0)
            })?;
        assert_eq!(count, 2);
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_key_rotation() {
    let dir = TempDir::new().unwrap();
    let key_a = test_key_raw();
    let key_b = test_key_raw();
    let path = db_path(&dir);

    // Create with key A.
    let db = open(
        &path,
        Options {
            key: Some(wrap_key(key_a.clone())),
            encryption: EncryptionMode::Required,
            ..Options::default()
        },
    )
    .unwrap();
    create_test_table(&db);
    db.execute("INSERT INTO t (val) VALUES (?1)", ["before rotation"]).unwrap();

    // Rotate to key B.
    db.rotate_key(&key_b).unwrap();
    db.close().unwrap();

    // Old key A should fail.
    let err = open(
        &path,
        Options {
            key: Some(wrap_key(key_a)),
            encryption: EncryptionMode::Required,
            ..Options::default()
        },
    )
    .unwrap_err();
    assert_eq!(err, Error::WrongKey);

    // New key B should succeed.
    let db2 = open(
        &path,
        Options {
            key: Some(wrap_key(key_b)),
            encryption: EncryptionMode::Required,
            ..Options::default()
        },
    )
    .unwrap();
    let val: String = db2
        .query_row("SELECT val FROM t WHERE id = 1", [], |row| row.get(0))
        .unwrap();
    assert_eq!(val, "before rotation");
}

#[test]
fn test_encryption_disabled() {
    let dir = TempDir::new().unwrap();
    let path = db_path(&dir);

    let db = open(
        &path,
        Options {
            encryption: EncryptionMode::Disabled,
            ..Options::default()
        },
    )
    .unwrap();
    create_test_table(&db);
    db.execute("INSERT INTO t (val) VALUES (?1)", ["plain"]).unwrap();
    db.close().unwrap();

    let plain = looks_plaintext(&path).unwrap();
    assert!(plain, "unencrypted database should have plaintext header");
}

#[test]
fn test_available() {
    kunipa_securedb::available().expect("SQLCipher should be available");
}

#[test]
fn test_wal_sidecar_not_plaintext() {
    let dir = TempDir::new().unwrap();
    let key = test_key();
    let path = db_path(&dir);

    let db = open_test_db(&dir, key, EncryptionMode::Required);
    create_test_table(&db);
    db.execute("INSERT INTO t (val) VALUES (?1)", ["wal test"]).unwrap();

    // WAL and SHM files should not have plaintext headers.
    let wal_path = format!("{}-wal", path);
    let shm_path = format!("{}-shm", path);

    if std::path::Path::new(&wal_path).exists() {
        assert!(!looks_plaintext(&wal_path).unwrap());
    }
    if std::path::Path::new(&shm_path).exists() {
        assert!(!looks_plaintext(&shm_path).unwrap());
    }
}

#[test]
fn test_concurrent_reopen() {
    let dir = TempDir::new().unwrap();
    let raw_key = test_key_raw();
    let path = db_path(&dir);

    for i in 0..5 {
        let db = open(
            &path,
            Options {
                key: Some(wrap_key(raw_key.clone())),
                encryption: EncryptionMode::Required,
                ..Options::default()
            },
        )
        .unwrap();

        if i == 0 {
            create_test_table(&db);
        }

        db.execute(
            "INSERT INTO t (val) VALUES (?1)",
            [format!("iter-{}", i)],
        )
        .unwrap();

        let count: i64 = db
            .query_row("SELECT count(*) FROM t", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, (i + 1) as i64);

        db.close().unwrap();
    }
}

#[test]
fn test_transaction() {
    let dir = TempDir::new().unwrap();
    let key = test_key();
    let db = open_test_db(&dir, key, EncryptionMode::Required);
    create_test_table(&db);

    // Rollback.
    db.with_connection_mut(|conn| {
        let tx = conn.transaction()?;
        tx.execute("INSERT INTO t (val) VALUES (?1)", ["rollback me"])?;
        tx.rollback()?;
        Ok(())
    })
    .unwrap();

    let count: i64 = db
        .query_row("SELECT count(*) FROM t", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0, "rollback should leave table empty");

    // Commit.
    db.with_connection_mut(|conn| {
        let tx = conn.transaction()?;
        tx.execute("INSERT INTO t (val) VALUES (?1)", ["commit me"])?;
        tx.commit()?;
        Ok(())
    })
    .unwrap();

    let count: i64 = db
        .query_row("SELECT count(*) FROM t", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1, "commit should persist one row");
}

#[test]
fn test_prepared_statements() {
    let dir = TempDir::new().unwrap();
    let key = test_key();
    let db = open_test_db(&dir, key, EncryptionMode::Required);
    create_test_table(&db);

    db.with_connection(|conn| {
        let mut stmt = conn.prepare("INSERT INTO t (val) VALUES (?1)")?;
        for i in 0..5 {
            stmt.execute([format!("stmt-{}", i)])?;
        }
        drop(stmt);

        let mut stmt = conn.prepare("SELECT val FROM t ORDER BY id")?;
        let vals: Vec<String> = stmt
            .query_map([], |row| row.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(vals.len(), 5);
        assert_eq!(vals[0], "stmt-0");
        assert_eq!(vals[4], "stmt-4");
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_wrong_key_fails_early() {
    let dir = TempDir::new().unwrap();
    let key = test_key();
    let path = db_path(&dir);

    let db = open_test_db(&dir, key, EncryptionMode::Required);
    create_test_table(&db);
    db.close().unwrap();

    // Error should occur at open(), not at first SELECT.
    let wrong_key = test_key();
    let result = open(
        &path,
        Options {
            key: Some(wrong_key),
            encryption: EncryptionMode::Required,
            ..Options::default()
        },
    );

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Error::WrongKey);
}

#[test]
fn test_encryption_required_no_key() {
    let dir = TempDir::new().unwrap();
    let path = db_path(&dir);

    let err = open(
        &path,
        Options {
            key: None,
            encryption: EncryptionMode::Required,
            ..Options::default()
        },
    )
    .unwrap_err();

    assert_eq!(err, Error::KeyRequired);
}

#[test]
fn test_can_open_with_key_valid() {
    let dir = TempDir::new().unwrap();
    let raw_key = test_key_raw();
    let path = db_path(&dir);

    let db = open(
        &path,
        Options {
            key: Some(wrap_key(raw_key.clone())),
            encryption: EncryptionMode::Required,
            ..Options::default()
        },
    )
    .unwrap();
    create_test_table(&db);
    db.close().unwrap();

    can_open_with_key(&path, &raw_key).expect("should open with correct key");
}

#[test]
fn test_can_open_with_key_wrong() {
    let dir = TempDir::new().unwrap();
    let key = test_key_raw();
    let path = db_path(&dir);

    let db = open(
        &path,
        Options {
            key: Some(wrap_key(key)),
            encryption: EncryptionMode::Required,
            ..Options::default()
        },
    )
    .unwrap();
    create_test_table(&db);
    db.close().unwrap();

    let wrong_key = test_key_raw();
    let err = can_open_with_key(&path, &wrong_key).unwrap_err();
    assert_eq!(err, Error::WrongKey);
}

#[test]
fn test_memory_unencrypted() {
    let db = open(
        ":memory:",
        Options {
            encryption: EncryptionMode::Disabled,
            ..Options::default()
        },
    )
    .unwrap();

    db.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)", [])
        .unwrap();
    db.execute("INSERT INTO t (val) VALUES (?1)", ["mem"]).unwrap();

    let val: String = db
        .query_row("SELECT val FROM t WHERE id = 1", [], |row| row.get(0))
        .unwrap();
    assert_eq!(val, "mem");
}

#[test]
fn test_memory_encrypted() {
    let key = test_key();
    let db = open(
        ":memory:",
        Options {
            key: Some(key),
            encryption: EncryptionMode::Required,
            ..Options::default()
        },
    )
    .unwrap();

    db.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)", [])
        .unwrap();
    db.execute("INSERT INTO t (val) VALUES (?1)", ["encrypted mem"]).unwrap();

    let val: String = db
        .query_row("SELECT val FROM t WHERE id = 1", [], |row| row.get(0))
        .unwrap();
    assert_eq!(val, "encrypted mem");

    let version = verify_cipher_metadata(&db).unwrap();
    assert!(!version.is_empty());
}

#[test]
fn test_looks_plaintext_nonexistent() {
    let result = looks_plaintext("/tmp/nonexistent_securedb_test.db").unwrap();
    assert!(!result, "nonexistent file should return false");
}

#[test]
fn test_type_bindings() {
    let dir = TempDir::new().unwrap();
    let key = test_key();
    let db = open_test_db(&dir, key, EncryptionMode::Required);

    db.with_connection(|conn| {
        conn.execute_batch(
            "CREATE TABLE types (
                id INTEGER PRIMARY KEY,
                blob_col BLOB,
                float_col REAL,
                bool_col INTEGER,
                null_col TEXT
            )",
        )?;

        conn.execute(
            "INSERT INTO types (blob_col, float_col, bool_col, null_col) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                vec![0xDE_u8, 0xAD, 0xBE, 0xEF],
                42.195_f64,
                true,
                rusqlite::types::Null,
            ],
        )?;

        let (blob, float_val, bool_val, null_val): (Vec<u8>, f64, bool, Option<String>) =
            conn.query_row("SELECT blob_col, float_col, bool_col, null_col FROM types WHERE id = 1", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?;

        assert_eq!(blob, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!((float_val - 42.195).abs() < 1e-10);
        assert!(bool_val);
        assert!(null_val.is_none());

        Ok(())
    })
    .unwrap();
}

#[test]
fn test_exec_context_with_args() {
    let dir = TempDir::new().unwrap();
    let key = test_key();
    let db = open_test_db(&dir, key, EncryptionMode::Required);
    create_test_table(&db);

    let rows_affected = db
        .execute("INSERT INTO t (val) VALUES (?1)", ["arg test"])
        .unwrap();
    assert_eq!(rows_affected, 1);

    let val: String = db
        .query_row("SELECT val FROM t WHERE id = 1", [], |row| row.get(0))
        .unwrap();
    assert_eq!(val, "arg test");
}

// --- Rust-specific tests ---

#[test]
fn test_double_close_idempotent() {
    let dir = TempDir::new().unwrap();
    let key = test_key();
    let db = open_test_db(&dir, key, EncryptionMode::Required);
    create_test_table(&db);

    db.close().unwrap();
    db.close().unwrap(); // Should not panic or error.
}

#[test]
fn test_operations_after_close_return_closed() {
    let dir = TempDir::new().unwrap();
    let key = test_key();
    let db = open_test_db(&dir, key, EncryptionMode::Required);
    create_test_table(&db);
    db.close().unwrap();

    let err = db.execute("SELECT 1", []).unwrap_err();
    assert_eq!(err, Error::Closed);

    let err = db
        .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
        .unwrap_err();
    assert_eq!(err, Error::Closed);
}

#[test]
fn test_rotate_key_on_closed_returns_closed() {
    let dir = TempDir::new().unwrap();
    let key = test_key();
    let db = open_test_db(&dir, key, EncryptionMode::Required);
    db.close().unwrap();

    let new_key = test_key_raw();
    let err = db.rotate_key(&new_key).unwrap_err();
    assert_eq!(err, Error::Closed);
}

#[test]
fn test_file_not_found() {
    let err = open(
        "/tmp/nonexistent_securedb_dir/nonexistent.db",
        Options {
            key: Some(test_key()),
            encryption: EncryptionMode::Required,
            create_if_missing: Some(false),
            ..Options::default()
        },
    )
    .unwrap_err();

    assert_eq!(err, Error::FileNotFound);
}

#[test]
fn test_read_only_mode() {
    let dir = TempDir::new().unwrap();
    let raw_key = test_key_raw();
    let path = db_path(&dir);

    // Create and populate first.
    let db = open(
        &path,
        Options {
            key: Some(wrap_key(raw_key.clone())),
            encryption: EncryptionMode::Required,
            ..Options::default()
        },
    )
    .unwrap();
    create_test_table(&db);
    db.execute("INSERT INTO t (val) VALUES (?1)", ["ro test"]).unwrap();
    db.close().unwrap();

    // Reopen read-only.
    let db2 = open(
        &path,
        Options {
            key: Some(wrap_key(raw_key)),
            encryption: EncryptionMode::Required,
            read_only: true,
            create_if_missing: Some(false),
            ..Options::default()
        },
    )
    .unwrap();

    let val: String = db2
        .query_row("SELECT val FROM t WHERE id = 1", [], |row| row.get(0))
        .unwrap();
    assert_eq!(val, "ro test");

    // Write should fail.
    let err = db2.execute("INSERT INTO t (val) VALUES (?1)", ["should fail"]);
    assert!(err.is_err(), "writes should fail on read-only database");
}

#[test]
fn test_can_open_with_key_nonexistent() {
    let err = can_open_with_key("/tmp/nonexistent_securedb_test_2.db", &test_key_raw()).unwrap_err();
    assert_eq!(err, Error::FileNotFound);
}

#[test]
fn test_disabled_with_key_returns_error() {
    let dir = TempDir::new().unwrap();
    let err = open(
        &db_path(&dir),
        Options {
            key: Some(test_key()),
            encryption: EncryptionMode::Disabled,
            ..Options::default()
        },
    )
    .unwrap_err();

    assert_eq!(
        err,
        Error::InvalidOptions("key must not be provided when encryption is disabled".into())
    );
}

#[test]
fn test_read_only_with_create_if_missing_returns_error() {
    let dir = TempDir::new().unwrap();
    let err = open(
        &db_path(&dir),
        Options {
            key: Some(test_key()),
            encryption: EncryptionMode::Required,
            read_only: true,
            create_if_missing: Some(true),
            ..Options::default()
        },
    )
    .unwrap_err();

    assert_eq!(
        err,
        Error::InvalidOptions(
            "read_only and create_if_missing cannot both be true".into()
        )
    );
}
