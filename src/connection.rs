use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use crate::error::{self, Error, Result};
use crate::options::{EncryptionMode, Options};

/// Type alias for a key that is zeroed on drop.
pub type SecureKey = SecretBox<Zeroizing<Vec<u8>>>;

/// Wraps raw key bytes into a `SecureKey` (defensive copy, zeroed on drop).
pub fn wrap_key(raw: Vec<u8>) -> SecureKey {
    SecretBox::new(Box::new(Zeroizing::new(raw)))
}

/// Internal state guarded by a single mutex.
struct Inner {
    conn: Connection,
    key: Option<SecureKey>,
}

/// A single-connection SQLCipher database with atomic key application.
///
/// All access goes through the internal mutex, enforcing the single-connection
/// model (equivalent to Go's `MaxOpenConns(1)`).
///
/// `Database` is `Send + Sync` — the internal mutex serializes all access.
pub struct Database {
    inner: Mutex<Option<Inner>>,
    path: String,
    #[allow(dead_code)]
    flags: OpenFlags,
    #[allow(dead_code)]
    busy_timeout: Duration,
    #[allow(dead_code)]
    wal: bool,
}

// Static assertion: Database must be Send + Sync.
#[allow(dead_code)]
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn check() {
        assert_send_sync::<Database>();
    }
};

impl Database {
    /// Provides closure-based access to the underlying `rusqlite::Connection`.
    ///
    /// The connection reference cannot escape the closure, ensuring the lock
    /// is held for the duration of the operation.
    pub fn with_connection<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> std::result::Result<T, rusqlite::Error>,
    {
        let guard = self.inner.lock().map_err(|_| Error::Poisoned)?;
        let inner = guard.as_ref().ok_or(Error::Closed)?;
        f(&inner.conn).map_err(Error::Sqlite)
    }

    /// Provides mutable closure-based access to the underlying connection.
    ///
    /// Required for operations like transactions that need `&mut Connection`.
    pub fn with_connection_mut<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> std::result::Result<T, rusqlite::Error>,
    {
        let mut guard = self.inner.lock().map_err(|_| Error::Poisoned)?;
        let inner = guard.as_mut().ok_or(Error::Closed)?;
        f(&mut inner.conn).map_err(Error::Sqlite)
    }

    /// Convenience: execute a single SQL statement with parameters.
    pub fn execute<P: rusqlite::Params>(&self, sql: &str, params: P) -> Result<usize> {
        self.with_connection(|conn| conn.execute(sql, params))
    }

    /// Convenience: query a single row.
    pub fn query_row<T, P, F>(&self, sql: &str, params: P, f: F) -> Result<T>
    where
        P: rusqlite::Params,
        F: FnOnce(&rusqlite::Row<'_>) -> std::result::Result<T, rusqlite::Error>,
    {
        self.with_connection(|conn| conn.query_row(sql, params, f))
    }

    /// Rotates the encryption key.
    ///
    /// The new key is applied via `PRAGMA rekey`. The stored key is updated
    /// only if the rekey succeeds. The old key is zeroed by `SecureKey::drop`.
    pub fn rotate_key(&self, new_key: &[u8]) -> Result<()> {
        if new_key.is_empty() {
            return Err(Error::KeyRequired);
        }

        let mut guard = self.inner.lock().map_err(|_| Error::Poisoned)?;
        let inner = guard.as_mut().ok_or(Error::Closed)?;

        // Format key as hex for PRAGMA rekey (zeroed after use).
        let hex = hex_key(new_key);
        let pragma_val = Zeroizing::new(format!("x'{}'", &*hex));
        inner
            .conn
            .pragma_update(None, "rekey", &*pragma_val)
            .map_err(|e| error::map_sqlite_error(e, true))?;

        // Rekey succeeded — update stored key (old key zeroed by drop).
        inner.key = Some(wrap_key(new_key.to_vec()));
        Ok(())
    }

    /// Explicitly closes the database. Idempotent.
    ///
    /// After `close()`, all methods return `Error::Closed`.
    /// `Drop` also closes as a safety net, but prefer explicit `close()`.
    #[must_use = "close() returns a Result that should be checked"]
    pub fn close(&self) -> Result<()> {
        let mut guard = self.inner.lock().map_err(|_| Error::Poisoned)?;
        // Take the inner state, dropping Connection and zeroing key.
        *guard = None;
        Ok(())
    }

    /// Returns the database path.
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl std::fmt::Debug for Database {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Database")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        // Safety net: ensure connection is closed and key is zeroed.
        // get_mut() avoids locking (we have &mut self in Drop).
        if let Ok(inner) = self.inner.get_mut() {
            *inner = None;
        }
    }
}

/// Opens a SQLCipher database with atomic key application.
pub(crate) fn open_database(path: &str, opts: Options) -> Result<Database> {
    let is_memory = is_memory_path(path);

    // Extract option values before moving key out of opts.
    let encryption = opts.encryption;
    let read_only = opts.read_only;
    let create_if_missing = opts.create_if_missing();
    let busy_timeout = opts.busy_timeout();
    let wal_enabled_opt = opts.wal_enabled();

    // Validate incompatible option combinations.
    if !is_memory && read_only && create_if_missing {
        return Err(Error::InvalidOptions(
            "read_only and create_if_missing cannot both be true".into(),
        ));
    }

    // Validate encryption mode vs key.
    let key: Option<SecureKey> = match encryption {
        EncryptionMode::Required => {
            let k = opts.key.ok_or(Error::KeyRequired)?;
            let secret: &Zeroizing<Vec<u8>> = k.expose_secret();
            if secret.is_empty() {
                return Err(Error::KeyRequired);
            }
            Some(k)
        }
        EncryptionMode::Disabled => {
            if opts.key.is_some() {
                return Err(Error::InvalidOptions(
                    "key must not be provided when encryption is disabled".into(),
                ));
            }
            None
        }
    };

    let had_key = key.is_some();

    // File-based checks (skip for in-memory).
    if !is_memory {
        let p = Path::new(path);

        if !create_if_missing {
            if !p.exists() {
                return Err(Error::FileNotFound);
            }
        } else if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(Error::Io)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
    }

    // Build open flags.
    let mut flags = OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if is_memory {
        flags |= OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE;
    } else if read_only {
        flags |= OpenFlags::SQLITE_OPEN_READ_ONLY;
    } else {
        flags |= OpenFlags::SQLITE_OPEN_READ_WRITE;
        if create_if_missing {
            flags |= OpenFlags::SQLITE_OPEN_CREATE;
        }
    }

    // Open connection.
    let conn = if is_memory {
        Connection::open_in_memory_with_flags(flags)
    } else {
        Connection::open_with_flags(path, flags)
    }
    .map_err(|e| error::map_sqlite_error(e, had_key))?;

    // Apply encryption key atomically (before any other operation).
    if let Some(ref k) = key {
        let secret: &Zeroizing<Vec<u8>> = k.expose_secret();
        let hex = hex_key(secret);
        let pragma_val = Zeroizing::new(format!("x'{}'", &*hex));
        conn.pragma_update(None, "key", &*pragma_val)
            .map_err(|e| error::map_sqlite_error(e, true))?;
    }

    // Verify: fail-fast on wrong key / corrupt file.
    conn.execute_batch("SELECT count(*) FROM sqlite_master;")
        .map_err(|e| error::map_sqlite_error(e, had_key))?;

    // Apply per-connection PRAGMAs.
    let timeout_ms = busy_timeout.as_millis().min(i64::MAX as u128) as i64;
    conn.pragma_update(None, "busy_timeout", timeout_ms)
        .map_err(Error::Sqlite)?;

    let wal_enabled = if is_memory { false } else { wal_enabled_opt };
    if wal_enabled {
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(Error::Sqlite)?;
    }

    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(Error::Sqlite)?;

    Ok(Database {
        inner: Mutex::new(Some(Inner { conn, key })),
        path: path.to_string(),
        flags,
        busy_timeout,
        wal: wal_enabled,
    })
}

/// Returns true if the path is the SQLite in-memory sentinel.
pub(crate) fn is_memory_path(path: &str) -> bool {
    path == ":memory:"
}

/// Encodes raw key bytes as a hex string for PRAGMA key/rekey.
/// The returned string is zeroed on drop.
fn hex_key(key: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(key.iter().map(|b| format!("{:02x}", b)).collect())
}
