//! # kunipa-securedb
//!
//! Minimal SQLCipher wrapper with atomic key application.
//!
//! This crate wraps `rusqlite` with `bundled-sqlcipher` to provide a
//! single-connection SQLCipher database that applies the encryption key
//! atomically right after opening, before any other operation.

pub mod error;
pub mod options;
pub(crate) mod connection;
mod verify;

pub use error::{Error, Result};
pub use options::{EncryptionMode, Options};
pub use connection::{Database, SecureKey, wrap_key};
pub use verify::{looks_plaintext, can_open_with_key, verify_cipher_metadata};

/// Opens a SQLCipher database with atomic key application.
///
/// The key (if required) is applied immediately after opening, before any
/// reads. This solves the timing problem where other drivers read
/// `sqlite_master` before the key is set.
///
/// # Examples
///
/// ```no_run
/// use kunipa_securedb::{open, wrap_key, Options, EncryptionMode};
///
/// let db = open("/path/to/db.sqlite", Options {
///     key: Some(wrap_key(vec![0u8; 32])),
///     encryption: EncryptionMode::Required,
///     ..Options::default()
/// }).unwrap();
/// ```
pub fn open(path: &str, opts: Options) -> Result<Database> {
    connection::open_database(path, opts)
}

/// Verifies that the current binary supports SQLCipher encryption.
///
/// Creates a temporary encrypted database, verifies `PRAGMA cipher_version`,
/// then cleans up. Returns `Ok(())` if SQLCipher is available.
pub fn available() -> Result<()> {
    use zeroize::Zeroizing;

    // Generate a random 32-byte key.
    let mut key_bytes = Zeroizing::new(vec![0u8; 32]);
    // Safety: sqlite3_randomness fills buffer with random bytes.
    unsafe {
        rusqlite::ffi::sqlite3_randomness(
            key_bytes.len() as i32,
            key_bytes.as_mut_ptr() as *mut std::ffi::c_void,
        );
    }

    let db = open(
        ":memory:",
        Options {
            key: Some(wrap_key(key_bytes.to_vec())),
            encryption: EncryptionMode::Required,
            ..Options::default()
        },
    )?;

    let version = verify_cipher_metadata(&db)?;
    if version.is_empty() {
        return Err(Error::CipherUnavailable);
    }

    let _ = db.close();
    Ok(())
}
