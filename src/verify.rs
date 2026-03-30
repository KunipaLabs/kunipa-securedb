use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::Database;
use crate::connection::wrap_key;
use crate::error::{Error, Result};
use crate::options::{EncryptionMode, Options};

/// The 16-byte header of an unencrypted SQLite database.
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

/// Checks whether a file starts with the plaintext SQLite header.
///
/// Returns `Ok(false)` if the file does not exist, cannot be read, or is
/// shorter than 16 bytes. Returns `Ok(true)` if the header matches
/// (indicating an unencrypted database).
pub fn looks_plaintext(path: &str) -> Result<bool> {
    let p = Path::new(path);
    if !p.exists() {
        return Ok(false);
    }

    let mut f = match File::open(p) {
        Ok(f) => f,
        Err(_) => return Ok(false),
    };

    let mut buf = [0u8; 16];
    match f.read_exact(&mut buf) {
        Ok(()) => Ok(buf == *SQLITE_HEADER),
        Err(_) => Ok(false),
    }
}

/// Attempts to open the database at `path` with the given key in read-only
/// mode and verifies that it can be read.
///
/// The verification is performed by `open()` itself (which executes
/// `SELECT count(*) FROM sqlite_master` atomically after keying).
///
/// Returns typed errors:
/// - `Error::FileNotFound` if the file does not exist
/// - `Error::WrongKey` if the key cannot decrypt the database
/// - `Error::NotDatabase` if the file is not a valid database
/// - `Error::CipherUnavailable` if SQLCipher is not available
pub fn can_open_with_key(path: &str, key: &[u8]) -> Result<()> {
    let p = Path::new(path);
    if !p.exists() {
        return Err(Error::FileNotFound);
    }

    let db = crate::open(
        path,
        Options {
            key: Some(wrap_key(key.to_vec())),
            encryption: EncryptionMode::Required,
            read_only: true,
            create_if_missing: Some(false),
            ..Options::default()
        },
    )?;

    // open() already verified sqlite_master — just close.
    let _ = db.close();
    Ok(())
}

/// Queries `PRAGMA cipher_version` on an open database.
///
/// Returns the version string on success, or `Error::CipherUnavailable`
/// if the cipher is not active. This is a diagnostic function — the real
/// proof of a valid key is the `SELECT count(*) FROM sqlite_master` probe
/// that `open()` performs atomically.
pub fn verify_cipher_metadata(db: &Database) -> Result<String> {
    let version: String =
        db.with_connection(|conn| conn.query_row("PRAGMA cipher_version;", [], |row| row.get(0)))?;

    if version.is_empty() {
        return Err(Error::CipherUnavailable);
    }

    Ok(version)
}
