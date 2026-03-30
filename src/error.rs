/// All errors returned by kunipa-securedb.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Encryption required but no key provided.
    #[error("securedb: encryption required but no key provided")]
    KeyRequired,

    /// The provided key cannot decrypt the database.
    #[error("securedb: wrong encryption key")]
    WrongKey,

    /// The file is not a valid SQLite/SQLCipher database.
    #[error("securedb: file is not a valid SQLite/SQLCipher database")]
    NotDatabase,

    /// Database file not found and creation not requested.
    #[error("securedb: database file not found")]
    FileNotFound,

    /// SQLCipher is not available in this build.
    #[error("securedb: SQLCipher not available")]
    CipherUnavailable,

    /// Operation attempted on a closed database.
    #[error("securedb: database is closed")]
    Closed,

    /// Internal mutex was poisoned (a thread panicked while holding the lock).
    #[error("securedb: internal mutex poisoned — a thread panicked while holding the database lock")]
    Poisoned,

    /// Invalid option combination.
    #[error("securedb: {0}")]
    InvalidOptions(String),

    /// Underlying rusqlite error.
    #[error("securedb: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// I/O error.
    #[error("securedb: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Maps a rusqlite error to a securedb error, using key presence to
/// distinguish WrongKey from NotDatabase when SQLite returns NOTADB.
pub(crate) fn map_sqlite_error(err: rusqlite::Error, had_key: bool) -> Error {
    if let rusqlite::Error::SqliteFailure(ffi_err, _) = &err
        && ffi_err.code == rusqlite::ffi::ErrorCode::NotADatabase
    {
        return if had_key {
            Error::WrongKey
        } else {
            Error::NotDatabase
        };
    }
    Error::Sqlite(err)
}

impl Error {
    /// Returns true if this is a `WrongKey` error.
    pub fn is_wrong_key(&self) -> bool {
        matches!(self, Error::WrongKey)
    }

    /// Returns true if this is a `KeyRequired` error.
    pub fn is_key_required(&self) -> bool {
        matches!(self, Error::KeyRequired)
    }

    /// Returns true if this is a `Closed` error.
    pub fn is_closed(&self) -> bool {
        matches!(self, Error::Closed)
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        // Compare by discriminant for sentinel errors; structural for others.
        match (self, other) {
            (Error::KeyRequired, Error::KeyRequired) => true,
            (Error::WrongKey, Error::WrongKey) => true,
            (Error::NotDatabase, Error::NotDatabase) => true,
            (Error::FileNotFound, Error::FileNotFound) => true,
            (Error::CipherUnavailable, Error::CipherUnavailable) => true,
            (Error::Closed, Error::Closed) => true,
            (Error::Poisoned, Error::Poisoned) => true,
            (Error::InvalidOptions(a), Error::InvalidOptions(b)) => a == b,
            _ => false,
        }
    }
}
