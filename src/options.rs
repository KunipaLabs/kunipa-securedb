use std::time::Duration;

use crate::connection::SecureKey;

/// Controls whether encryption is required when opening a database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EncryptionMode {
    /// A key must be provided; opening without a key returns `ErrKeyRequired`.
    #[default]
    Required,
    /// Opens the database without encryption. Any provided key is ignored.
    Disabled,
}

/// Configuration for opening a SQLCipher database.
#[derive(Default)]
pub struct Options {
    /// Raw binary encryption key (32 bytes recommended).
    /// Wrapped in `SecureKey` for deterministic zeroing on drop.
    pub key: Option<SecureKey>,
    /// Encryption mode. Defaults to `Required`.
    pub encryption: EncryptionMode,
    /// Open the database in read-only mode.
    pub read_only: bool,
    /// Create the database file if it does not exist. `None` means `true`.
    pub create_if_missing: Option<bool>,
    /// SQLite busy timeout. `None` means 5 seconds.
    pub busy_timeout: Option<Duration>,
    /// Enable WAL journal mode. `None` means `true`.
    pub wal: Option<bool>,
}

impl Options {
    /// Returns the effective create-if-missing setting (default: true).
    pub(crate) fn create_if_missing(&self) -> bool {
        self.create_if_missing.unwrap_or(true)
    }

    /// Returns the effective WAL setting (default: true).
    pub(crate) fn wal_enabled(&self) -> bool {
        self.wal.unwrap_or(true)
    }

    /// Returns the effective busy timeout (default: 5 seconds).
    pub(crate) fn busy_timeout(&self) -> Duration {
        self.busy_timeout.unwrap_or(Duration::from_secs(5))
    }
}
