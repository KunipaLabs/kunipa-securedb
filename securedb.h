#ifndef SECUREDB_H
#define SECUREDB_H

#include <sqlite3.h>

// securedb_open opens a SQLite/SQLCipher database and applies the encryption
// key atomically before any other operation. This is the core of the mini-driver:
// sqlite3_open_v2() → sqlite3_key() → SELECT count(*) FROM sqlite_master.
//
// If key is NULL or key_len is 0, the database is opened without encryption.
// Returns SQLITE_OK on success, or an SQLite error code on failure.
// On failure, *db is set to NULL.
int securedb_open(const char *path, const char *key, int key_len,
                  int flags, sqlite3 **db);

// securedb_rekey changes the encryption key of an already-opened database.
// The database must have been opened with securedb_open and a valid key.
int securedb_rekey(sqlite3 *db, const char *new_key, int new_key_len);

// securedb_close closes a database handle opened by securedb_open.
int securedb_close(sqlite3 *db);

// securedb_errmsg returns the most recent error message for a database handle.
const char *securedb_errmsg(sqlite3 *db);

// securedb_errcode returns the most recent error code for a database handle.
int securedb_errcode(sqlite3 *db);

#endif // SECUREDB_H
