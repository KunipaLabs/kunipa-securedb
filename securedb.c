#include "securedb.h"
#include <string.h>

int securedb_open(const char *path, const char *key, int key_len,
                  int flags, sqlite3 **db) {
    *db = NULL;

    int rc = sqlite3_open_v2(path, db, flags, NULL);
    if (rc != SQLITE_OK) {
        if (*db != NULL) {
            sqlite3_close(*db);
            *db = NULL;
        }
        return rc;
    }

    // If a key is provided, apply it atomically before any other operation.
    if (key != NULL && key_len > 0) {
        rc = sqlite3_key(*db, key, key_len);
        if (rc != SQLITE_OK) {
            sqlite3_close(*db);
            *db = NULL;
            return rc;
        }

        // Verify: attempt to read sqlite_master to confirm the key is correct.
        // This must happen before any other operation to fail early on wrong key.
        rc = sqlite3_exec(*db, "SELECT count(*) FROM sqlite_master",
                          NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            sqlite3_close(*db);
            *db = NULL;
            return rc;
        }
    }

    return SQLITE_OK;
}

int securedb_rekey(sqlite3 *db, const char *new_key, int new_key_len) {
    if (db == NULL) {
        return SQLITE_MISUSE;
    }
    return sqlite3_rekey(db, new_key, new_key_len);
}

int securedb_close(sqlite3 *db) {
    if (db == NULL) {
        return SQLITE_OK;
    }
    // Use sqlite3_close_v2: defers actual deallocation until all prepared
    // statements are finalized. Safer than sqlite3_close which returns
    // SQLITE_BUSY and leaves the handle in a limbo state.
    return sqlite3_close_v2(db);
}

const char *securedb_errmsg(sqlite3 *db) {
    if (db == NULL) {
        return "nil database handle";
    }
    return sqlite3_errmsg(db);
}

int securedb_errcode(sqlite3 *db) {
    if (db == NULL) {
        return SQLITE_MISUSE;
    }
    return sqlite3_errcode(db);
}
