#include "session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void session_init(sqlite3 *db) {
    const char *sql =
        "CREATE TABLE IF NOT EXISTS sessions ("
        "session_id TEXT PRIMARY KEY,"
        "user_id INTEGER NOT NULL,"
        "user_name TEXT,"
        "user_cnic TEXT,"
        "user_email TEXT,"
        "is_admin INTEGER DEFAULT 0,"
        "expires_at DATETIME"
        ");";
    char *err = NULL;
    sqlite3_exec(db, sql, 0, 0, &err);
    if (err) sqlite3_free(err);
}

void session_generate_id(char *out, int len) {
    static const char chars[] = "abcdef0123456789";
    srand((unsigned int)time(NULL) ^ (unsigned int)(size_t)out);
    for (int i = 0; i < len; i++) {
        out[i] = chars[rand() % 16];
    }
    out[len] = '\0';
}

int session_create(sqlite3 *db, int user_id, const char *name, const char *cnic,
                   const char *email, int is_admin, char *out_session_id) {
    char sid[SESSION_ID_LEN + 1];
    session_generate_id(sid, SESSION_ID_LEN);

    const char *sql =
        "INSERT INTO sessions (session_id, user_id, user_name, user_cnic, user_email, is_admin, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, datetime('now', '+24 hours'));";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;

    sqlite3_bind_text(stmt, 1, sid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, user_id);
    sqlite3_bind_text(stmt, 3, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, cnic, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, email, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 6, is_admin);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) {
        strncpy(out_session_id, sid, SESSION_ID_LEN + 1);
        return 1;
    }
    return 0;
}

Session session_get(sqlite3 *db, const char *session_id) {
    Session s;
    memset(&s, 0, sizeof(s));
    s.valid = 0;

    if (!session_id || strlen(session_id) == 0) return s;

    const char *sql =
        "SELECT user_id, user_name, user_cnic, user_email, is_admin "
        "FROM sessions WHERE session_id = ? AND expires_at > datetime('now');";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return s;

    sqlite3_bind_text(stmt, 1, session_id, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        s.user_id  = sqlite3_column_int(stmt, 0);
        const char *nm = (const char *)sqlite3_column_text(stmt, 1);
        const char *cn = (const char *)sqlite3_column_text(stmt, 2);
        const char *em = (const char *)sqlite3_column_text(stmt, 3);
        s.is_admin = sqlite3_column_int(stmt, 4);
        if (nm) strncpy(s.user_name,  nm, 127);
        if (cn) strncpy(s.user_cnic,  cn, 19);
        if (em) strncpy(s.user_email, em, 119);
        strncpy(s.session_id, session_id, SESSION_ID_LEN);
        s.valid = 1;
    }
    sqlite3_finalize(stmt);
    return s;
}

void session_destroy(sqlite3 *db, const char *session_id) {
    const char *sql = "DELETE FROM sessions WHERE session_id = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return;
    sqlite3_bind_text(stmt, 1, session_id, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void session_cleanup_expired(sqlite3 *db) {
    sqlite3_exec(db, "DELETE FROM sessions WHERE expires_at <= datetime('now');", 0, 0, NULL);
}
