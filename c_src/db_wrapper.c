#include "db_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static sqlite3 *g_db = NULL;

static const char *SCHEMA =
    "CREATE TABLE IF NOT EXISTS sessions ("
    "session_id TEXT PRIMARY KEY,"
    "user_id INTEGER NOT NULL,"
    "user_name TEXT,"
    "user_cnic TEXT,"
    "user_email TEXT,"
    "is_admin INTEGER DEFAULT 0,"
    "expires_at DATETIME);"

    "CREATE TABLE IF NOT EXISTS users ("
    "user_id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "name TEXT NOT NULL,"
    "cnic TEXT UNIQUE NOT NULL,"
    "email TEXT UNIQUE NOT NULL,"
    "password_hash TEXT NOT NULL,"
    "is_admin INTEGER DEFAULT 0,"
    "is_deleted INTEGER DEFAULT 0,"
    "created_at DATETIME DEFAULT CURRENT_TIMESTAMP);"

    "CREATE TABLE IF NOT EXISTS elections ("
    "election_id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "title TEXT NOT NULL,"
    "description TEXT,"
    "status TEXT DEFAULT 'upcoming',"
    "start_date DATETIME NOT NULL,"
    "end_date DATETIME NOT NULL,"
    "created_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
    "is_deleted INTEGER DEFAULT 0,"
    "deleted_at DATETIME,"
    "deleted_by INTEGER);"

    "CREATE TABLE IF NOT EXISTS election_voters ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "election_id INTEGER NOT NULL,"
    "user_id INTEGER NOT NULL,"
    "added_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
    "UNIQUE(election_id, user_id));"

    "CREATE TABLE IF NOT EXISTS candidates ("
    "candidate_id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "user_id INTEGER NOT NULL,"
    "cnic TEXT NOT NULL,"
    "name TEXT NOT NULL,"
    "description TEXT,"
    "election_id INTEGER NOT NULL,"
    "image_path TEXT DEFAULT 'default-candidate.png',"
    "application_id INTEGER,"
    "created_at DATETIME DEFAULT CURRENT_TIMESTAMP);"

    "CREATE TABLE IF NOT EXISTS candidate_applications ("
    "application_id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "user_id INTEGER NOT NULL,"
    "election_id INTEGER NOT NULL,"
    "description TEXT,"
    "image_path TEXT DEFAULT 'default-candidate.png',"
    "status TEXT DEFAULT 'pending',"
    "applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
    "reviewed_at DATETIME,"
    "reviewed_by INTEGER,"
    "rejection_reason TEXT,"
    "UNIQUE(user_id, election_id));"

    "CREATE TABLE IF NOT EXISTS votes ("
    "vote_id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "user_id INTEGER NOT NULL,"
    "candidate_id INTEGER NOT NULL,"
    "election_id INTEGER NOT NULL,"
    "voted_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
    "ip_address TEXT,"
    "UNIQUE(user_id, election_id));"

    "CREATE TABLE IF NOT EXISTS password_reset_requests ("
    "req_id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "user_id INTEGER NOT NULL,"
    "email TEXT NOT NULL,"
    "status TEXT DEFAULT 'pending',"
    "requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
    "resolved_at DATETIME,"
    "UNIQUE(user_id, status));";

int db_init(const char *path) {
    if (sqlite3_open(path, &g_db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(g_db));
        return 0;
    }
    sqlite3_exec(g_db, "PRAGMA journal_mode=WAL;", 0, 0, NULL);
    char *err = NULL;
    /* Execute schema one statement at a time */
    const char *ptr = SCHEMA;
    while (*ptr) {
        sqlite3_stmt *tmp;
        const char *tail;
        int rc = sqlite3_prepare_v2(g_db, ptr, -1, &tmp, &tail);
        if (rc == SQLITE_OK) {
            sqlite3_step(tmp);
            sqlite3_finalize(tmp);
        }
        if (tail == ptr) break;
        ptr = tail;
    }
    (void)err;
    return 1;
}

sqlite3 *db_get(void) { return g_db; }

/* ================================================================
   USERS
   ================================================================ */

int db_create_user(const char *cnic, const char *name, const char *email,
                   const char *hash, int is_admin) {
    const char *sql =
        "INSERT OR IGNORE INTO users (cnic, name, email, password_hash, is_admin) "
        "VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(stmt, 1, cnic,  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, name,  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, email, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, hash,  -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, 5, is_admin);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE && sqlite3_changes(g_db) > 0);
}

static int verify_user(const char *field, const char *val, const char *hash,
                        int *uid, int *is_admin, int *is_deleted) {
    char sql[256];
    snprintf(sql, sizeof(sql),
        "SELECT user_id, is_admin, is_deleted FROM users "
        "WHERE %s = ? AND password_hash = ?;", field);
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(stmt, 1, val,  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, hash, -1, SQLITE_TRANSIENT);
    int ok = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *uid        = sqlite3_column_int(stmt, 0);
        *is_admin   = sqlite3_column_int(stmt, 1);
        *is_deleted = sqlite3_column_int(stmt, 2);
        ok = 1;
    }
    sqlite3_finalize(stmt);
    return ok;
}

int db_verify_user_by_email(const char *email, const char *hash,
                             int *uid, int *is_admin, int *is_deleted) {
    return verify_user("email", email, hash, uid, is_admin, is_deleted);
}

int db_verify_user_by_cnic(const char *cnic, const char *hash,
                            int *uid, int *is_admin, int *is_deleted) {
    return verify_user("cnic", cnic, hash, uid, is_admin, is_deleted);
}

int db_get_user(int user_id, char *name, char *cnic, char *email,
                int *is_admin, int *is_deleted, char *created_at) {
    const char *sql =
        "SELECT name, cnic, email, is_admin, is_deleted, created_at "
        "FROM users WHERE user_id = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(stmt, 1, user_id);
    int ok = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *n = (const char *)sqlite3_column_text(stmt, 0);
        const char *c = (const char *)sqlite3_column_text(stmt, 1);
        const char *e = (const char *)sqlite3_column_text(stmt, 2);
        const char *dt= (const char *)sqlite3_column_text(stmt, 5);
        if (name)       { if(n) strncpy(name, n, 127); else name[0]=0; }
        if (cnic)       { if(c) strncpy(cnic, c, 19);  else cnic[0]=0; }
        if (email)      { if(e) strncpy(email,e, 119);  else email[0]=0; }
        if (is_admin)   *is_admin   = sqlite3_column_int(stmt, 3);
        if (is_deleted) *is_deleted = sqlite3_column_int(stmt, 4);
        if (created_at) { if(dt) strncpy(created_at, dt, 31); else created_at[0]=0; }
        ok = 1;
    }
    sqlite3_finalize(stmt);
    return ok;
}

int db_update_user(int user_id, const char *name, const char *email) {
    const char *sql = "UPDATE users SET name = ?, email = ? WHERE user_id = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(stmt, 1, name,  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, email, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, 3, user_id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

int db_update_password(int user_id, const char *new_hash) {
    const char *sql = "UPDATE users SET password_hash = ? WHERE user_id = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(stmt, 1, new_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, 2, user_id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

int db_ban_user(int user_id) {
    const char *sql = "UPDATE users SET is_deleted = 1 WHERE user_id = ? AND is_admin = 0;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(stmt, 1, user_id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE && sqlite3_changes(g_db) > 0);
}

int db_unban_user(int user_id) {
    const char *sql = "UPDATE users SET is_deleted = 0 WHERE user_id = ? AND is_admin = 0;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(stmt, 1, user_id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE && sqlite3_changes(g_db) > 0);
}

int db_user_is_banned(int user_id) {
    const char *sql = "SELECT is_deleted FROM users WHERE user_id = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(stmt, 1, user_id);
    int banned = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) banned = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return banned;
}

/* ================================================================
   ELECTIONS
   ================================================================ */

int db_create_election(const char *title, const char *desc,
                       const char *start, const char *end,
                       const char *status, int *out_id) {
    const char *sql =
        "INSERT INTO elections (title, description, start_date, end_date, status) "
        "VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(stmt, 1, title,  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, desc,   -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, start,  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, end,    -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, status, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc == SQLITE_DONE) {
        if (out_id) *out_id = (int)sqlite3_last_insert_rowid(g_db);
        return 1;
    }
    return 0;
}

int db_update_election(int eid, const char *title, const char *desc,
                       const char *start, const char *end) {
    const char *sql =
        "UPDATE elections SET title=?, description=?, start_date=?, end_date=? "
        "WHERE election_id=? AND is_deleted=0;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(stmt, 1, title, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, desc,  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, start, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, end,   -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, 5, eid);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

int db_delete_election(int eid, int by_uid) {
    const char *sql =
        "UPDATE elections SET is_deleted=1, deleted_at=datetime('now'), deleted_by=? "
        "WHERE election_id=? AND status='upcoming' AND "
        "(SELECT COUNT(*) FROM votes WHERE election_id=?)=0;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(stmt, 1, by_uid);
    sqlite3_bind_int(stmt, 2, eid);
    sqlite3_bind_int(stmt, 3, eid);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE && sqlite3_changes(g_db) > 0);
}

int db_get_total_votes_in_election(int eid) {
    const char *sql = "SELECT COUNT(*) FROM votes WHERE election_id=?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(stmt, 1, eid);
    int cnt = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) cnt = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return cnt;
}

void db_update_election_statuses(void) {
    sqlite3_exec(g_db,
        "UPDATE elections SET status='active' "
        "WHERE is_deleted=0 AND status!='closed' "
        "AND datetime('now') >= start_date AND datetime('now') < end_date;",
        0, 0, NULL);
    sqlite3_exec(g_db,
        "UPDATE elections SET status='closed' "
        "WHERE is_deleted=0 AND datetime('now') >= end_date;",
        0, 0, NULL);
    sqlite3_exec(g_db,
        "UPDATE elections SET status='upcoming' "
        "WHERE is_deleted=0 AND status!='active' AND status!='closed' "
        "AND datetime('now') < start_date;",
        0, 0, NULL);
}

/* ================================================================
   ELECTION VOTERS
   ================================================================ */

int db_set_election_voters(int eid, int *voter_ids, int count) {
    sqlite3_exec(g_db, "BEGIN;", 0, 0, NULL);
    char del[128];
    snprintf(del, sizeof(del),
        "DELETE FROM election_voters WHERE election_id=%d;", eid);
    sqlite3_exec(g_db, del, 0, 0, NULL);

    const char *ins =
        "INSERT OR IGNORE INTO election_voters (election_id, user_id) VALUES (?, ?);";
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(g_db, ins, -1, &stmt, NULL);
    for (int i = 0; i < count; i++) {
        sqlite3_reset(stmt);
        sqlite3_bind_int(stmt, 1, eid);
        sqlite3_bind_int(stmt, 2, voter_ids[i]);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    sqlite3_exec(g_db, "COMMIT;", 0, 0, NULL);
    return 1;
}

int db_is_eligible(int eid, int uid) {
    const char *sql =
        "SELECT 1 FROM election_voters WHERE election_id=? AND user_id=?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(stmt, 1, eid);
    sqlite3_bind_int(stmt, 2, uid);
    int ok = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return ok;
}

/* ================================================================
   CANDIDATES
   ================================================================ */

int db_add_candidate(int user_id, const char *cnic, const char *name,
                     const char *desc, int eid, const char *img, int app_id) {
    const char *sql =
        "INSERT INTO candidates (user_id, cnic, name, description, election_id, image_path, application_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int (stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, cnic,  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, name,  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, desc ? desc : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, 5, eid);
    sqlite3_bind_text(stmt, 6, img  ? img  : "default-candidate.png", -1, SQLITE_TRANSIENT);
    if (app_id > 0) sqlite3_bind_int(stmt, 7, app_id);
    else            sqlite3_bind_null(stmt, 7);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

int db_delete_candidate(int candidate_id) {
    const char *sql =
        "DELETE FROM candidates WHERE candidate_id=? AND "
        "(SELECT status FROM elections WHERE election_id="
        "(SELECT election_id FROM candidates WHERE candidate_id=?))='upcoming';";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(stmt, 1, candidate_id);
    sqlite3_bind_int(stmt, 2, candidate_id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE && sqlite3_changes(g_db) > 0);
}

int db_user_is_candidate(int user_id, int eid) {
    const char *sql =
        "SELECT 1 FROM candidates WHERE user_id=? AND election_id=?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_int(stmt, 2, eid);
    int ok = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return ok;
}

/* ================================================================
   APPLICATIONS
   ================================================================ */

int db_submit_application(int user_id, int eid, const char *desc,
                          const char *img_path, int *out_id) {
    const char *sql =
        "INSERT INTO candidate_applications (user_id, election_id, description, image_path) "
        "VALUES (?, ?, ?, ?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int (stmt, 1, user_id);
    sqlite3_bind_int (stmt, 2, eid);
    sqlite3_bind_text(stmt, 3, desc     ? desc     : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, img_path ? img_path : "default-candidate.png", -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc == SQLITE_DONE) {
        if (out_id) *out_id = (int)sqlite3_last_insert_rowid(g_db);
        return 1;
    }
    return 0;
}

int db_approve_application(int app_id, int admin_uid) {
    /* Read application details */
    const char *sel =
        "SELECT a.user_id, a.election_id, a.description, a.image_path, "
        "       u.cnic, u.name "
        "FROM candidate_applications a "
        "JOIN users u ON u.user_id = a.user_id "
        "WHERE a.application_id = ? AND a.status = 'pending';";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sel, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(stmt, 1, app_id);

    int uid = 0, eid = 0;
    char desc[1024]="", img[256]="", cnic[20]="", name[128]="";

    if (sqlite3_step(stmt) != SQLITE_ROW) { sqlite3_finalize(stmt); return 0; }
    uid = sqlite3_column_int(stmt, 0);
    eid = sqlite3_column_int(stmt, 1);
    const char *d = (const char*)sqlite3_column_text(stmt, 2);
    const char *i = (const char*)sqlite3_column_text(stmt, 3);
    const char *c = (const char*)sqlite3_column_text(stmt, 4);
    const char *n = (const char*)sqlite3_column_text(stmt, 5);
    if (d) strncpy(desc, d, 1023);
    if (i) strncpy(img,  i, 255);
    if (c) strncpy(cnic, c, 19);
    if (n) strncpy(name, n, 127);
    sqlite3_finalize(stmt);

    /* Create candidate */
    if (!db_add_candidate(uid, cnic, name, desc, eid, img, app_id)) return 0;

    /* Update application status */
    const char *upd =
        "UPDATE candidate_applications SET status='approved', "
        "reviewed_at=datetime('now'), reviewed_by=? WHERE application_id=?;";
    if (sqlite3_prepare_v2(g_db, upd, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(stmt, 1, admin_uid);
    sqlite3_bind_int(stmt, 2, app_id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

int db_reject_application(int app_id, int admin_uid, const char *reason) {
    const char *sql =
        "UPDATE candidate_applications SET status='rejected', "
        "reviewed_at=datetime('now'), reviewed_by=?, rejection_reason=? "
        "WHERE application_id=?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int (stmt, 1, admin_uid);
    sqlite3_bind_text(stmt, 2, reason ? reason : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, 3, app_id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

int db_user_has_applied(int user_id, int eid) {
    const char *sql =
        "SELECT application_id FROM candidate_applications "
        "WHERE user_id=? AND election_id=?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_int(stmt, 2, eid);
    int id = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) id = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return id;
}

/* ================================================================
   VOTES
   ================================================================ */

int db_cast_vote(int user_id, int candidate_id, int eid, const char *ip) {
    const char *sql =
        "INSERT OR IGNORE INTO votes (user_id, candidate_id, election_id, ip_address) "
        "VALUES (?, ?, ?, ?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int (stmt, 1, user_id);
    sqlite3_bind_int (stmt, 2, candidate_id);
    sqlite3_bind_int (stmt, 3, eid);
    sqlite3_bind_text(stmt, 4, ip ? ip : "", -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE && sqlite3_changes(g_db) > 0);
}

int db_user_has_voted(int user_id, int eid) {
    const char *sql =
        "SELECT 1 FROM votes WHERE user_id=? AND election_id=?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_int(stmt, 2, eid);
    int ok = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return ok;
}

/* ================================================================
   BATCH OPS
   ================================================================ */

int db_clear_voters(void) {
    sqlite3_exec(g_db, "DELETE FROM votes;", 0, 0, NULL);
    sqlite3_exec(g_db, "DELETE FROM candidate_applications;", 0, 0, NULL);
    sqlite3_exec(g_db, "DELETE FROM candidates;", 0, 0, NULL);
    sqlite3_exec(g_db, "DELETE FROM election_voters;", 0, 0, NULL);
    sqlite3_exec(g_db, "DELETE FROM users WHERE is_admin=0;", 0, 0, NULL);
    return 1;
}

int db_clear_elections(void) {
    sqlite3_exec(g_db, "DELETE FROM votes;", 0, 0, NULL);
    sqlite3_exec(g_db, "DELETE FROM candidate_applications;", 0, 0, NULL);
    sqlite3_exec(g_db, "DELETE FROM candidates;", 0, 0, NULL);
    sqlite3_exec(g_db, "DELETE FROM election_voters;", 0, 0, NULL);
    sqlite3_exec(g_db, "DELETE FROM elections;", 0, 0, NULL);
    return 1;
}

int db_reset_all(void) {
    sqlite3_exec(g_db, "DELETE FROM sessions;", 0, 0, NULL);
    sqlite3_exec(g_db, "DELETE FROM votes;", 0, 0, NULL);
    sqlite3_exec(g_db, "DELETE FROM candidate_applications;", 0, 0, NULL);
    sqlite3_exec(g_db, "DELETE FROM candidates;", 0, 0, NULL);
    sqlite3_exec(g_db, "DELETE FROM election_voters;", 0, 0, NULL);
    sqlite3_exec(g_db, "DELETE FROM elections;", 0, 0, NULL);
    sqlite3_exec(g_db, "DELETE FROM users;", 0, 0, NULL);
    sqlite3_exec(g_db, "DELETE FROM password_reset_requests;", 0, 0, NULL);
    return 1;
}

/* ================================================================
   PASSWORD RESET REQUESTS
   ================================================================ */

int db_create_password_reset_request(int user_id, const char *email) {
    /* Remove any existing pending request for this user first */
    const char *del = "DELETE FROM password_reset_requests WHERE user_id=? AND status='pending';";
    sqlite3_stmt *d;
    if (sqlite3_prepare_v2(g_db, del, -1, &d, NULL) == SQLITE_OK) {
        sqlite3_bind_int(d, 1, user_id); sqlite3_step(d); sqlite3_finalize(d);
    }
    const char *sql =
        "INSERT INTO password_reset_requests (user_id, email) VALUES (?, ?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int (stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, email, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

int db_has_pending_reset_request(int user_id) {
    const char *sql =
        "SELECT 1 FROM password_reset_requests WHERE user_id=? AND status='pending';";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(stmt, 1, user_id);
    int ok = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return ok;
}

int db_resolve_password_reset(int req_id, const char *new_hash) {
    /* Get user_id from request */
    const char *sel = "SELECT user_id FROM password_reset_requests WHERE req_id=?;";
    sqlite3_stmt *s;
    if (sqlite3_prepare_v2(g_db, sel, -1, &s, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(s, 1, req_id);
    int uid = 0;
    if (sqlite3_step(s) == SQLITE_ROW) uid = sqlite3_column_int(s, 0);
    sqlite3_finalize(s);
    if (!uid) return 0;
    /* Update password */
    db_update_password(uid, new_hash);
    /* Mark request resolved */
    const char *upd =
        "UPDATE password_reset_requests SET status='resolved', "
        "resolved_at=datetime('now') WHERE req_id=?;";
    sqlite3_stmt *u;
    if (sqlite3_prepare_v2(g_db, upd, -1, &u, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(u, 1, req_id);
    int rc = sqlite3_step(u);
    sqlite3_finalize(u);
    return rc == SQLITE_DONE;
}

void db_foreach_reset_request(db_reset_row_cb cb, void *user_data) {
    const char *sql =
        "SELECT r.req_id, r.user_id, u.name, r.email, u.cnic, r.requested_at, r.status "
        "FROM password_reset_requests r "
        "JOIN users u ON u.user_id = r.user_id "
        "ORDER BY r.status ASC, r.requested_at DESC;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int req_id = sqlite3_column_int(stmt, 0);
        int uid    = sqlite3_column_int(stmt, 1);
        const char *nm = (const char*)sqlite3_column_text(stmt, 2);
        const char *em = (const char*)sqlite3_column_text(stmt, 3);
        const char *cn = (const char*)sqlite3_column_text(stmt, 4);
        const char *ra = (const char*)sqlite3_column_text(stmt, 5);
        const char *st = (const char*)sqlite3_column_text(stmt, 6);
        cb(req_id, uid, nm?nm:"", em?em:"", cn?cn:"", ra?ra:"", st?st:"", user_data);
    }
    sqlite3_finalize(stmt);
}
