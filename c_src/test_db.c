#include "db_wrapper.h"
#include <stdio.h>
#include "sqlite3.h"

extern sqlite3 *db; // Since it's static in db_wrapper.c, wait, I can't access it. Instead, I'll just write the query here.

int main() {
    sqlite3 *db;
    sqlite3_open("../instance/voting_system.db", &db);
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT cnic, password_hash, is_admin FROM users;", -1, &stmt, NULL);
    
    printf("USERS IN DB:\n");
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        printf("CNIC: %s | HASH: %s | ADMIN: %d\n", sqlite3_column_text(stmt, 0), sqlite3_column_text(stmt, 1), sqlite3_column_int(stmt, 2));
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}
