#ifndef SESSION_H
#define SESSION_H

#include "sqlite3.h"

#define SESSION_COOKIE_NAME "vs_session"
#define SESSION_EXPIRE_HOURS 24
#define SESSION_ID_LEN 32

typedef struct {
    char session_id[SESSION_ID_LEN + 1];
    int  user_id;
    char user_name[128];
    char user_cnic[20];
    char user_email[120];
    int  is_admin;
    int  valid;
} Session;

void session_init(sqlite3 *db);
void session_generate_id(char *out, int len);
int  session_create(sqlite3 *db, int user_id, const char *name, const char *cnic, const char *email, int is_admin, char *out_session_id);
Session session_get(sqlite3 *db, const char *session_id);
void session_destroy(sqlite3 *db, const char *session_id);
void session_cleanup_expired(sqlite3 *db);

#endif
