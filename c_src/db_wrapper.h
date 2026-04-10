#ifndef DB_WRAPPER_H
#define DB_WRAPPER_H

#include "sqlite3.h"

/* ---- Init ---- */
int db_init(const char *path);
sqlite3 *db_get(void);

/* ---- Users ---- */
int db_create_user(const char *cnic, const char *name, const char *email, const char *hash, int is_admin);
int db_verify_user_by_email(const char *email, const char *hash, int *uid, int *is_admin, int *is_deleted);
int db_verify_user_by_cnic(const char *cnic, const char *hash, int *uid, int *is_admin, int *is_deleted);
int db_get_user(int user_id, char *name, char *cnic, char *email, int *is_admin, int *is_deleted, char *created_at);
int db_update_user(int user_id, const char *name, const char *email);
int db_update_password(int user_id, const char *new_hash);
int db_ban_user(int user_id);
int db_unban_user(int user_id);
int db_user_is_banned(int user_id);

/* ---- Elections ---- */
int db_create_election(const char *title, const char *desc, const char *start, const char *end, const char *status, int *out_id);
int db_update_election(int eid, const char *title, const char *desc, const char *start, const char *end);
int db_delete_election(int eid, int by_uid);
int db_get_total_votes_in_election(int eid);
void db_update_election_statuses(void);

/* ---- Election Voters ---- */
int db_set_election_voters(int eid, int *voter_ids, int count);
int db_is_eligible(int eid, int uid);

/* ---- Candidates ---- */
int db_add_candidate(int user_id, const char *cnic, const char *name, const char *desc, int eid, const char *img, int app_id);
int db_delete_candidate(int candidate_id);

/* ---- Applications ---- */
int db_submit_application(int user_id, int eid, const char *desc, const char *img_path, int *out_id);
int db_approve_application(int app_id, int admin_uid);
int db_reject_application(int app_id, int admin_uid, const char *reason);
int db_user_has_applied(int user_id, int eid);
int db_user_is_candidate(int user_id, int eid);

/* ---- Votes ---- */
int db_cast_vote(int user_id, int candidate_id, int eid, const char *ip);
int db_user_has_voted(int user_id, int eid);

/* ---- Batch Ops ---- */
int db_clear_voters(void);
int db_clear_elections(void);
int db_reset_all(void);

/* ---- Password Reset Requests ---- */
int  db_create_password_reset_request(int user_id, const char *email);
int  db_has_pending_reset_request(int user_id);
int  db_resolve_password_reset(int req_id, const char *new_hash);
/* callback row: req_id, user_id, name, email, cnic, requested_at, status */
typedef void (*db_reset_row_cb)(int req_id, int uid, const char *name,
                                const char *email, const char *cnic,
                                const char *requested_at, const char *status,
                                void *user_data);
void db_foreach_reset_request(db_reset_row_cb cb, void *user_data);

#endif
