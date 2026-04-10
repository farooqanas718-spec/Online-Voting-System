#ifndef API_HANDLERS_H
#define API_HANDLERS_H

#include "mongoose.h"
#include "session.h"

/* Utility */
void send_redirect(struct mg_connection *c, const char *location);
void send_html_page(struct mg_connection *c, const char *path,
                    const char **keys, const char **vals, int kv_count);
void set_flash(char *flash_store, const char *msg, const char *type);
const char *get_cookie(const char *cookie_hdr, const char *name, char *out, int max);

/* Route Handlers */
void handle_login_get(struct mg_connection *c, struct mg_http_message *hm);
void handle_login_post(struct mg_connection *c, struct mg_http_message *hm);
void handle_logout(struct mg_connection *c, struct mg_http_message *hm);
void handle_voter_dashboard(struct mg_connection *c, struct mg_http_message *hm);
void handle_election_details(struct mg_connection *c, struct mg_http_message *hm, int eid);
void handle_cast_vote(struct mg_connection *c, struct mg_http_message *hm);
void handle_apply_get(struct mg_connection *c, struct mg_http_message *hm, int eid);
void handle_apply_post(struct mg_connection *c, struct mg_http_message *hm, int eid);
void handle_view_application(struct mg_connection *c, struct mg_http_message *hm, int app_id);
void handle_public_results(struct mg_connection *c, struct mg_http_message *hm, int eid);
void handle_admin_dashboard(struct mg_connection *c, struct mg_http_message *hm);
void handle_admin_voters(struct mg_connection *c, struct mg_http_message *hm);
void handle_admin_add_voter_get(struct mg_connection *c, struct mg_http_message *hm);
void handle_admin_add_voter_post(struct mg_connection *c, struct mg_http_message *hm);
void handle_admin_edit_voter_get(struct mg_connection *c, struct mg_http_message *hm, int uid);
void handle_admin_edit_voter_post(struct mg_connection *c, struct mg_http_message *hm, int uid);
void handle_admin_ban_voter(struct mg_connection *c, struct mg_http_message *hm, int uid);
void handle_admin_unban_voter(struct mg_connection *c, struct mg_http_message *hm, int uid);
void handle_admin_delete_voter_permanent(struct mg_connection *c, struct mg_http_message *hm, int uid);
void handle_admin_elections(struct mg_connection *c, struct mg_http_message *hm);
void handle_admin_create_election_get(struct mg_connection *c, struct mg_http_message *hm);
void handle_admin_create_election_post(struct mg_connection *c, struct mg_http_message *hm);
void handle_admin_edit_election_get(struct mg_connection *c, struct mg_http_message *hm, int eid);
void handle_admin_edit_election_post(struct mg_connection *c, struct mg_http_message *hm, int eid);
void handle_admin_election_voters_get(struct mg_connection *c, struct mg_http_message *hm, int eid);
void handle_admin_election_voters_post(struct mg_connection *c, struct mg_http_message *hm, int eid);
void handle_admin_delete_election(struct mg_connection *c, struct mg_http_message *hm, int eid);
void handle_admin_applications(struct mg_connection *c, struct mg_http_message *hm);
void handle_admin_election_applications(struct mg_connection *c, struct mg_http_message *hm, int eid);
void handle_admin_approve_application(struct mg_connection *c, struct mg_http_message *hm, int app_id);
void handle_admin_reject_application(struct mg_connection *c, struct mg_http_message *hm, int app_id);
void handle_admin_manage_candidates(struct mg_connection *c, struct mg_http_message *hm, int eid);
void handle_admin_add_candidate(struct mg_connection *c, struct mg_http_message *hm, int eid);
void handle_admin_delete_candidate(struct mg_connection *c, struct mg_http_message *hm, int cid);
void handle_admin_results(struct mg_connection *c, struct mg_http_message *hm, int eid);
void handle_admin_change_password_get(struct mg_connection *c, struct mg_http_message *hm);
void handle_admin_change_password_post(struct mg_connection *c, struct mg_http_message *hm);

/* Session helpers exposed to server.c */
Session get_session_from_request(struct mg_http_message *hm);

/* Forgot password / password reset */
void handle_forgot_password_get(struct mg_connection *c, struct mg_http_message *hm);
void handle_forgot_password_post(struct mg_connection *c, struct mg_http_message *hm);
void handle_admin_password_resets(struct mg_connection *c, struct mg_http_message *hm);
void handle_admin_resolve_reset(struct mg_connection *c, struct mg_http_message *hm, int req_id);

#endif
