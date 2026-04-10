#include "mongoose.h"
#include "db_wrapper.h"
#include "session.h"
#include "api_handlers.h"
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Helper macros for routing using mg_str fields */
#define URI_EQ(hm, path)     (strncmp((hm)->uri.buf, (path), (hm)->uri.len) == 0 && \
                               strlen(path) == (size_t)(hm)->uri.len)
#define URI_PREFIX(hm, pre)  (strncmp((hm)->uri.buf, (pre), strlen(pre)) == 0)
#define METHOD_IS(hm, m)     (strncmp((hm)->method.buf, (m), (hm)->method.len) == 0 && \
                               strlen(m) == (size_t)(hm)->method.len)
#define IS_GET(hm)           METHOD_IS(hm, "GET")
#define IS_POST(hm)          METHOD_IS(hm, "POST")

/* Extract integer segment from URI after a given prefix */
static int uri_int(struct mg_http_message *hm, const char *prefix) {
    int id = 0;
    const char *p = hm->uri.buf + strlen(prefix);
    sscanf(p, "%d", &id);
    return id;
}

/* Check if URI matches a prefix and optional suffix (e.g. prefix="/admin/voters/", suffix="/edit") */
static int uri_match_seg(const char *uri, size_t ulen, const char *prefix, const char *suffix) {
    size_t plen = strlen(prefix);
    size_t slen = suffix ? strlen(suffix) : 0;
    if (ulen < plen + 1) return 0;
    if (strncmp(uri, prefix, plen) != 0) return 0;
    if (slen == 0) return 1;  /* no suffix required */
    /* find suffix from end */
    if (ulen < plen + slen) return 0;
    return strncmp(uri + ulen - slen, suffix, slen) == 0;
}

static void route(struct mg_connection *c, int ev, void *ev_data) {
    if (ev != MG_EV_HTTP_MSG) return;
    struct mg_http_message *hm = (struct mg_http_message *)ev_data;

    const char *uri = hm->uri.buf;
    size_t ulen = hm->uri.len;

    /* Serve static files from public/ directory */
    if (strncmp(uri, "/css/", 5) == 0 ||
        strncmp(uri, "/js/",  4) == 0  ||
        strncmp(uri, "/images/", 8) == 0 ||
        (ulen == 12 && strncmp(uri, "/favicon.ico", 12) == 0)) {
        struct mg_http_serve_opts opts = {0};
        opts.root_dir = "public";
        mg_http_serve_dir(c, hm, &opts);
        return;
    }

    /* ---- AUTH ---- */
    if (URI_EQ(hm, "/login") && IS_GET(hm)) {
        handle_login_get(c, hm);
    } else if (URI_EQ(hm, "/login") && IS_POST(hm)) {
        handle_login_post(c, hm);
    } else if (URI_EQ(hm, "/logout")) {
        handle_logout(c, hm);
    } else if (URI_EQ(hm, "/forgot-password") && IS_GET(hm)) {
        handle_forgot_password_get(c, hm);
    } else if (URI_EQ(hm, "/forgot-password") && IS_POST(hm)) {
        handle_forgot_password_post(c, hm);

    /* ---- VOTER DASHBOARD ---- */
    } else if (URI_EQ(hm, "/dashboard")) {
        handle_voter_dashboard(c, hm);
    } else if (URI_EQ(hm, "/vote") && IS_POST(hm)) {
        handle_cast_vote(c, hm);

    /* ---- RESULTS ---- */
    } else if (strncmp(uri, "/results/", 9) == 0) {
        int eid = uri_int(hm, "/results/");
        handle_public_results(c, hm, eid);

    /* ---- ELECTION DETAILS & APPLY ---- */
    } else if (uri_match_seg(uri, ulen, "/election/", "/apply") && IS_GET(hm)) {
        int eid = uri_int(hm, "/election/");
        handle_apply_get(c, hm, eid);
    } else if (uri_match_seg(uri, ulen, "/election/", "/apply") && IS_POST(hm)) {
        int eid = uri_int(hm, "/election/");
        handle_apply_post(c, hm, eid);
    } else if (strncmp(uri, "/election/", 10) == 0) {
        int eid = uri_int(hm, "/election/");
        handle_election_details(c, hm, eid);
    } else if (strncmp(uri, "/applications/", 14) == 0) {
        int aid = uri_int(hm, "/applications/");
        handle_view_application(c, hm, aid);

    /* ---- ADMIN DASHBOARD ---- */
    } else if (URI_EQ(hm, "/admin/dashboard")) {
        handle_admin_dashboard(c, hm);
    } else if (URI_EQ(hm, "/admin/change-password") && IS_GET(hm)) {
        handle_admin_change_password_get(c, hm);
    } else if (URI_EQ(hm, "/admin/change-password") && IS_POST(hm)) {
        handle_admin_change_password_post(c, hm);
    } else if (URI_EQ(hm, "/admin/password-resets")) {
        handle_admin_password_resets(c, hm);
    } else if (uri_match_seg(uri, ulen, "/admin/password-resets/", "/resolve") && IS_POST(hm)) {
        int rid = uri_int(hm, "/admin/password-resets/");
        handle_admin_resolve_reset(c, hm, rid);

    /* ---- ADMIN VOTERS ---- */
    } else if (URI_EQ(hm, "/admin/voters/add") && IS_GET(hm)) {
        handle_admin_add_voter_get(c, hm);
    } else if (URI_EQ(hm, "/admin/voters/add") && IS_POST(hm)) {
        handle_admin_add_voter_post(c, hm);
    } else if (uri_match_seg(uri, ulen, "/admin/voters/", "/edit") && IS_GET(hm)) {
        int uid = uri_int(hm, "/admin/voters/");
        handle_admin_edit_voter_get(c, hm, uid);
    } else if (uri_match_seg(uri, ulen, "/admin/voters/", "/edit") && IS_POST(hm)) {
        int uid = uri_int(hm, "/admin/voters/");
        handle_admin_edit_voter_post(c, hm, uid);
    } else if (uri_match_seg(uri, ulen, "/admin/voters/", "/ban") && IS_POST(hm)) {
        int uid = uri_int(hm, "/admin/voters/");
        handle_admin_ban_voter(c, hm, uid);
    } else if (uri_match_seg(uri, ulen, "/admin/voters/", "/unban") && IS_POST(hm)) {
        int uid = uri_int(hm, "/admin/voters/");
        handle_admin_unban_voter(c, hm, uid);
    } else if (uri_match_seg(uri, ulen, "/admin/voters/", "/delete") && IS_POST(hm)) {
        int uid = uri_int(hm, "/admin/voters/");
        handle_admin_delete_voter_permanent(c, hm, uid);
    } else if (URI_EQ(hm, "/admin/voters")) {
        handle_admin_voters(c, hm);

    /* ---- ADMIN ELECTIONS ---- */
    } else if (URI_EQ(hm, "/admin/elections/create") && IS_GET(hm)) {
        handle_admin_create_election_get(c, hm);
    } else if (URI_EQ(hm, "/admin/elections/create") && IS_POST(hm)) {
        handle_admin_create_election_post(c, hm);
    } else if (uri_match_seg(uri, ulen, "/admin/elections/", "/candidates/add") && IS_POST(hm)) {
        int eid = uri_int(hm, "/admin/elections/");
        handle_admin_add_candidate(c, hm, eid);
    } else if (uri_match_seg(uri, ulen, "/admin/elections/", "/candidates")) {
        int eid = uri_int(hm, "/admin/elections/");
        handle_admin_manage_candidates(c, hm, eid);
    } else if (uri_match_seg(uri, ulen, "/admin/elections/", "/applications")) {
        int eid = uri_int(hm, "/admin/elections/");
        handle_admin_election_applications(c, hm, eid);
    } else if (uri_match_seg(uri, ulen, "/admin/elections/", "/voters") && IS_GET(hm)) {
        int eid = uri_int(hm, "/admin/elections/");
        handle_admin_election_voters_get(c, hm, eid);
    } else if (uri_match_seg(uri, ulen, "/admin/elections/", "/voters") && IS_POST(hm)) {
        int eid = uri_int(hm, "/admin/elections/");
        handle_admin_election_voters_post(c, hm, eid);
    } else if (uri_match_seg(uri, ulen, "/admin/elections/", "/delete") && IS_POST(hm)) {
        int eid = uri_int(hm, "/admin/elections/");
        handle_admin_delete_election(c, hm, eid);
    } else if (uri_match_seg(uri, ulen, "/admin/elections/", "/edit") && IS_GET(hm)) {
        int eid = uri_int(hm, "/admin/elections/");
        handle_admin_edit_election_get(c, hm, eid);
    } else if (uri_match_seg(uri, ulen, "/admin/elections/", "/edit") && IS_POST(hm)) {
        int eid = uri_int(hm, "/admin/elections/");
        handle_admin_edit_election_post(c, hm, eid);
    } else if (strncmp(uri, "/admin/results/", 15) == 0) {
        int eid = uri_int(hm, "/admin/results/");
        handle_admin_results(c, hm, eid);
    } else if (URI_EQ(hm, "/admin/elections")) {
        handle_admin_elections(c, hm);

    /* ---- ADMIN APPLICATIONS ---- */
    } else if (uri_match_seg(uri, ulen, "/admin/applications/", "/approve") && IS_POST(hm)) {
        int aid = uri_int(hm, "/admin/applications/");
        handle_admin_approve_application(c, hm, aid);
    } else if (uri_match_seg(uri, ulen, "/admin/applications/", "/reject") && IS_POST(hm)) {
        int aid = uri_int(hm, "/admin/applications/");
        handle_admin_reject_application(c, hm, aid);
    } else if (URI_EQ(hm, "/admin/applications")) {
        handle_admin_applications(c, hm);

    /* ---- ADMIN CANDIDATES ---- */
    } else if (uri_match_seg(uri, ulen, "/admin/candidates/", "/delete") && IS_POST(hm)) {
        int cid = uri_int(hm, "/admin/candidates/");
        handle_admin_delete_candidate(c, hm, cid);

    /* ---- ROOT redirect ---- */
    } else if (ulen == 1 && uri[0] == '/') {
        Session s = get_session_from_request(hm);
        if (s.valid) {
            const char *dest = s.is_admin ? "/admin/dashboard" : "/dashboard";
            mg_http_reply(c, 302, "Location: %s\r\n", "", dest);
        } else {
            mg_http_reply(c, 302, "Location: /login\r\n", "");
        }
    } else {
        mg_http_reply(c, 404, "Content-Type: text/html\r\n",
            "<h1 style='font-family:sans-serif;text-align:center;margin-top:4rem'>404 - Page Not Found</h1>"
            "<p style='text-align:center'><a href='/'>Go Home</a></p>");
    }
}

static void handle_cli(int argc, char *argv[]) {
    if (argc < 3) return;
    if (strcmp(argv[2], "update-admin") == 0 && argc >= 6) {
        const char *cnic  = argv[3];
        const char *email = argv[4];
        const char *pass  = argv[5];
        char hash[65]; sha256_string(pass, hash);
        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(db_get(),
            "SELECT user_id FROM users WHERE is_admin=1;", -1, &stmt, NULL);
        int exists = (sqlite3_step(stmt) == SQLITE_ROW);
        int uid = exists ? sqlite3_column_int(stmt, 0) : 0;
        sqlite3_finalize(stmt);
        if (exists) {
            db_update_password(uid, hash);
            sqlite3_stmt *s2;
            sqlite3_prepare_v2(db_get(),
                "UPDATE users SET email=?, cnic=? WHERE user_id=?;", -1, &s2, NULL);
            sqlite3_bind_text(s2, 1, email, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s2, 2, cnic,  -1, SQLITE_TRANSIENT);
            sqlite3_bind_int( s2, 3, uid);
            sqlite3_step(s2); sqlite3_finalize(s2);
        } else {
            db_create_user(cnic, "Administrator", email, hash, 1);
        }
        printf("Admin updated successfully.\n");
    } else if (strcmp(argv[2], "reset-db") == 0) {
        db_reset_all();
        printf("Database reset.\n");
    } else if (strcmp(argv[2], "clear-voters") == 0) {
        db_clear_voters();
        printf("Voters cleared.\n");
    } else if (strcmp(argv[2], "clear-elections") == 0) {
        db_clear_elections();
        printf("Elections cleared.\n");
    }
}

int main(int argc, char *argv[]) {
    /* Ensure instance folder exists */
    system("mkdir instance >nul 2>&1");

    if (!db_init("instance/voting_system.db")) {
        fprintf(stderr, "Failed to initialize database.\n");
        return 1;
    }

    /* Bootstrap admin if none exists */
    sqlite3_stmt *chk;
    sqlite3_prepare_v2(db_get(),
        "SELECT COUNT(*) FROM users WHERE is_admin=1;", -1, &chk, NULL);
    int admin_count = 0;
    if (sqlite3_step(chk) == SQLITE_ROW) admin_count = sqlite3_column_int(chk, 0);
    sqlite3_finalize(chk);
    if (admin_count == 0) {
        char hash[65]; sha256_string("Admin@123", hash);
        db_create_user("0000000000000", "Administrator", "admin@votingsystem.com", hash, 1);
        printf("[*] Admin account created: admin@votingsystem.com / Admin@123\n");
    }

    /* Handle CLI commands AFTER DB is open */
    if (argc >= 3 && strcmp(argv[1], "--cmd") == 0) {
        handle_cli(argc, argv);
        return 0;
    }

    struct mg_mgr mgr;
    mg_mgr_init(&mgr);
    mg_log_set(0);  /* silence debug output — errors only */
    mg_http_listen(&mgr, "http://0.0.0.0:5000", route, NULL);
    printf("=================================================\n");
    printf(" Voting System C Backend running on port 5000\n");
    printf(" URL: http://127.0.0.1:5000\n");
    printf(" Admin: admin@votingsystem.com / Admin@123\n");
    printf("=================================================\n");
    printf(" Press Ctrl+C to stop\n\n");

    for (;;) mg_mgr_poll(&mgr, 1000);

    mg_mgr_free(&mgr);
    return 0;
}
