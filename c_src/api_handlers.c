#include "api_handlers.h"
#include "db_wrapper.h"
#include "sha256.h"
#include "session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ================================================================
   SHARED FLASH MESSAGE STORAGE  (per-request, simple ring buffer)
   ================================================================ */
static char g_flash_msg[512]  = "";
static char g_flash_type[32]  = "info";

void set_flash(char *flash_store, const char *msg, const char *type) {
    (void)flash_store;
    strncpy(g_flash_msg,  msg  ? msg  : "", 511);
    strncpy(g_flash_type, type ? type : "info", 31);
}

static void flush_flash(void) {
    g_flash_msg[0] = '\0';
    g_flash_type[0] = '\0';
}

/* ================================================================
   COOKIE HELPERS
   ================================================================ */
const char *get_cookie(const char *cookie_hdr, const char *name, char *out, int max) {
    if (!cookie_hdr) { out[0]=0; return NULL; }
    char search[64];
    snprintf(search, sizeof(search), "%s=", name);
    const char *p = strstr(cookie_hdr, search);
    if (!p) { out[0]=0; return NULL; }
    p += strlen(search);
    int i = 0;
    while (*p && *p != ';' && i < max-1) out[i++] = *p++;
    out[i] = 0;
    return out;
}

Session get_session_from_request(struct mg_http_message *hm) {
    struct mg_str *cookie_hdr = mg_http_get_header(hm, "Cookie");
    char sid[SESSION_ID_LEN + 1] = "";
    if (cookie_hdr) {
        char buf[256] = "";
        char tmp[cookie_hdr->len + 1];
        memcpy(tmp, cookie_hdr->buf, cookie_hdr->len);
        tmp[cookie_hdr->len] = '\0';
        get_cookie(tmp, SESSION_COOKIE_NAME, buf, sizeof(buf));
        strncpy(sid, buf, SESSION_ID_LEN);
    }
    return session_get(db_get(), sid);
}

/* ================================================================
   HTML TEMPLATE ENGINE (lightweight string replacement)
   ================================================================ */

static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *buf = malloc(sz + 1);
    if (!buf) { fclose(f); return NULL; }
    fread(buf, 1, sz, f);
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

/* Replace all occurrences of {{key}} with val in template src */
static char *str_replace(const char *src, const char *key, const char *val) {
    if (!src || !key || !val) return src ? strdup(src) : NULL;
    char placeholder[128];
    snprintf(placeholder, sizeof(placeholder), "{{%s}}", key);
    size_t plen = strlen(placeholder);
    size_t vlen = strlen(val);
    size_t slen = strlen(src);

    /* Count occurrences */
    int cnt = 0;
    const char *p = src;
    while ((p = strstr(p, placeholder))) { cnt++; p += plen; }
    if (cnt == 0) return strdup(src);

    size_t newsz = slen + (vlen - plen) * cnt + 1;
    char  *out   = malloc(newsz);
    if (!out) return strdup(src);

    char *dst = out;
    p = src;
    while (*p) {
        if (strncmp(p, placeholder, plen) == 0) {
            memcpy(dst, val, vlen);
            dst += vlen;
            p   += plen;
        } else {
            *dst++ = *p++;
        }
    }
    *dst = '\0';
    return out;
}

/* Load page, apply flash + multiple kv replacements, send */
void send_html_page(struct mg_connection *c, const char *path,
                    const char **keys, const char **vals, int kv_count) {
    char full_path[512];
    snprintf(full_path, sizeof(full_path), "public/pages/%s", path);

    char *tmpl = read_file(full_path);
    if (!tmpl) {
        mg_http_reply(c, 404, "", "Page not found: %s", path);
        return;
    }

    /* Inject flash */
    char flash_html[700] = "";
    if (g_flash_msg[0]) {
        snprintf(flash_html, sizeof(flash_html),
            "<div class=\"alert alert-%s\" id=\"flash-msg\">%s</div>",
            g_flash_type, g_flash_msg);
    }

    /* Apply replacements */
    char *cur = str_replace(tmpl, "FLASH_MESSAGE", flash_html);
    free(tmpl);
    flush_flash();

    for (int i = 0; i < kv_count; i++) {
        char *next = str_replace(cur, keys[i], vals[i]);
        free(cur);
        cur = next;
    }

    mg_http_reply(c, 200, "Content-Type: text/html\r\n", "%s", cur);
    free(cur);
}

void send_redirect(struct mg_connection *c, const char *location) {
    mg_http_reply(c, 302, "Location: %s\r\n", "", location);
}

/* ================================================================
   FORM PARSING HELPERS
   ================================================================ */
static int form_get(struct mg_http_message *hm, const char *key, char *out, int max) {
    struct mg_str val = mg_http_var(hm->body, mg_str(key));
    if (val.len == 0) { out[0]=0; return 0; }
    int n = val.len < (size_t)(max-1) ? (int)val.len : max-1;
    strncpy(out, val.buf, n);
    out[n] = 0;
    /* URL-decode '+' as space */
    for (int i=0;i<n;i++) if(out[i]=='+') out[i]=' ';
    mg_url_decode(out, strlen(out), out, max, 1);
    return 1;
}

static void clean_cnic(char *cnic) {
    char tmp[32]=""; int j=0;
    for (int i=0; cnic[i] && j<13; i++)
        if (isdigit((unsigned char)cnic[i])) tmp[j++]=cnic[i];
    tmp[j]=0;
    strncpy(cnic, tmp, 32);
}

static void format_cnic(const char *cnic, char *out) {
    if (strlen(cnic) == 13) {
        snprintf(out, 20, "%.5s-%.7s-%.1s", cnic, cnic+5, cnic+12);
    } else {
        strncpy(out, cnic, 20);
    }
}


/* Read flash from cookies */
static void read_flash_cookies(struct mg_http_message *hm) {
    struct mg_str *ch = mg_http_get_header(hm, "Cookie");
    if (!ch) return;
    char tmp[ch->len+1];
    memcpy(tmp, ch->buf, ch->len);
    tmp[ch->len]=0;
    char msg[512]="", type[32]="";
    get_cookie(tmp, "flash_msg",  msg,  sizeof(msg));
    get_cookie(tmp, "flash_type", type, sizeof(type));
    if (msg[0]) {
        /* URL-decode: converts %20 -> space, %2C -> comma, etc. */
        char decoded[512]="";
        mg_url_decode(msg, strlen(msg), decoded, sizeof(decoded)-1, 1);
        strncpy(g_flash_msg,  decoded[0] ? decoded : msg, 511);
        strncpy(g_flash_type, type[0] ? type : "info", 31);
    }
}

/* Send redirect WITH flash cookies set */
static void redirect_with_flash(struct mg_connection *c, const char *location,
                                const char *msg, const char *type) {
    char enc_msg[1024]="";
    /* Simple encoding: replace spaces with %20 */
    int j=0;
    for (int i=0;msg[i]&&j<1020;i++){
        if(msg[i]==' '){ enc_msg[j++]='%';enc_msg[j++]='2';enc_msg[j++]='0';}
        else if(msg[i]=='"'){ enc_msg[j++]='%';enc_msg[j++]='2';enc_msg[j++]='2';}
        else enc_msg[j++]=msg[i];
    }
    enc_msg[j]=0;
    char hdr[1200];
    snprintf(hdr, sizeof(hdr),
        "Location: %s\r\n"
        "Set-Cookie: flash_msg=%s; Path=/\r\n"
        "Set-Cookie: flash_type=%s; Path=/\r\n",
        location, enc_msg, type);
    mg_http_reply(c, 302, hdr, "");
}

/* ================================================================
   AUTH ROUTES
   ================================================================ */

void handle_login_get(struct mg_connection *c, struct mg_http_message *hm) {
    read_flash_cookies(hm);
    /* If already logged in, redirect */
    Session s = get_session_from_request(hm);
    if (s.valid) {
        send_redirect(c, s.is_admin ? "/admin/dashboard" : "/dashboard");
        return;
    }
    const char *k[] = {"IDENTIFIER_VAL"};
    const char *v[] = {""};
    send_html_page(c, "login.html", k, v, 1);
}

void handle_login_post(struct mg_connection *c, struct mg_http_message *hm) {
    char identifier[128]="", password[128]="";
    form_get(hm, "identifier", identifier, sizeof(identifier));
    form_get(hm, "password",   password,   sizeof(password));

    if (!identifier[0] || !password[0]) {
        redirect_with_flash(c, "/login", "Please provide both CNIC/Email and password.", "danger");
        return;
    }

    char hashed[65];
    sha256_string(password, hashed);

    int uid=0, is_admin=0, is_deleted=0, found=0;

    if (strchr(identifier, '@')) {
        /* Email login — admin only */
        found = db_verify_user_by_email(identifier, hashed, &uid, &is_admin, &is_deleted);
        if (found && !is_admin) {
            redirect_with_flash(c, "/login",
                "Voters must login using CNIC, not email.", "warning");
            return;
        }
        if (!found) {
            redirect_with_flash(c, "/login",
                "Admin email not found. Please check your credentials.", "danger");
            return;
        }
    } else {
        /* CNIC login — voters only */
        char cnic[32]; strncpy(cnic, identifier, 31); cnic[31]=0;
        clean_cnic(cnic);
        if (strlen(cnic) != 13) {
            redirect_with_flash(c, "/login",
                "Invalid CNIC format. CNIC must be 13 digits.", "danger");
            return;
        }
        found = db_verify_user_by_cnic(cnic, hashed, &uid, &is_admin, &is_deleted);
        if (!found) {
            redirect_with_flash(c, "/login",
                "You are not a registered voter. Please contact your administrator.", "warning");
            return;
        }
    }

    if (is_deleted) {
        redirect_with_flash(c, "/login",
            "This account has been banned. Please contact the administrator.", "danger");
        return;
    }

    /* Get user details */
    char name[128]="", cnic_str[20]="", email[120]="";
    int dummy1, dummy2; char dummy3[32];
    db_get_user(uid, name, cnic_str, email, &dummy1, &dummy2, dummy3);

    /* Create session */
    char sid[SESSION_ID_LEN+1]="";
    session_create(db_get(), uid, name, cnic_str, email, is_admin, sid);

    /* Set cookie and redirect */
    char cookie_hdr[256];
    snprintf(cookie_hdr, sizeof(cookie_hdr),
        "Set-Cookie: %s=%s; Path=/; HttpOnly\r\n"
        "Set-Cookie: flash_msg=Welcome%%20back%%2C%%20%s%%21; Path=/\r\n"
        "Set-Cookie: flash_type=success; Path=/\r\n",
        SESSION_COOKIE_NAME, sid, name);

    char full_hdr[512];
    snprintf(full_hdr, sizeof(full_hdr),
        "Set-Cookie: %s=%s; Path=/; HttpOnly\r\n"
        "Set-Cookie: flash_msg=Welcome%%20back%%2C%%20%s%%21; Path=/\r\n"
        "Set-Cookie: flash_type=success; Path=/\r\n"
        "Location: %s\r\n",
        SESSION_COOKIE_NAME, sid, name,
        is_admin ? "/admin/dashboard" : "/dashboard");
    mg_http_reply(c, 302, full_hdr, "");
}

void handle_logout(struct mg_connection *c, struct mg_http_message *hm) {
    Session s = get_session_from_request(hm);
    if (s.valid) session_destroy(db_get(), s.session_id);
    char logout_hdr[512];
    snprintf(logout_hdr, sizeof(logout_hdr),
        "Set-Cookie: %s=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT\r\n"
        "Set-Cookie: flash_msg=You%%20have%%20been%%20logged%%20out.; Path=/\r\n"
        "Set-Cookie: flash_type=success; Path=/\r\n"
        "Location: /login\r\n",
        SESSION_COOKIE_NAME);
    mg_http_reply(c, 302, logout_hdr, "");
}

/* ================================================================
   VOTER DASHBOARD
   ================================================================ */

void handle_voter_dashboard(struct mg_connection *c, struct mg_http_message *hm) {
    read_flash_cookies(hm);
    Session s = get_session_from_request(hm);
    if (!s.valid) { redirect_with_flash(c,"/login","Please log in.","warning"); return; }
    if (s.is_admin) { send_redirect(c, "/admin/dashboard"); return; }

    db_update_election_statuses();

    /* Query all non-deleted elections */
    sqlite3_stmt *stmt;
    const char *sql =
        "SELECT election_id, title, description, status, start_date, end_date "
        "FROM elections WHERE is_deleted=0 ORDER BY created_at DESC;";
    sqlite3_prepare_v2(db_get(), sql, -1, &stmt, NULL);

    /* Build election cards HTML */
    char cards[65536] = "";
    char row[4096];

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int eid    = sqlite3_column_int(stmt, 0);
        const char *title  = (const char*)sqlite3_column_text(stmt, 1);
        const char *desc   = (const char*)sqlite3_column_text(stmt, 2);
        const char *status = (const char*)sqlite3_column_text(stmt, 3);
        const char *sdate  = (const char*)sqlite3_column_text(stmt, 4);
        const char *edate  = (const char*)sqlite3_column_text(stmt, 5);

        /* Determine badges */
        const char *stat_col = "secondary";
        if (strcmp(status,"active")==0) stat_col="success";
        else if (strcmp(status,"upcoming")==0) stat_col="warning";
        else stat_col="secondary";

        int eligible = db_is_eligible(eid, s.user_id);
        int has_voted = db_user_has_voted(s.user_id, eid);
        int has_applied = db_user_has_applied(s.user_id, eid);
        int is_cand = db_user_is_candidate(s.user_id, eid);
        int total_candidates=0;
        {
            sqlite3_stmt *cs;
            char csql[128]; snprintf(csql,128,"SELECT COUNT(*) FROM candidates WHERE election_id=%d;",eid);
            sqlite3_prepare_v2(db_get(),csql,-1,&cs,NULL);
            if(sqlite3_step(cs)==SQLITE_ROW) total_candidates=sqlite3_column_int(cs,0);
            sqlite3_finalize(cs);
        }

        char desc_short[104]="";
        if (desc) { strncpy(desc_short, desc, 100); if(strlen(desc)>100) strcpy(desc_short+100,"..."); }

        char apply_btn[256]="", voted_alert[256]="", cand_alert[256]="", app_alert[256]="", results_btn[256]="";

        if (has_voted) snprintf(voted_alert,sizeof(voted_alert),
            "<div class=\"alert alert-success p-2 mb-3\">✅ You have voted in this election</div>");
        if (is_cand)   snprintf(cand_alert,sizeof(cand_alert),
            "<div class=\"alert alert-info p-2 mb-3\">ℹ️ You are a candidate in this election</div>");
        if (has_applied && !is_cand) {
            /* get status */
            sqlite3_stmt *as2;
            char asql[200]; snprintf(asql,200,"SELECT status FROM candidate_applications WHERE user_id=%d AND election_id=%d;",s.user_id,eid);
            sqlite3_prepare_v2(db_get(),asql,-1,&as2,NULL);
            char ast[20]="pending";
            if(sqlite3_step(as2)==SQLITE_ROW){ const char *t=(const char*)sqlite3_column_text(as2,0); if(t)strncpy(ast,t,19); }
            sqlite3_finalize(as2);
            const char *ac=strcmp(ast,"pending")==0?"warning":(strcmp(ast,"approved")==0?"success":"danger");
            snprintf(app_alert,sizeof(app_alert),
                "<div class=\"alert alert-%s p-2 mb-3\">Application: %s</div>",ac,ast);
        }
        if (eligible && strcmp(status,"upcoming")==0 && !has_applied && !is_cand)
            snprintf(apply_btn,sizeof(apply_btn),
                "<a href=\"/election/%d/apply\" class=\"btn btn-secondary btn-sm\">Apply as Candidate</a>", eid);
        if (strcmp(status,"closed")==0)
            snprintf(results_btn,sizeof(results_btn),
                "<a href=\"/results/%d\" class=\"btn btn-success btn-sm\">View Results</a>", eid);

        snprintf(row, sizeof(row),
            "<div class=\"col-md-6 col-lg-4\">"
            "<div class=\"card-glass p-6 h-100\">"
            "<div class=\"d-flex justify-content-between align-items-start mb-3\">"
            "<h2 class=\"h4 mb-0\">%s</h2>"
            "<div class=\"d-flex flex-column gap-2\">"
            "<span class=\"badge badge-%s\">%s</span>"
            "<span class=\"badge badge-%s\">%s</span>"
            "</div></div>"
            "<p class=\"text-gray mb-4\">%s</p>"
            "<div class=\"mb-4\">"
            "<small class=\"text-gray d-block\">📅 %s</small>"
            "<small class=\"text-gray d-block\">🏁 %s</small>"
            "<small class=\"text-gray d-block mt-2\">👥 %d candidates</small>"
            "</div>"
            "%s%s%s"
            "<div class=\"d-flex gap-2\">"
            "<a href=\"/election/%d\" class=\"btn btn-primary btn-sm\">View Details</a>"
            "%s%s"
            "</div>"
            "</div></div>",
            title ? title : "",
            stat_col, status ? status : "",
            eligible ? "success":"danger", eligible ? "✓ ELIGIBLE":"✗ NOT ELIGIBLE",
            desc_short,
            sdate ? sdate : "", edate ? edate : "",
            total_candidates,
            voted_alert, cand_alert, app_alert,
            eid, apply_btn, results_btn
        );
        strncat(cards, row, sizeof(cards)-strlen(cards)-1);
    }
    sqlite3_finalize(stmt);

    if (!cards[0]) {
        strncpy(cards,
            "<div class=\"col-12\"><div class=\"card-glass p-8 text-center\">"
            "<h2 class=\"h3 mb-3\">No Elections Available</h2>"
            "<p class=\"text-gray\">You are not currently eligible to participate in any elections.</p>"
            "</div></div>", sizeof(cards));
    }

    char cnic_fmt[20]; format_cnic(s.user_cnic, cnic_fmt);
    const char *k[] = {"USER_NAME", "USER_CNIC", "ELECTION_CARDS"};
    const char *v[] = {s.user_name, cnic_fmt, cards};
    send_html_page(c, "voter_dashboard.html", k, v, 3);
}

/* ================================================================
   ELECTION DETAILS + VOTING
   ================================================================ */

void handle_election_details(struct mg_connection *c, struct mg_http_message *hm, int eid) {
    read_flash_cookies(hm);
    Session s = get_session_from_request(hm);
    if (!s.valid) { redirect_with_flash(c,"/login","Please log in.","warning"); return; }

    db_update_election_statuses();

    /* Get election */
    sqlite3_stmt *stmt;
    const char *esql =
        "SELECT title, description, status, start_date, end_date FROM elections "
        "WHERE election_id=? AND is_deleted=0;";
    sqlite3_prepare_v2(db_get(), esql, -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, eid);
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        redirect_with_flash(c, s.is_admin?"/admin/elections":"/dashboard","Election not found.","danger");
        return;
    }
    char title[256]="", desc[2048]="", status[20]="", sdate[32]="", edate[32]="";
    const char *t=(const char*)sqlite3_column_text(stmt,0);
    const char *d=(const char*)sqlite3_column_text(stmt,1);
    const char *st=(const char*)sqlite3_column_text(stmt,2);
    const char *sd=(const char*)sqlite3_column_text(stmt,3);
    const char *ed=(const char*)sqlite3_column_text(stmt,4);
    if(t) strncpy(title,t,255); if(d) strncpy(desc,d,2047);
    if(st) strncpy(status,st,19); if(sd) strncpy(sdate,sd,31); if(ed) strncpy(edate,ed,31);
    sqlite3_finalize(stmt);

    int eligible  = db_is_eligible(eid, s.user_id);
    int has_voted = db_user_has_voted(s.user_id, eid);
    int total_votes = db_get_total_votes_in_election(eid);

    /* Alerts */
    char alerts[1024]="";
    if (has_voted) {
        strncat(alerts,
            "<div class=\"alert alert-success\"><h3 style=\"margin-bottom:var(--space-2);\">✓ Thank You for Voting!</h3>"
            "<p>Your vote has been recorded successfully. You cannot change your vote once submitted.</p></div>",
            sizeof(alerts)-strlen(alerts)-1);
    }
    if (strcmp(status,"active")!=0) {
        char tmp[256];
        snprintf(tmp,256,
            "<div class=\"alert alert-warning\"><h3 style=\"margin-bottom:var(--space-2);\">⚠️ Election Not Active</h3>"
            "<p>This election is currently %s. Voting is only available during the active period.</p></div>",status);
        strncat(alerts,tmp,sizeof(alerts)-strlen(alerts)-1);
    }
    if (!eligible) {
        strncat(alerts,
            "<div class=\"alert alert-warning\"><h3 style=\"margin-bottom:var(--space-2);\">⚠️ Not Eligible to Vote</h3>"
            "<p>You are not on the eligible voters list for this election.</p></div>",
            sizeof(alerts)-strlen(alerts)-1);
    }

    /* Candidates */
    const char *csql =
        "SELECT candidate_id, name, description, image_path FROM candidates WHERE election_id=?;";
    sqlite3_prepare_v2(db_get(), csql, -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, eid);

    char candidates_html[32768]="";
    int can_vote = (strcmp(status,"active")==0 && !has_voted && eligible);
    if (can_vote) {
        char form_open[256];
        snprintf(form_open,256,
            "<form method=\"POST\" action=\"/vote\" id=\"voteForm\">"
            "<input type=\"hidden\" name=\"election_id\" value=\"%d\">"
            "<div class=\"grid grid-3\">", eid);
        strncpy(candidates_html, form_open, sizeof(candidates_html));
    } else {
        strncpy(candidates_html, "<div class=\"grid grid-3\">", sizeof(candidates_html));
    }

    int cand_count=0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int cid = sqlite3_column_int(stmt, 0);
        const char *cn = (const char*)sqlite3_column_text(stmt, 1);
        const char *cd = (const char*)sqlite3_column_text(stmt, 2);
        const char *ci = (const char*)sqlite3_column_text(stmt, 3);
        char cname[128]="",cdesc[512]="";
        if(cn) strncpy(cname,cn,127); if(cd) strncpy(cdesc,cd,511);
        char img_tag[512];
        if (ci && strcmp(ci,"default-candidate.png")!=0)
            snprintf(img_tag,sizeof(img_tag),"<img src=\"/images/%s\" alt=\"%s\" class=\"candidate-image\">",ci,cname);
        else
            snprintf(img_tag,sizeof(img_tag),"<div class=\"candidate-image\" style=\"background:var(--gradient-primary);display:flex;align-items:center;justify-content:center;color:white;font-size:var(--text-3xl);font-weight:bold;\">%c</div>",cname[0]?cname[0]:'?');

        char card[2048];
        if (can_vote) {
            snprintf(card,sizeof(card),
                "<label class=\"candidate-card card\">"
                "<input type=\"radio\" name=\"candidate_id\" value=\"%d\" required>"
                "%s<h3 class=\"text-center mb-3\">%s</h3>"
                "<p class=\"text-sm text-gray text-center\">%s</p>"
                "</label>", cid, img_tag, cname, cdesc[0]?cdesc:"No description provided");
        } else {
            snprintf(card,sizeof(card),
                "<div class=\"card text-center\">"
                "%s<h3 class=\"mb-3\">%s</h3>"
                "<p class=\"text-sm text-gray\">%s</p>"
                "</div>", img_tag, cname, cdesc[0]?cdesc:"No description provided");
        }
        strncat(candidates_html, card, sizeof(candidates_html)-strlen(candidates_html)-1);
        cand_count++;
    }
    sqlite3_finalize(stmt);
    strncat(candidates_html, "</div>", sizeof(candidates_html)-strlen(candidates_html)-1);

    if (can_vote) {
        strncat(candidates_html,
            "<div class=\"text-center mt-8\">"
            "<button type=\"submit\" class=\"btn btn-success btn-lg\" "
            "onclick=\"return confirm('Are you sure you want to submit your vote? This action cannot be undone.')\">🗳️ Submit Vote</button>"
            "</div></form>", sizeof(candidates_html)-strlen(candidates_html)-1);
    }

    char no_cand[256]="";
    if (cand_count==0)
        strncpy(no_cand,"<div class=\"card text-center\" style=\"padding:var(--space-12);\"><h3 class=\"mb-3\">No Candidates Yet</h3><p class=\"text-gray\">Candidates have not been added yet.</p></div>",sizeof(no_cand));

    char eid_str[16]; snprintf(eid_str,16,"%d",eid);
    char tv_str[16]; snprintf(tv_str,16,"%d",total_votes);
    char cc_str[16]; snprintf(cc_str,16,"%d",cand_count);

    const char *stat_col = strcmp(status,"active")==0?"success":(strcmp(status,"upcoming")==0?"warning":"secondary");
    char back_url[64]; snprintf(back_url,64,"%s", s.is_admin?"/admin/elections":"/dashboard");

    const char *k[] = {"ELECTION_TITLE","ELECTION_DESC","ELECTION_STATUS","STATUS_COLOR",
                        "START_DATE","END_DATE","TOTAL_VOTES","TOTAL_CANDIDATES",
                        "ALERTS","CANDIDATES_HTML","NO_CANDIDATES","BACK_URL"};
    const char *v[] = {title,desc,status,stat_col,sdate,edate,tv_str,cc_str,
                        alerts,candidates_html,no_cand,back_url};
    send_html_page(c, "election_details.html", k, v, 12);
}

void handle_cast_vote(struct mg_connection *c, struct mg_http_message *hm) {
    Session s = get_session_from_request(hm);
    if (!s.valid) { redirect_with_flash(c,"/login","Please log in.","warning"); return; }

    char cid_s[16]="", eid_s[16]="";
    form_get(hm,"candidate_id",cid_s,sizeof(cid_s));
    form_get(hm,"election_id", eid_s,sizeof(eid_s));
    int cid=atoi(cid_s), eid=atoi(eid_s);

    if (!cid || !eid) {
        redirect_with_flash(c,"/dashboard","Invalid vote submission.","danger"); return;
    }

    db_update_election_statuses();

    /* Check election is active */
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db_get(),"SELECT status FROM elections WHERE election_id=? AND is_deleted=0;",-1,&stmt,NULL);
    sqlite3_bind_int(stmt,1,eid);
    char estatus[20]="";
    if(sqlite3_step(stmt)==SQLITE_ROW){const char *t=(const char*)sqlite3_column_text(stmt,0);if(t)strncpy(estatus,t,19);}
    sqlite3_finalize(stmt);

    if (strcmp(estatus,"active")!=0) {
        redirect_with_flash(c,"/dashboard","This election is not currently active.","warning"); return;
    }
    if (!db_is_eligible(eid, s.user_id)) {
        redirect_with_flash(c,"/dashboard","You are not eligible to vote in this election.","danger"); return;
    }
    /* Verify candidate belongs to election */
    sqlite3_prepare_v2(db_get(),"SELECT election_id FROM candidates WHERE candidate_id=?;",-1,&stmt,NULL);
    sqlite3_bind_int(stmt,1,cid);
    int cand_eid=0;
    if(sqlite3_step(stmt)==SQLITE_ROW) cand_eid=sqlite3_column_int(stmt,0);
    sqlite3_finalize(stmt);
    if (cand_eid != eid) {
        redirect_with_flash(c,"/dashboard","Invalid candidate selection.","danger"); return;
    }

    struct mg_str *peer = mg_http_get_header(hm,"X-Real-IP");
    char ip[64]="127.0.0.1";
    if (peer) { int n=peer->len<63?peer->len:63; memcpy(ip,peer->buf,n); ip[n]=0; }

    if (db_cast_vote(s.user_id, cid, eid, ip)) {
        char loc[64]; snprintf(loc,64,"/election/%d",eid);
        redirect_with_flash(c,loc,"Your vote has been recorded successfully!","success");
    } else {
        char loc[64]; snprintf(loc,64,"/election/%d",eid);
        redirect_with_flash(c,loc,"You have already voted in this election.","warning");
    }
}

/* ================================================================
   CANDIDATE APPLICATION
   ================================================================ */

void handle_apply_get(struct mg_connection *c, struct mg_http_message *hm, int eid) {
    read_flash_cookies(hm);
    Session s = get_session_from_request(hm);
    if (!s.valid) { redirect_with_flash(c,"/login","Please log in.","warning"); return; }

    /* Checks */
    if (!db_is_eligible(eid, s.user_id)) {
        redirect_with_flash(c,"/dashboard","You must be an eligible voter to apply.","danger"); return;
    }
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db_get(),"SELECT status FROM elections WHERE election_id=? AND is_deleted=0;",-1,&stmt,NULL);
    sqlite3_bind_int(stmt,1,eid);
    char estatus[20]="";
    if(sqlite3_step(stmt)==SQLITE_ROW){const char *t=(const char*)sqlite3_column_text(stmt,0);if(t)strncpy(estatus,t,19);}
    sqlite3_finalize(stmt);
    if (strcmp(estatus,"upcoming")!=0) {
        redirect_with_flash(c,"/dashboard","Applications only accepted for upcoming elections.","warning"); return;
    }
    int existing = db_user_has_applied(s.user_id, eid);
    if (existing) {
        char loc[64]; snprintf(loc,64,"/applications/%d",existing);
        redirect_with_flash(c,loc,"You have already applied for this election.","info"); return;
    }

    /* Get election title */
    char etitle[256]="";
    sqlite3_prepare_v2(db_get(),"SELECT title FROM elections WHERE election_id=?;",-1,&stmt,NULL);
    sqlite3_bind_int(stmt,1,eid);
    if(sqlite3_step(stmt)==SQLITE_ROW){const char *t=(const char*)sqlite3_column_text(stmt,0);if(t)strncpy(etitle,t,255);}
    sqlite3_finalize(stmt);

    char eid_str[16]; snprintf(eid_str,16,"%d",eid);
    char cnic_fmt[20]; format_cnic(s.user_cnic, cnic_fmt);
    const char *k[]={"ELECTION_TITLE","ELECTION_ID","USER_NAME","USER_CNIC_FMT"};
    const char *v[]={etitle,eid_str,s.user_name,cnic_fmt};
    send_html_page(c,"apply_candidate.html",k,v,4);
}

void handle_apply_post(struct mg_connection *c, struct mg_http_message *hm, int eid) {
    Session s = get_session_from_request(hm);
    if (!s.valid) { redirect_with_flash(c,"/login","Please log in.","warning"); return; }

    char desc[2048]="";
    form_get(hm,"description",desc,sizeof(desc));
    if (strlen(desc) < 10) {
        char loc[64]; snprintf(loc,64,"/election/%d/apply",eid);
        redirect_with_flash(c,loc,"Please provide a description (at least 10 characters).","danger");
        return;
    }

    int out_id=0;
    if (db_submit_application(s.user_id, eid, desc, "default-candidate.png", &out_id)) {
        redirect_with_flash(c,"/dashboard","Your application has been submitted for admin review.","success");
    } else {
        char loc[64]; snprintf(loc,64,"/election/%d/apply",eid);
        redirect_with_flash(c,loc,"You have already applied or an error occurred.","warning");
    }
}

void handle_view_application(struct mg_connection *c, struct mg_http_message *hm, int app_id) {
    read_flash_cookies(hm);
    Session s = get_session_from_request(hm);
    if (!s.valid) { redirect_with_flash(c,"/login","Please log in.","warning"); return; }

    sqlite3_stmt *stmt;
    const char *sql =
        "SELECT a.user_id, a.election_id, a.description, a.status, a.applied_at, "
        "       a.rejection_reason, e.title "
        "FROM candidate_applications a "
        "JOIN elections e ON e.election_id = a.election_id "
        "WHERE a.application_id=?;";
    sqlite3_prepare_v2(db_get(),sql,-1,&stmt,NULL);
    sqlite3_bind_int(stmt,1,app_id);
    if (sqlite3_step(stmt)!=SQLITE_ROW) {
        sqlite3_finalize(stmt);
        redirect_with_flash(c,"/dashboard","Application not found.","danger"); return;
    }
    int auid=sqlite3_column_int(stmt,0);
    if (auid != s.user_id && !s.is_admin) {
        sqlite3_finalize(stmt);
        redirect_with_flash(c,"/dashboard","Access denied.","danger"); return;
    }
    char adesc[2048]="",astatus[20]="",adate[32]="",areason[512]="",etitle[256]="";
    const char *td=(const char*)sqlite3_column_text(stmt,2);
    const char *ts=(const char*)sqlite3_column_text(stmt,3);
    const char *ta=(const char*)sqlite3_column_text(stmt,4);
    const char *tr=(const char*)sqlite3_column_text(stmt,5);
    const char *te=(const char*)sqlite3_column_text(stmt,6);
    if(td) strncpy(adesc,td,2047); if(ts) strncpy(astatus,ts,19);
    if(ta) strncpy(adate,ta,31);  if(tr) strncpy(areason,tr,511);
    if(te) strncpy(etitle,te,255);
    sqlite3_finalize(stmt);

    const char *sc=strcmp(astatus,"approved")==0?"success":(strcmp(astatus,"pending")==0?"warning":"danger");
    char reason_html[640]="";
    if (areason[0]) snprintf(reason_html,sizeof(reason_html),
        "<div class=\"alert alert-danger\"><strong>Rejection Reason:</strong> %s</div>",areason);

    const char *k[]={"ELECTION_TITLE","APP_STATUS","STATUS_COLOR","APP_DESC","APP_DATE","REASON_HTML"};
    const char *v[]={etitle,astatus,sc,adesc,adate,reason_html};
    send_html_page(c,"application_status.html",k,v,6);
}

/* ================================================================
   PUBLIC RESULTS
   ================================================================ */

void handle_public_results(struct mg_connection *c, struct mg_http_message *hm, int eid) {
    read_flash_cookies(hm);
    Session s = get_session_from_request(hm);
    if (!s.valid) { redirect_with_flash(c,"/login","Please log in.","warning"); return; }

    db_update_election_statuses();

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db_get(),"SELECT title,description,status FROM elections WHERE election_id=? AND is_deleted=0;",-1,&stmt,NULL);
    sqlite3_bind_int(stmt,1,eid);
    if(sqlite3_step(stmt)!=SQLITE_ROW){sqlite3_finalize(stmt);redirect_with_flash(c,"/dashboard","Election not found.","danger");return;}
    char etitle[256]="",edesc[1024]="",estatus[20]="";
    const char *t=(const char*)sqlite3_column_text(stmt,0);
    const char *d=(const char*)sqlite3_column_text(stmt,1);
    const char *st=(const char*)sqlite3_column_text(stmt,2);
    if(t)strncpy(etitle,t,255);if(d)strncpy(edesc,d,1023);if(st)strncpy(estatus,st,19);
    sqlite3_finalize(stmt);

    if (strcmp(estatus,"closed")!=0 && !s.is_admin) {
        redirect_with_flash(c,"/dashboard","Results are only available after the election closes.","warning");
        return;
    }

    int total_votes = db_get_total_votes_in_election(eid);

    /* Get results sorted by votes */
    const char *rsql =
        "SELECT c.candidate_id, c.name, c.description, "
        "COUNT(v.vote_id) as vote_count "
        "FROM candidates c "
        "LEFT JOIN votes v ON v.candidate_id=c.candidate_id "
        "WHERE c.election_id=? "
        "GROUP BY c.candidate_id ORDER BY vote_count DESC;";
    sqlite3_prepare_v2(db_get(),rsql,-1,&stmt,NULL);
    sqlite3_bind_int(stmt,1,eid);

    char winner_html[512]="";
    char results_rows[16384]="";
    int idx=0;

    while(sqlite3_step(stmt)==SQLITE_ROW) {
        const char *cn=(const char*)sqlite3_column_text(stmt,1);
        const char *cd=(const char*)sqlite3_column_text(stmt,2);
        int vc=sqlite3_column_int(stmt,3);
        char cname[128]="",cdesc[512]="";
        if(cn)strncpy(cname,cn,127);if(cd)strncpy(cdesc,cd,511);
        double pct = total_votes>0 ? (vc*100.0/total_votes) : 0.0;

        if(idx==0 && total_votes>0) {
            snprintf(winner_html,sizeof(winner_html),
                "<div class=\"card mb-8\" style=\"background:var(--gradient-primary);color:white;padding:var(--space-10);text-align:center;\">"
                "<div style=\"font-size:var(--text-5xl);margin-bottom:var(--space-4);\">🎉</div>"
                "<h2 class=\"mb-4\" style=\"color:white;\">Winner: %s</h2>"
                "<p style=\"font-size:var(--text-2xl);opacity:0.9;\">%d votes (%.1f%%)</p>"
                "</div>",cname,vc,pct);
        }

        char row[1024];
        snprintf(row,sizeof(row),
            "<div>"
            "<div style=\"display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--space-3);\">"
            "<div style=\"display:flex;align-items:center;gap:var(--space-4);\">"
            "<div style=\"width:50px;height:50px;background:var(--gradient-primary);border-radius:50%;display:flex;align-items:center;justify-content:center;color:white;font-weight:bold;font-size:var(--text-xl);\">#%d</div>"
            "<div><h3 class=\"mb-1\">%s</h3><p class=\"text-sm text-gray\">%s</p></div>"
            "</div>"
            "<div class=\"text-right\"><p class=\"fw-bold\" style=\"font-size:var(--text-2xl);color:var(--primary-600);\">%d</p><p class=\"text-sm text-gray\">votes</p></div>"
            "</div>"
            "<div class=\"progress\"><div class=\"progress-bar\" data-width=\"%.1f\" style=\"width:%.1f%%;\">%.1f%%</div></div>"
            "</div>",
            idx+1,cname,cdesc[0]?cdesc:"No description",vc,pct,pct,pct);
        strncat(results_rows,row,sizeof(results_rows)-strlen(results_rows)-1);
        idx++;
    }
    sqlite3_finalize(stmt);

    char tv_str[16]; snprintf(tv_str,16,"%d",total_votes);
    char tc_str[16]; snprintf(tc_str,16,"%d",idx);
    char back_url[64]; snprintf(back_url,64,"%s",s.is_admin?"/admin/elections":"/dashboard");
    const char *stat_col=strcmp(estatus,"active")==0?"success":(strcmp(estatus,"upcoming")==0?"warning":"secondary");

    char no_results[256]="";
    if(!idx) strncpy(no_results,"<div class=\"card text-center\" style=\"padding:var(--space-12);\"><h3 class=\"mb-3\">No Candidates</h3><p class=\"text-gray\">This election has no candidates.</p></div>",sizeof(no_results));

    const char *k[]={"ELECTION_TITLE","ELECTION_DESC","ELECTION_STATUS","STATUS_COLOR",
                      "TOTAL_VOTES","TOTAL_CANDIDATES","WINNER_HTML","RESULTS_ROWS","NO_RESULTS","BACK_URL"};
    const char *v[]={etitle,edesc,estatus,stat_col,tv_str,tc_str,winner_html,results_rows,no_results,back_url};
    send_html_page(c,"results.html",k,v,10);
}

/* ================================================================
   ADMIN DASHBOARD
   ================================================================ */

void handle_admin_dashboard(struct mg_connection *c, struct mg_http_message *hm) {
    read_flash_cookies(hm);
    Session s = get_session_from_request(hm);
    if(!s.valid){redirect_with_flash(c,"/login","Please log in.","warning");return;}
    if(!s.is_admin){redirect_with_flash(c,"/dashboard","Access denied.","danger");return;}

    db_update_election_statuses();

    /* Stats */
    sqlite3_stmt *stmt;
    int total_voters=0,total_elections=0,total_votes=0,active_elections=0,pending_apps=0;
    sqlite3_prepare_v2(db_get(),"SELECT COUNT(*) FROM users WHERE is_admin=0 AND is_deleted=0;",-1,&stmt,NULL);
    if(sqlite3_step(stmt)==SQLITE_ROW) total_voters=sqlite3_column_int(stmt,0);
    sqlite3_finalize(stmt);
    sqlite3_prepare_v2(db_get(),"SELECT COUNT(*) FROM elections WHERE is_deleted=0;",-1,&stmt,NULL);
    if(sqlite3_step(stmt)==SQLITE_ROW) total_elections=sqlite3_column_int(stmt,0);
    sqlite3_finalize(stmt);
    sqlite3_prepare_v2(db_get(),"SELECT COUNT(*) FROM votes;",-1,&stmt,NULL);
    if(sqlite3_step(stmt)==SQLITE_ROW) total_votes=sqlite3_column_int(stmt,0);
    sqlite3_finalize(stmt);
    sqlite3_prepare_v2(db_get(),"SELECT COUNT(*) FROM elections WHERE status='active' AND is_deleted=0;",-1,&stmt,NULL);
    if(sqlite3_step(stmt)==SQLITE_ROW) active_elections=sqlite3_column_int(stmt,0);
    sqlite3_finalize(stmt);
    sqlite3_prepare_v2(db_get(),"SELECT COUNT(*) FROM candidate_applications WHERE status='pending';",-1,&stmt,NULL);
    if(sqlite3_step(stmt)==SQLITE_ROW) pending_apps=sqlite3_column_int(stmt,0);
    sqlite3_finalize(stmt);

    /* Recent elections table */
    const char *esql =
        "SELECT election_id, title, status, start_date, "
        "(SELECT COUNT(*) FROM election_voters WHERE election_id=e.election_id) "
        "FROM elections e WHERE is_deleted=0 ORDER BY created_at DESC LIMIT 5;";
    sqlite3_prepare_v2(db_get(),esql,-1,&stmt,NULL);
    char recent_rows[8192]="";
    while(sqlite3_step(stmt)==SQLITE_ROW){
        int rid=sqlite3_column_int(stmt,0);
        const char *rt=(const char*)sqlite3_column_text(stmt,1);
        const char *rs=(const char*)sqlite3_column_text(stmt,2);
        const char *rsd=(const char*)sqlite3_column_text(stmt,3);
        int rv=sqlite3_column_int(stmt,4);
        char row[512];
        const char *sc=strcmp(rs,"active")==0?"success":"secondary";
        snprintf(row,512,
            "<tr><td>%s</td><td><span class=\"badge badge-%s\">%s</span></td>"
            "<td>%s</td><td>%d voters</td>"
            "<td><a href=\"/admin/elections/%d/applications\" class=\"btn btn-sm btn-outline\">View</a></td></tr>",
            rt?rt:"",sc,rs?rs:"",rsd?rsd:"",rv,rid);
        strncat(recent_rows,row,sizeof(recent_rows)-strlen(recent_rows)-1);
    }
    sqlite3_finalize(stmt);

    /* Pending applications */
    const char *asql =
        "SELECT a.application_id, u.name, u.cnic, e.title, a.applied_at "
        "FROM candidate_applications a "
        "JOIN users u ON u.user_id=a.user_id "
        "JOIN elections e ON e.election_id=a.election_id "
        "WHERE a.status='pending' ORDER BY a.applied_at DESC LIMIT 10;";
    sqlite3_prepare_v2(db_get(),asql,-1,&stmt,NULL);
    char pending_rows[8192]="";
    while(sqlite3_step(stmt)==SQLITE_ROW){
        int aid=sqlite3_column_int(stmt,0);
        const char *an=(const char*)sqlite3_column_text(stmt,1);
        const char *ac=(const char*)sqlite3_column_text(stmt,2);
        const char *ae=(const char*)sqlite3_column_text(stmt,3);
        const char *aat=(const char*)sqlite3_column_text(stmt,4);
        char cnic_fmt[20]=""; if(ac) format_cnic(ac,cnic_fmt);
        char row[1024];
        snprintf(row,sizeof(row),
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td><form method=\"POST\" action=\"/admin/applications/%d/approve\" style=\"display:inline;\">"
            "<button type=\"submit\" class=\"btn btn-sm btn-success\">Approve</button></form>"
            "<button type=\"button\" class=\"btn btn-sm btn-danger\" "
            "onclick=\"rejectApplication(%d)\">Reject</button></td></tr>",
            an?an:"",cnic_fmt,ae?ae:"",aat?aat:"",aid,aid);
        strncat(pending_rows,row,sizeof(pending_rows)-strlen(pending_rows)-1);
    }
    sqlite3_finalize(stmt);

    /* Pending password reset requests count */
    int pending_resets=0;
    sqlite3_prepare_v2(db_get(),"SELECT COUNT(*) FROM password_reset_requests WHERE status='pending';",-1,&stmt,NULL);
    if(sqlite3_step(stmt)==SQLITE_ROW) pending_resets=sqlite3_column_int(stmt,0);
    sqlite3_finalize(stmt);

    char tv_s[16],te_s[16],ta_s[16],tae_s[16],tp_s[16],tr_s[16];
    snprintf(tv_s,16,"%d",total_voters);
    snprintf(te_s,16,"%d",total_elections);
    snprintf(ta_s,16,"%d",total_votes);
    snprintf(tae_s,16,"%d",active_elections);
    snprintf(tp_s,16,"%d",pending_apps);
    snprintf(tr_s,16,"%d",pending_resets);

    /* Reset card styling — red border + color when there are pending requests */
    const char *reset_color  = pending_resets > 0 ? "#dc3545" : "inherit";
    const char *reset_border = pending_resets > 0 ? "2px solid rgba(220,53,69,0.5)" : "";

    char pa_section[9000]="";
    if(pending_rows[0]) {
        snprintf(pa_section,sizeof(pa_section),
            "<div class=\"card-glass p-6\">"
            "<h2 class=\"h3 mb-4\">Pending Applications</h2>"
            "<div class=\"table-responsive\"><table class=\"table\">"
            "<thead><tr><th>Applicant</th><th>CNIC</th><th>Election</th><th>Applied At</th><th>Actions</th></tr></thead>"
            "<tbody>%s</tbody></table></div></div>",
            pending_rows);
    }

    const char *k[]={"TOTAL_VOTERS","TOTAL_ELECTIONS","TOTAL_VOTES","ACTIVE_ELECTIONS",
                      "PENDING_APPS","RECENT_ROWS","PENDING_APPS_STR","PENDING_SECTION",
                      "RESET_REQUESTS","RESET_COLOR","RESET_BORDER","USER_NAME"};
    const char *v[]={tv_s,te_s,ta_s,tae_s,tp_s,recent_rows,tp_s,pa_section,
                     tr_s,reset_color,reset_border,s.user_name};
    send_html_page(c,"admin_dashboard.html",k,v,12);
}

/* ================================================================
   ADMIN VOTER MANAGEMENT
   ================================================================ */

void handle_admin_voters(struct mg_connection *c, struct mg_http_message *hm) {
    read_flash_cookies(hm);
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}

    char search[128]="";
    struct mg_str qs = hm->query;
    if (qs.len) {
        char tmp[qs.len+1]; memcpy(tmp,qs.buf,qs.len); tmp[qs.len]=0;
        mg_url_decode(tmp, strlen(tmp), search, sizeof(search), 1);
        /* extract search=value */
        char *p = strstr(search,"search=");
        if(p) {
            memmove(search,p+7,strlen(p+7)+1);
            char *amp=strchr(search,'&'); if(amp)*amp=0;
            for(int i=0;search[i];i++) if(search[i]=='+') search[i]=' ';
            mg_url_decode(search,strlen(search),search,sizeof(search),1);
        } else { search[0]=0; }
    }

    /* Check ?filter=resets to show only voters with pending reset requests */
    int filter_resets = 0;
    if(qs.len) {
        char qsbuf[256]; int qsn=qs.len<255?qs.len:255;
        memcpy(qsbuf,qs.buf,qsn); qsbuf[qsn]=0;
        if(strstr(qsbuf,"filter=resets")) filter_resets=1;
    }

    const char *vsql;
    char vsql_like[512];
    sqlite3_stmt *stmt;

    if(filter_resets) {
        vsql="SELECT u.user_id,u.name,u.cnic,u.email,u.is_deleted,u.created_at "
             "FROM users u "
             "INNER JOIN password_reset_requests r ON r.user_id=u.user_id AND r.status='pending' "
             "WHERE u.is_admin=0 ORDER BY u.name ASC;";
        sqlite3_prepare_v2(db_get(),vsql,-1,&stmt,NULL);
    } else if (search[0]) {
        snprintf(vsql_like,sizeof(vsql_like),
            "SELECT user_id,name,cnic,email,is_deleted,created_at FROM users WHERE is_admin=0 "
            "AND (name LIKE '%%%s%%' OR cnic LIKE '%%%s%%' OR email LIKE '%%%s%%') "
            "ORDER BY is_deleted ASC, created_at DESC;",search,search,search);
        sqlite3_prepare_v2(db_get(),vsql_like,-1,&stmt,NULL);
    } else {
        vsql="SELECT user_id,name,cnic,email,is_deleted,created_at FROM users WHERE is_admin=0 "
             "ORDER BY is_deleted ASC, created_at DESC;";
        sqlite3_prepare_v2(db_get(),vsql,-1,&stmt,NULL);
    }

    /* Build a lookup set of user_ids with pending reset requests */
    char reset_uids[4096]=",";
    sqlite3_stmt *rstmt;
    sqlite3_prepare_v2(db_get(),
        "SELECT user_id FROM password_reset_requests WHERE status='pending';",
        -1,&rstmt,NULL);
    while(sqlite3_step(rstmt)==SQLITE_ROW){
        char tmp[16]; snprintf(tmp,16,"%d,",sqlite3_column_int(rstmt,0));
        strncat(reset_uids,tmp,sizeof(reset_uids)-strlen(reset_uids)-1);
    }
    sqlite3_finalize(rstmt);

    char rows[32768]="";
    int count=0;
    while(sqlite3_step(stmt)==SQLITE_ROW){
        int uid=sqlite3_column_int(stmt,0);
        const char *nm=(const char*)sqlite3_column_text(stmt,1);
        const char *cn=(const char*)sqlite3_column_text(stmt,2);
        const char *em=(const char*)sqlite3_column_text(stmt,3);
        int banned=sqlite3_column_int(stmt,4);
        const char *dt=(const char*)sqlite3_column_text(stmt,5);
        char cnic_fmt[20]=""; if(cn) format_cnic(cn,cnic_fmt);
        char date_str[12]=""; if(dt&&strlen(dt)>=10){strncpy(date_str,dt,10);}

        /* Check if this voter has a pending reset request */
        char uid_needle[16]; snprintf(uid_needle,16,",%d,",uid);
        int has_reset = (strstr(reset_uids, uid_needle) != NULL);

        /* Row style: red background for pending reset, yellow for banned */
        const char *row_style;
        if(has_reset && !banned)
            row_style=" style=\"background:rgba(220,53,69,0.12);border-left:4px solid #dc3545;\"";
        else if(banned)
            row_style=" style=\"opacity:0.6;background-color:#fff3cd;\"";
        else
            row_style="";

        char reset_badge[100]="";
        if(has_reset)
            snprintf(reset_badge,sizeof(reset_badge),
                " <span class=\"badge badge-danger\" title=\"Password reset requested\">🔑 Reset</span>");

        char action_btns[1024];
        if(!banned)
            snprintf(action_btns,sizeof(action_btns),
                "<a href=\"/admin/voters/%d/edit\" class=\"btn btn-sm btn-info\">✏️ Edit</a>"
                "<form method=\"POST\" action=\"/admin/voters/%d/ban\" style=\"display:inline;\""
                " onsubmit=\"return confirm('Ban this voter?');\"><button type=\"submit\" class=\"btn btn-sm btn-warning\">🚫 Ban</button></form>"
                "<form method=\"POST\" action=\"/admin/voters/%d/delete\" style=\"display:inline;\""
                " onsubmit=\"return confirm('Permanently delete this voter and ALL their data?\\nThis cannot be undone!');\"><button type=\"submit\" class=\"btn btn-sm btn-danger\">🗑️</button></form>",
                uid,uid,uid);
        else
            snprintf(action_btns,sizeof(action_btns),
                "<form method=\"POST\" action=\"/admin/voters/%d/unban\" style=\"display:inline;\"><button type=\"submit\" class=\"btn btn-sm btn-success\">✅ Unban</button></form>"
                "<form method=\"POST\" action=\"/admin/voters/%d/delete\" style=\"display:inline;\""
                " onsubmit=\"return confirm('Permanently delete this voter and ALL their data?\\nThis cannot be undone!');\"><button type=\"submit\" class=\"btn btn-sm btn-danger\">🗑️</button></form>",
                uid,uid);

        char row[1200];
        snprintf(row,sizeof(row),
            "<tr%s><td>%s%s</td><td>%s</td><td>%s</td>"
            "<td><span class=\"badge badge-%s\">%s</span></td>"
            "<td>%s</td><td>%s</td></tr>",
            row_style,
            nm?nm:"", reset_badge, cnic_fmt, em?em:"",
            banned?"danger":"success", banned?"BANNED":"Active",
            date_str, action_btns);
        strncat(rows,row,sizeof(rows)-strlen(rows)-1);
        count++;
    }
    sqlite3_finalize(stmt);

    char count_str[16]; snprintf(count_str,16,"%d",count);
    char no_voters[256]="";
    if(!count){
        if(filter_resets)
            snprintf(no_voters,sizeof(no_voters),
                "<p class=\"text-gray\">No voters with pending password reset requests.</p>");
        else
            snprintf(no_voters,sizeof(no_voters),
                "<p class=\"text-gray\">No voters found%s%s%s.</p>",
                search[0]?" matching \"":"",search,search[0]?"\"":"");
    }

    /* Page heading changes when filter active */
    const char *heading = filter_resets ?
        "🔑 Voters with Password Reset Requests" : "Manage Voters";

    const char *k[]={"SEARCH_QUERY","VOTER_COUNT","VOTER_ROWS","NO_VOTERS_MSG","USER_NAME","PAGE_HEADING"};
    const char *v[]={search,count_str,rows,no_voters,s.user_name,heading};
    send_html_page(c,"admin_manage_voters.html",k,v,6);
}

void handle_admin_add_voter_get(struct mg_connection *c, struct mg_http_message *hm) {
    read_flash_cookies(hm);
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}
    const char *k[]={"NAME_VAL","CNIC_VAL","EMAIL_VAL","USER_NAME"};
    const char *v[]={"","","",s.user_name};
    send_html_page(c,"admin_add_voter.html",k,v,4);
}

void handle_admin_add_voter_post(struct mg_connection *c, struct mg_http_message *hm) {
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}
    char name[128]="",cnic[32]="",email[128]="",password[128]="";
    form_get(hm,"name",name,sizeof(name));
    form_get(hm,"cnic",cnic,sizeof(cnic));
    form_get(hm,"email",email,sizeof(email));
    form_get(hm,"password",password,sizeof(password));

    clean_cnic(cnic);
    if(strlen(name)<2||strlen(cnic)!=13||strlen(email)<5||strlen(password)<8){
        redirect_with_flash(c,"/admin/voters/add",
            "Validation failed. Check name (2+ chars), CNIC (13 digits), email, password (8+ chars).","danger");
        return;
    }
    char hashed[65]; sha256_string(password,hashed);
    if(db_create_user(cnic,name,email,hashed,0)){
        redirect_with_flash(c,"/admin/voters","Voter added successfully.","success");
    } else {
        redirect_with_flash(c,"/admin/voters/add","CNIC or email already exists.","danger");
    }
}

void handle_admin_edit_voter_get(struct mg_connection *c, struct mg_http_message *hm, int uid) {
    read_flash_cookies(hm);
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}
    char name[128]="",cnic[20]="",email[120]="",created_at[32]="";
    int is_adm=0,is_del=0;
    if(!db_get_user(uid,name,cnic,email,&is_adm,&is_del,created_at)||is_adm){
        redirect_with_flash(c,"/admin/voters","Voter not found.","danger");return;
    }
    char cnic_fmt[20]; format_cnic(cnic,cnic_fmt);
    char uid_s[16]; snprintf(uid_s,16,"%d",uid);
    const char *k[]={"VOTER_ID","VOTER_NAME","VOTER_CNIC","VOTER_EMAIL","USER_NAME"};
    const char *v[]={uid_s,name,cnic_fmt,email,s.user_name};
    send_html_page(c,"admin_edit_voter.html",k,v,5);
}

void handle_admin_edit_voter_post(struct mg_connection *c, struct mg_http_message *hm, int uid) {
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}
    /* CNIC is NOT accepted from form — it is read-only. Email can be updated. */
    char name[128]="", email[128]="", new_password[128]="";
    form_get(hm,"name",name,sizeof(name));
    form_get(hm,"email",email,sizeof(email));
    form_get(hm,"new_password",new_password,sizeof(new_password));

    if(strlen(name)<2 || strlen(email)<5 || !strchr(email,'@')){
        char loc[64]; snprintf(loc,64,"/admin/voters/%d/edit",uid);
        redirect_with_flash(c,loc,"Name (2+ chars) and valid email required.","danger");
        return;
    }
    db_update_user(uid, name, email);
    if(new_password[0] && strlen(new_password)>=6){
        char hashed[65]; sha256_string(new_password,hashed);
        db_update_password(uid,hashed);
        /* Auto-resolve any pending password reset request for this voter */
        const char *del_reset =
            "UPDATE password_reset_requests SET status='resolved', "
            "resolved_at=datetime('now') WHERE user_id=? AND status='pending';";
        sqlite3_stmt *rs;
        if(sqlite3_prepare_v2(db_get(),del_reset,-1,&rs,NULL)==SQLITE_OK){
            sqlite3_bind_int(rs,1,uid);
            sqlite3_step(rs);
            sqlite3_finalize(rs);
        }
    }
    redirect_with_flash(c,"/admin/voters","Voter updated successfully.","success");
}

void handle_admin_ban_voter(struct mg_connection *c, struct mg_http_message *hm, int uid) {
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){send_redirect(c,"/login");return;}
    if(db_ban_user(uid)) redirect_with_flash(c,"/admin/voters","Voter banned.","success");
    else                  redirect_with_flash(c,"/admin/voters","Could not ban voter.","danger");
}

void handle_admin_unban_voter(struct mg_connection *c, struct mg_http_message *hm, int uid) {
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){send_redirect(c,"/login");return;}
    if(db_unban_user(uid)) redirect_with_flash(c,"/admin/voters","Voter unbanned.","success");
    else                    redirect_with_flash(c,"/admin/voters","Could not unban voter.","danger");
}

void handle_admin_delete_voter_permanent(struct mg_connection *c, struct mg_http_message *hm, int uid) {
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){send_redirect(c,"/login");return;}
    /* Safety: cannot delete admins */
    char nm[128]=""; int ia=0,idel=0; char cn[32]="",em[128]="",cat[32]="";
    if(!db_get_user(uid,nm,cn,em,&ia,&idel,cat)||ia){
        redirect_with_flash(c,"/admin/voters","Voter not found or cannot delete admin.","danger");
        return;
    }
    /* Hard-delete all related data then the user */
    sqlite3 *db = db_get();
    sqlite3_exec(db,"BEGIN;",0,0,NULL);
    char sql[256];
    snprintf(sql,sizeof(sql),"DELETE FROM votes WHERE user_id=%d;",uid);
    sqlite3_exec(db,sql,0,0,NULL);
    snprintf(sql,sizeof(sql),"DELETE FROM candidate_applications WHERE user_id=%d;",uid);
    sqlite3_exec(db,sql,0,0,NULL);
    snprintf(sql,sizeof(sql),"DELETE FROM candidates WHERE user_id=%d;",uid);
    sqlite3_exec(db,sql,0,0,NULL);
    snprintf(sql,sizeof(sql),"DELETE FROM election_voters WHERE user_id=%d;",uid);
    sqlite3_exec(db,sql,0,0,NULL);
    snprintf(sql,sizeof(sql),"DELETE FROM sessions WHERE user_id=%d;",uid);
    sqlite3_exec(db,sql,0,0,NULL);
    snprintf(sql,sizeof(sql),"DELETE FROM password_reset_requests WHERE user_id=%d;",uid);
    sqlite3_exec(db,sql,0,0,NULL);
    snprintf(sql,sizeof(sql),"DELETE FROM users WHERE user_id=%d AND is_admin=0;",uid);
    sqlite3_exec(db,sql,0,0,NULL);
    sqlite3_exec(db,"COMMIT;",0,0,NULL);
    char msg[200];
    snprintf(msg,sizeof(msg),"Voter '%s' permanently deleted from the system.",nm);
    redirect_with_flash(c,"/admin/voters",msg,"success");
}

/* ================================================================
   ADMIN ELECTIONS
   ================================================================ */

void handle_admin_elections(struct mg_connection *c, struct mg_http_message *hm) {
    read_flash_cookies(hm);
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}

    db_update_election_statuses();

    sqlite3_stmt *stmt;
    const char *esql=
        "SELECT e.election_id, e.title, e.status, e.start_date, e.end_date,"
        "(SELECT COUNT(*) FROM election_voters WHERE election_id=e.election_id),"
        "(SELECT COUNT(*) FROM candidates WHERE election_id=e.election_id),"
        "(SELECT COUNT(*) FROM votes WHERE election_id=e.election_id) "
        "FROM elections e WHERE is_deleted=0 ORDER BY created_at DESC;";
    sqlite3_prepare_v2(db_get(),esql,-1,&stmt,NULL);
    char rows[32768]="";
    while(sqlite3_step(stmt)==SQLITE_ROW){
        int eid=sqlite3_column_int(stmt,0);
        const char *et=(const char*)sqlite3_column_text(stmt,1);
        const char *es=(const char*)sqlite3_column_text(stmt,2);
        const char *sd=(const char*)sqlite3_column_text(stmt,3);
        const char *ed=(const char*)sqlite3_column_text(stmt,4);
        int ev=sqlite3_column_int(stmt,5);
        int ec=sqlite3_column_int(stmt,6);
        int evo=sqlite3_column_int(stmt,7);
        const char *sc=strcmp(es,"active")==0?"success":(strcmp(es,"upcoming")==0?"warning":"secondary");
        int is_upcoming=(strcmp(es,"upcoming")==0);

        char actions[1024]="";
        if(is_upcoming){
            char tmp[512];
            snprintf(tmp,sizeof(tmp),
                "<a href=\"/admin/elections/%d/voters\" class=\"btn btn-sm btn-info\">Voters</a>"
                "<a href=\"/admin/elections/%d/candidates\" class=\"btn btn-sm btn-info\">Candidates</a>"
                "<a href=\"/admin/elections/%d/edit\" class=\"btn btn-sm btn-warning\">Edit</a>",eid,eid,eid);
            strncpy(actions,tmp,sizeof(actions));
        }
        char tmp2[256];
        snprintf(tmp2,sizeof(tmp2),"<a href=\"/admin/elections/%d/applications\" class=\"btn btn-sm btn-secondary\">Applications</a>",eid);
        strncat(actions,tmp2,sizeof(actions)-strlen(actions)-1);
        if(strcmp(es,"closed")==0||evo>0){
            snprintf(tmp2,sizeof(tmp2),"<a href=\"/admin/results/%d\" class=\"btn btn-sm btn-success\">Results</a>",eid);
            strncat(actions,tmp2,sizeof(actions)-strlen(actions)-1);
        }
        if(is_upcoming&&evo==0){
            snprintf(tmp2,sizeof(tmp2),
                "<form method=\"POST\" action=\"/admin/elections/%d/delete\" style=\"display:inline;\" "
                "onsubmit=\"return confirm('Archive this election?');\">"
                "<button type=\"submit\" class=\"btn btn-sm btn-danger\">Archive</button></form>",eid);
            strncat(actions,tmp2,sizeof(actions)-strlen(actions)-1);
        }

        char row[2048];
        snprintf(row,sizeof(row),
            "<tr><td>%s</td><td><span class=\"badge badge-%s\">%s</span></td>"
            "<td><small>%s<br>to %s</small></td><td>%d</td><td>%d</td><td>%d</td>"
            "<td><div class=\"btn-group-vertical btn-group-sm\">%s</div></td></tr>",
            et?et:"",sc,es?es:"",sd?sd:"",ed?ed:"",ev,ec,evo,actions);
        strncat(rows,row,sizeof(rows)-strlen(rows)-1);
    }
    sqlite3_finalize(stmt);

    char no_msg[64]="";
    if(!rows[0]) strcpy(no_msg,"<p class=\"text-gray\">No elections created yet.</p>");

    const char *k[]={"ELECTION_ROWS","NO_ELECTIONS_MSG","USER_NAME"};
    const char *v[]={rows,no_msg,s.user_name};
    send_html_page(c,"admin_elections.html",k,v,3);
}

void handle_admin_create_election_get(struct mg_connection *c, struct mg_http_message *hm) {
    read_flash_cookies(hm);
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db_get(),
        "SELECT user_id,name,cnic FROM users WHERE is_admin=0 AND is_deleted=0 ORDER BY name;",-1,&stmt,NULL);
    char voter_checkboxes[16384]="";
    while(sqlite3_step(stmt)==SQLITE_ROW){
        int vid=sqlite3_column_int(stmt,0);
        const char *vn=(const char*)sqlite3_column_text(stmt,1);
        const char *vc=(const char*)sqlite3_column_text(stmt,2);
        char cnic_fmt[20]=""; if(vc) format_cnic(vc,cnic_fmt);
        char row[512];
        snprintf(row,sizeof(row),
            "<div class=\"col-md-6\"><div class=\"form-check\">"
            "<input class=\"form-check-input voter-checkbox\" type=\"checkbox\" "
            "name=\"eligible_voters[]\" value=\"%d\" id=\"voter-%d\">"
            "<label class=\"form-check-label\" for=\"voter-%d\">%s <span class=\"text-gray\">(%s)</span></label>"
            "</div></div>",vid,vid,vid,vn?vn:"",cnic_fmt);
        strncat(voter_checkboxes,row,sizeof(voter_checkboxes)-strlen(voter_checkboxes)-1);
    }
    sqlite3_finalize(stmt);
    if(!voter_checkboxes[0])
        strncpy(voter_checkboxes,"<p class=\"text-gray\">No voters registered yet. <a href=\"/admin/voters/add\">Add voters first</a>.</p>",sizeof(voter_checkboxes));

    const char *k[]={"VOTER_CHECKBOXES","USER_NAME"};
    const char *v[]={voter_checkboxes,s.user_name};
    send_html_page(c,"admin_create_election.html",k,v,2);
}

void handle_admin_create_election_post(struct mg_connection *c, struct mg_http_message *hm) {
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}

    char title[256]="",desc[2048]="",start_date[32]="",end_date[32]="";
    form_get(hm,"title",title,sizeof(title));
    form_get(hm,"description",desc,sizeof(desc));
    form_get(hm,"start_date",start_date,sizeof(start_date));
    form_get(hm,"end_date",end_date,sizeof(end_date));

    /* Parse voter IDs from body manually */
    char body_copy[hm->body.len+1];
    memcpy(body_copy,hm->body.buf,hm->body.len);
    body_copy[hm->body.len]=0;

    int voter_ids[1024]; int voter_count=0;
    char *ptr=body_copy;
    while((ptr=strstr(ptr,"eligible_voters%5B%5D="))!=NULL||
          (ptr=strstr(ptr,"eligible_voters[]="))!=NULL) {
        /* try both encoded and raw */
        char *p2=strstr(body_copy,"eligible_voters%5B%5D=");
        if(!p2) p2=strstr(body_copy,"eligible_voters[]=");
        if(!p2) break;

        /* Scan all occurrences */
        const char *tag1="eligible_voters%5B%5D=";
        const char *tag2="eligible_voters[]=";
        char *q=body_copy;
        voter_count=0;
        while(voter_count<1024){
            char *f1=strstr(q,tag1);
            char *f2=strstr(q,tag2);
            char *f=NULL;
            int tlen=0;
            if(f1&&f2) {f=f1<f2?f1:f2; tlen=f==f1?strlen(tag1):strlen(tag2);}
            else if(f1){f=f1;tlen=strlen(tag1);}
            else if(f2){f=f2;tlen=strlen(tag2);}
            else break;
            q=f+tlen;
            voter_ids[voter_count++]=atoi(q);
        }
        break;
    }

    if(strlen(title)<3||voter_count==0||!start_date[0]||!end_date[0]){
        redirect_with_flash(c,"/admin/elections/create",
            "Title (3+ chars), dates, and at least one voter required.","danger");
        return;
    }
    /* Replace T with space for SQLite */
    for(int i=0;start_date[i];i++) if(start_date[i]=='T') start_date[i]=' ';
    for(int i=0;end_date[i];i++)   if(end_date[i]=='T')   end_date[i]=' ';

    /* Determine status */
    char status[16]="upcoming";

    int eid=0;
    if(db_create_election(title,desc,start_date,end_date,status,&eid)){
        db_set_election_voters(eid,voter_ids,voter_count);
        char msg[128]; snprintf(msg,128,"Election \"%s\" created successfully!",title);
        redirect_with_flash(c,"/admin/elections",msg,"success");
    } else {
        redirect_with_flash(c,"/admin/elections/create","An error occurred.","danger");
    }
}

void handle_admin_edit_election_get(struct mg_connection *c, struct mg_http_message *hm, int eid) {
    read_flash_cookies(hm);
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db_get(),
        "SELECT title,description,start_date,end_date FROM elections WHERE election_id=? AND is_deleted=0;",
        -1,&stmt,NULL);
    sqlite3_bind_int(stmt,1,eid);
    if(sqlite3_step(stmt)!=SQLITE_ROW){
        sqlite3_finalize(stmt);
        redirect_with_flash(c,"/admin/elections","Election not found.","danger");return;
    }
    char et[256]="",ed[2048]="",esd[32]="",eed[32]="";
    const char *t=(const char*)sqlite3_column_text(stmt,0);
    const char *d=(const char*)sqlite3_column_text(stmt,1);
    const char *sd=(const char*)sqlite3_column_text(stmt,2);
    const char *endd=(const char*)sqlite3_column_text(stmt,3);
    if(t)strncpy(et,t,255);if(d)strncpy(ed,d,2047);
    if(sd)strncpy(esd,sd,31);if(endd)strncpy(eed,endd,31);
    sqlite3_finalize(stmt);
    /* Convert space to T for datetime-local */
    for(int i=0;esd[i];i++) if(esd[i]==' ') esd[i]='T';
    for(int i=0;eed[i];i++) if(eed[i]==' ') eed[i]='T';
    /* Trim seconds if present e.g. 2024-01-01T12:00:00 -> 2024-01-01T12:00 */
    if(strlen(esd)>16) esd[16]=0;
    if(strlen(eed)>16) eed[16]=0;

    char eid_s[16]; snprintf(eid_s,16,"%d",eid);
    const char *k[]={"ELECTION_ID","ELECTION_TITLE","ELECTION_DESC","START_DATE","END_DATE","USER_NAME"};
    const char *v[]={eid_s,et,ed,esd,eed,s.user_name};
    send_html_page(c,"admin_edit_election.html",k,v,6);
}

void handle_admin_edit_election_post(struct mg_connection *c, struct mg_http_message *hm, int eid) {
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}
    char title[256]="",desc[2048]="",start_date[32]="",end_date[32]="";
    form_get(hm,"title",title,sizeof(title));
    form_get(hm,"description",desc,sizeof(desc));
    form_get(hm,"start_date",start_date,sizeof(start_date));
    form_get(hm,"end_date",end_date,sizeof(end_date));
    for(int i=0;start_date[i];i++) if(start_date[i]=='T') start_date[i]=' ';
    for(int i=0;end_date[i];i++)   if(end_date[i]=='T')   end_date[i]=' ';
    if(strlen(title)<3){
        char loc[64]; snprintf(loc,64,"/admin/elections/%d/edit",eid);
        redirect_with_flash(c,loc,"Title must be at least 3 characters.","danger");return;
    }
    if(db_update_election(eid,title,desc,start_date,end_date))
        redirect_with_flash(c,"/admin/elections","Election updated successfully.","success");
    else {
        char loc[64]; snprintf(loc,64,"/admin/elections/%d/edit",eid);
        redirect_with_flash(c,loc,"Error updating election.","danger");
    }
}

void handle_admin_election_voters_get(struct mg_connection *c, struct mg_http_message *hm, int eid) {
    read_flash_cookies(hm);
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}

    /* Check election is upcoming */
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db_get(),"SELECT status,title FROM elections WHERE election_id=? AND is_deleted=0;",-1,&stmt,NULL);
    sqlite3_bind_int(stmt,1,eid);
    char estatus[20]="",etitle[256]="";
    if(sqlite3_step(stmt)==SQLITE_ROW){
        const char *st=(const char*)sqlite3_column_text(stmt,0);
        const char *tt=(const char*)sqlite3_column_text(stmt,1);
        if(st)strncpy(estatus,st,19);if(tt)strncpy(etitle,tt,255);
    }
    sqlite3_finalize(stmt);
    if(strcmp(estatus,"upcoming")!=0){
        redirect_with_flash(c,"/admin/elections","Cannot modify voter list after election has started.","warning");return;
    }

    /* Get all non-deleted non-admin voters */
    sqlite3_prepare_v2(db_get(),
        "SELECT user_id,name,cnic FROM users WHERE is_admin=0 AND is_deleted=0 ORDER BY name;",
        -1,&stmt,NULL);
    char checkboxes[16384]="";
    while(sqlite3_step(stmt)==SQLITE_ROW){
        int vid=sqlite3_column_int(stmt,0);
        const char *vn=(const char*)sqlite3_column_text(stmt,1);
        const char *vc=(const char*)sqlite3_column_text(stmt,2);
        char cnic_fmt[20]=""; if(vc) format_cnic(vc,cnic_fmt);
        int checked=db_is_eligible(eid,vid);
        char row[512];
        snprintf(row,sizeof(row),
            "<div class=\"col-md-6\"><div class=\"form-check\">"
            "<input class=\"form-check-input voter-checkbox\" type=\"checkbox\" "
            "name=\"eligible_voters[]\" value=\"%d\" id=\"voter-%d\"%s>"
            "<label class=\"form-check-label\" for=\"voter-%d\">%s <span class=\"text-gray\">(%s)</span></label>"
            "</div></div>",vid,vid,checked?" checked":"",vid,vn?vn:"",cnic_fmt);
        strncat(checkboxes,row,sizeof(checkboxes)-strlen(checkboxes)-1);
    }
    sqlite3_finalize(stmt);

    char eid_s[16]; snprintf(eid_s,16,"%d",eid);
    const char *k[]={"ELECTION_ID","ELECTION_TITLE","VOTER_CHECKBOXES","USER_NAME"};
    const char *v[]={eid_s,etitle,checkboxes,s.user_name};
    send_html_page(c,"admin_manage_election_voters.html",k,v,4);
}

void handle_admin_election_voters_post(struct mg_connection *c, struct mg_http_message *hm, int eid) {
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}

    char body_copy[hm->body.len+1];
    memcpy(body_copy,hm->body.buf,hm->body.len);
    body_copy[hm->body.len]=0;

    int voter_ids[1024]; int voter_count=0;
    const char *tags[]={"eligible_voters%5B%5D=","eligible_voters[]="};
    for(int t=0;t<2;t++){
        char *q=body_copy;
        while(voter_count<1024){
            char *f=strstr(q,tags[t]);
            if(!f) break;
            q=f+strlen(tags[t]);
            voter_ids[voter_count++]=atoi(q);
        }
        if(voter_count) break;
    }

    if(voter_count==0){
        char loc[64]; snprintf(loc,64,"/admin/elections/%d/voters",eid);
        redirect_with_flash(c,loc,"Must select at least one eligible voter.","danger");return;
    }
    db_set_election_voters(eid,voter_ids,voter_count);
    redirect_with_flash(c,"/admin/elections","Eligible voters updated successfully.","success");
}

void handle_admin_delete_election(struct mg_connection *c, struct mg_http_message *hm, int eid) {
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}
    if(db_delete_election(eid,s.user_id))
        redirect_with_flash(c,"/admin/elections","Election archived.","success");
    else
        redirect_with_flash(c,"/admin/elections","Cannot archive (active or has votes).","danger");
}

/* ================================================================
   ADMIN APPLICATIONS
   ================================================================ */

void handle_admin_applications(struct mg_connection *c, struct mg_http_message *hm) {
    read_flash_cookies(hm);
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}

    char status_filter[20]="all";
    char qs_str[256]="";
    if(hm->query.len){
        int n=hm->query.len<255?hm->query.len:255;
        memcpy(qs_str,hm->query.buf,n); qs_str[n]=0;
        char *p=strstr(qs_str,"status="); if(p){strncpy(status_filter,p+7,19); char *amp=strchr(status_filter,'&');if(amp)*amp=0;}
    }

    char where[64]="";
    if(strcmp(status_filter,"pending")==0)  strncpy(where,"WHERE a.status='pending'",63);
    else if(strcmp(status_filter,"approved")==0) strncpy(where,"WHERE a.status='approved'",63);
    else if(strcmp(status_filter,"rejected")==0) strncpy(where,"WHERE a.status='rejected'",63);

    char sql[512];
    snprintf(sql,sizeof(sql),
        "SELECT a.application_id, u.name, u.cnic, e.title, a.status, a.applied_at "
        "FROM candidate_applications a "
        "JOIN users u ON u.user_id=a.user_id "
        "JOIN elections e ON e.election_id=a.election_id "
        "%s ORDER BY a.applied_at DESC;", where);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db_get(),sql,-1,&stmt,NULL);
    char rows[32768]="";
    while(sqlite3_step(stmt)==SQLITE_ROW){
        int aid=sqlite3_column_int(stmt,0); (void)aid;
        const char *an=(const char*)sqlite3_column_text(stmt,1);
        const char *ac=(const char*)sqlite3_column_text(stmt,2);
        const char *ae=(const char*)sqlite3_column_text(stmt,3);
        const char *as2=(const char*)sqlite3_column_text(stmt,4);
        const char *aat=(const char*)sqlite3_column_text(stmt,5);
        char cnic_fmt[20]=""; if(ac) format_cnic(ac,cnic_fmt);
        const char *sc=strcmp(as2?as2:"","approved")==0?"success":(strcmp(as2?as2:"","pending")==0?"warning":"danger");
        char row[1024];
        snprintf(row,sizeof(row),
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td><span class=\"badge badge-%s\">%s</span></td></tr>",
            an?an:"",cnic_fmt,ae?ae:"",aat?aat:"",sc,as2?as2:"");
        strncat(rows,row,sizeof(rows)-strlen(rows)-1);
    }
    sqlite3_finalize(stmt);

    char no_msg[64]=""; if(!rows[0]) strcpy(no_msg,"<p class=\"text-gray\">No applications found.</p>");
    const char *k[]={"APPLICATION_ROWS","NO_APPS_MSG","STATUS_FILTER","USER_NAME"};
    const char *v[]={rows,no_msg,status_filter,s.user_name};
    send_html_page(c,"admin_applications.html",k,v,4);
}

void handle_admin_election_applications(struct mg_connection *c, struct mg_http_message *hm, int eid) {
    read_flash_cookies(hm);
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}

    char etitle[256]="";
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db_get(),"SELECT title FROM elections WHERE election_id=?;",-1,&stmt,NULL);
    sqlite3_bind_int(stmt,1,eid);
    if(sqlite3_step(stmt)==SQLITE_ROW){const char *t=(const char*)sqlite3_column_text(stmt,0);if(t)strncpy(etitle,t,255);}
    sqlite3_finalize(stmt);

    sqlite3_prepare_v2(db_get(),
        "SELECT a.application_id, u.name, u.cnic, a.description, a.status, a.applied_at "
        "FROM candidate_applications a JOIN users u ON u.user_id=a.user_id "
        "WHERE a.election_id=? ORDER BY a.applied_at DESC;",
        -1,&stmt,NULL);
    sqlite3_bind_int(stmt,1,eid);
    char cards[32768]="";
    while(sqlite3_step(stmt)==SQLITE_ROW){
        int aid=sqlite3_column_int(stmt,0);
        const char *an=(const char*)sqlite3_column_text(stmt,1);
        const char *ac=(const char*)sqlite3_column_text(stmt,2);
        const char *ad=(const char*)sqlite3_column_text(stmt,3);
        const char *as2=(const char*)sqlite3_column_text(stmt,4);
        const char *aat=(const char*)sqlite3_column_text(stmt,5);
        char cnic_fmt[20]=""; if(ac) format_cnic(ac,cnic_fmt);
        const char *sc=strcmp(as2?as2:"","approved")==0?"success":(strcmp(as2?as2:"","pending")==0?"warning":"danger");
        char action_btns[512]="";
        if(strcmp(as2?as2:"","pending")==0){
            snprintf(action_btns,sizeof(action_btns),
                "<div class=\"mt-3\">"
                "<form method=\"POST\" action=\"/admin/applications/%d/approve\" style=\"display:inline;\">"
                "<button type=\"submit\" class=\"btn btn-success btn-sm\">Approve</button></form>"
                "<button class=\"btn btn-danger btn-sm\" onclick=\"rejectApp(%d)\">Reject</button>"
                "</div>",aid,aid);
        }
        char card[2048];
        snprintf(card,sizeof(card),
            "<div class=\"card-glass p-4 mb-3\">"
            "<div class=\"d-flex justify-content-between\">"
            "<div><h3 class=\"h5\">%s</h3>"
            "<p class=\"text-gray\">CNIC: %s</p>"
            "<p>%s</p><small class=\"text-gray\">Applied: %s</small></div>"
            "<div><span class=\"badge badge-%s\">%s</span></div>"
            "</div>%s</div>",
            an?an:"",cnic_fmt,ad?ad:"",aat?aat:"",sc,as2?as2:"",action_btns);
        strncat(cards,card,sizeof(cards)-strlen(cards)-1);
    }
    sqlite3_finalize(stmt);
    if(!cards[0]) strncpy(cards,"<p class=\"text-gray\">No applications yet.</p>",sizeof(cards));

    char eid_s[16]; snprintf(eid_s,16,"%d",eid);
    const char *k[]={"ELECTION_ID","ELECTION_TITLE","APPLICATION_CARDS","USER_NAME"};
    const char *v[]={eid_s,etitle,cards,s.user_name};
    send_html_page(c,"admin_election_applications.html",k,v,4);
}

void handle_admin_approve_application(struct mg_connection *c, struct mg_http_message *hm, int app_id) {
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}
    /* Get election_id for redirect */
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db_get(),"SELECT election_id FROM candidate_applications WHERE application_id=?;",-1,&stmt,NULL);
    sqlite3_bind_int(stmt,1,app_id);
    int eid=0;
    if(sqlite3_step(stmt)==SQLITE_ROW) eid=sqlite3_column_int(stmt,0);
    sqlite3_finalize(stmt);

    if(db_approve_application(app_id,s.user_id)){
        char loc[64]; snprintf(loc,64,"/admin/elections/%d/applications",eid);
        redirect_with_flash(c,loc,"Application approved.","success");
    } else {
        redirect_with_flash(c,"/admin/applications","Could not approve application.","danger");
    }
}

void handle_admin_reject_application(struct mg_connection *c, struct mg_http_message *hm, int app_id) {
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}
    char reason[512]="";
    form_get(hm,"reason",reason,sizeof(reason));
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db_get(),"SELECT election_id FROM candidate_applications WHERE application_id=?;",-1,&stmt,NULL);
    sqlite3_bind_int(stmt,1,app_id);
    int eid=0;
    if(sqlite3_step(stmt)==SQLITE_ROW) eid=sqlite3_column_int(stmt,0);
    sqlite3_finalize(stmt);
    db_reject_application(app_id,s.user_id,reason);
    char loc[64]; snprintf(loc,64,"/admin/elections/%d/applications",eid);
    redirect_with_flash(c,loc,"Application rejected.","info");
}

/* ================================================================
   ADMIN CANDIDATES
   ================================================================ */

void handle_admin_manage_candidates(struct mg_connection *c, struct mg_http_message *hm, int eid) {
    read_flash_cookies(hm);
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}

    db_update_election_statuses();
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db_get(),"SELECT title,status FROM elections WHERE election_id=? AND is_deleted=0;",-1,&stmt,NULL);
    sqlite3_bind_int(stmt,1,eid);
    char etitle[256]="",estatus[20]="";
    if(sqlite3_step(stmt)==SQLITE_ROW){
        const char *t=(const char*)sqlite3_column_text(stmt,0);
        const char *st=(const char*)sqlite3_column_text(stmt,1);
        if(t)strncpy(etitle,t,255);if(st)strncpy(estatus,st,19);
    }
    sqlite3_finalize(stmt);

    /* Candidates list */
    sqlite3_prepare_v2(db_get(),
        "SELECT candidate_id,name,cnic,description FROM candidates WHERE election_id=?;",
        -1,&stmt,NULL);
    sqlite3_bind_int(stmt,1,eid);
    char cand_rows[16384]="";
    while(sqlite3_step(stmt)==SQLITE_ROW){
        int cid=sqlite3_column_int(stmt,0);
        const char *cn=(const char*)sqlite3_column_text(stmt,1);
        const char *cc=(const char*)sqlite3_column_text(stmt,2);
        const char *cd=(const char*)sqlite3_column_text(stmt,3);
        char cnic_fmt[20]=""; if(cc) format_cnic(cc,cnic_fmt);
        char del_btn[256]="";
        if(strcmp(estatus,"upcoming")==0)
            snprintf(del_btn,sizeof(del_btn),
                "<form method=\"POST\" action=\"/admin/candidates/%d/delete\" style=\"display:inline;\" "
                "onsubmit=\"return confirm('Remove candidate?');\"><button type=\"submit\" class=\"btn btn-sm btn-danger\">Remove</button></form>",cid);
        char row[1024];
        snprintf(row,sizeof(row),
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
            cn?cn:"",cnic_fmt,cd?cd:"",del_btn);
        strncat(cand_rows,row,sizeof(cand_rows)-strlen(cand_rows)-1);
    }
    sqlite3_finalize(stmt);

    /* Add candidate form (upcoming only — eligible voters not yet candidates) */
    char add_form[8192]="";
    if(strcmp(estatus,"upcoming")==0){
        sqlite3_prepare_v2(db_get(),
            "SELECT u.user_id, u.name, u.cnic FROM users u "
            "JOIN election_voters ev ON ev.user_id=u.user_id "
            "WHERE ev.election_id=? AND u.is_deleted=0 "
            "AND NOT EXISTS (SELECT 1 FROM candidates c WHERE c.user_id=u.user_id AND c.election_id=?) "
            "ORDER BY u.name;",
            -1,&stmt,NULL);
        sqlite3_bind_int(stmt,1,eid); sqlite3_bind_int(stmt,2,eid);
        char voter_opts[4096]="<option value=\"\">-- Select Voter --</option>";
        while(sqlite3_step(stmt)==SQLITE_ROW){
            int vid=sqlite3_column_int(stmt,0);
            const char *vn=(const char*)sqlite3_column_text(stmt,1);
            const char *vc=(const char*)sqlite3_column_text(stmt,2);
            char cnic_fmt[20]=""; if(vc) format_cnic(vc,cnic_fmt);
            char opt[256]; snprintf(opt,256,"<option value=\"%d\">%s (%s)</option>",vid,vn?vn:"",cnic_fmt);
            strncat(voter_opts,opt,sizeof(voter_opts)-strlen(voter_opts)-1);
        }
        sqlite3_finalize(stmt);
        snprintf(add_form,sizeof(add_form),
            "<div class=\"card-glass p-6\"><h3 class=\"h4 mb-4\">Add Candidate Directly</h3>"
            "<form method=\"POST\" action=\"/admin/elections/%d/candidates/add\">"
            "<div class=\"form-group\">"
            "<label class=\"form-label\">Select Eligible Voter</label>"
            "<select name=\"user_id\" class=\"form-control\">%s</select></div>"
            "<div class=\"form-group\">"
            "<label class=\"form-label\">Description</label>"
            "<textarea name=\"description\" class=\"form-control\" rows=\"3\"></textarea></div>"
            "<button type=\"submit\" class=\"btn btn-primary\">Add Candidate</button>"
            "</form></div>",eid,voter_opts);
    }

    char eid_s[16]; snprintf(eid_s,16,"%d",eid);
    char no_msg[64]=""; if(!cand_rows[0]) strcpy(no_msg,"<p class=\"text-gray\">No candidates yet.</p>");
    const char *k[]={"ELECTION_ID","ELECTION_TITLE","CANDIDATE_ROWS","NO_CAND_MSG","ADD_FORM","USER_NAME"};
    const char *v[]={eid_s,etitle,cand_rows,no_msg,add_form,s.user_name};
    send_html_page(c,"admin_manage_candidates.html",k,v,6);
}

void handle_admin_add_candidate(struct mg_connection *c, struct mg_http_message *hm, int eid) {
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}
    char uid_s[16]="",desc[2048]="";
    form_get(hm,"user_id",uid_s,sizeof(uid_s));
    form_get(hm,"description",desc,sizeof(desc));
    int uid=atoi(uid_s);
    if(!uid){
        char loc[64]; snprintf(loc,64,"/admin/elections/%d/candidates",eid);
        redirect_with_flash(c,loc,"Must select a voter.","danger"); return;
    }
    char name[128]="",cnic[20]=""; int da,db2; char dc[32];
    db_get_user(uid,name,cnic,NULL,&da,&db2,dc);
    if(!db_is_eligible(eid,uid)){
        char loc[64]; snprintf(loc,64,"/admin/elections/%d/candidates",eid);
        redirect_with_flash(c,loc,"Selected user is not an eligible voter.","danger"); return;
    }
    if(db_user_is_candidate(uid,eid)){
        char loc[64]; snprintf(loc,64,"/admin/elections/%d/candidates",eid);
        redirect_with_flash(c,loc,"User is already a candidate.","warning"); return;
    }
    db_add_candidate(uid,cnic,name,desc,eid,"default-candidate.png",0);
    char loc[64]; snprintf(loc,64,"/admin/elections/%d/candidates",eid);
    redirect_with_flash(c,loc,"Candidate added.","success");
}

void handle_admin_delete_candidate(struct mg_connection *c, struct mg_http_message *hm, int cid) {
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}
    /* Get election_id */
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db_get(),"SELECT election_id FROM candidates WHERE candidate_id=?;",-1,&stmt,NULL);
    sqlite3_bind_int(stmt,1,cid);
    int eid=0;
    if(sqlite3_step(stmt)==SQLITE_ROW) eid=sqlite3_column_int(stmt,0);
    sqlite3_finalize(stmt);
    if(db_delete_candidate(cid)){
        char loc[64]; snprintf(loc,64,"/admin/elections/%d/candidates",eid);
        redirect_with_flash(c,loc,"Candidate removed.","success");
    } else {
        char loc[64]; snprintf(loc,64,"/admin/elections/%d/candidates",eid);
        redirect_with_flash(c,loc,"Cannot remove candidate (election not upcoming).","warning");
    }
}

/* ================================================================
   ADMIN RESULTS
   ================================================================ */

void handle_admin_results(struct mg_connection *c, struct mg_http_message *hm, int eid) {
    /* Admin can see results anytime; reuse public results with admin session */
    /* Temporarily override status check by calling public handler */
    db_update_election_statuses();

    /* Force it through */
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}
    read_flash_cookies(hm);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db_get(),"SELECT title,description,status FROM elections WHERE election_id=? AND is_deleted=0;",-1,&stmt,NULL);
    sqlite3_bind_int(stmt,1,eid);
    if(sqlite3_step(stmt)!=SQLITE_ROW){sqlite3_finalize(stmt);redirect_with_flash(c,"/admin/elections","Election not found.","danger");return;}
    char etitle[256]="",edesc[1024]="",estatus[20]="";
    const char *t=(const char*)sqlite3_column_text(stmt,0);
    const char *d=(const char*)sqlite3_column_text(stmt,1);
    const char *st=(const char*)sqlite3_column_text(stmt,2);
    if(t)strncpy(etitle,t,255);if(d)strncpy(edesc,d,1023);if(st)strncpy(estatus,st,19);
    sqlite3_finalize(stmt);

    int total_votes = db_get_total_votes_in_election(eid);
    const char *rsql =
        "SELECT c.candidate_id, c.name, c.description, COUNT(v.vote_id) as vc "
        "FROM candidates c LEFT JOIN votes v ON v.candidate_id=c.candidate_id "
        "WHERE c.election_id=? GROUP BY c.candidate_id ORDER BY vc DESC;";
    sqlite3_prepare_v2(db_get(),rsql,-1,&stmt,NULL);
    sqlite3_bind_int(stmt,1,eid);

    char winner_html[512]="", results_rows[16384]="";
    int idx=0;
    while(sqlite3_step(stmt)==SQLITE_ROW){
        const char *cn=(const char*)sqlite3_column_text(stmt,1);
        const char *cd=(const char*)sqlite3_column_text(stmt,2);
        int vc=sqlite3_column_int(stmt,3);
        char cname[128]="",cdesc[512]="";
        if(cn)strncpy(cname,cn,127);if(cd)strncpy(cdesc,cd,511);
        double pct=total_votes>0?(vc*100.0/total_votes):0.0;
        if(idx==0&&total_votes>0)
            snprintf(winner_html,sizeof(winner_html),
                "<div class=\"card mb-8\" style=\"background:var(--gradient-primary);color:white;padding:var(--space-10);text-align:center;\">"
                "<div style=\"font-size:var(--text-5xl);\">🎉</div>"
                "<h2 class=\"mb-4\" style=\"color:white;\">Winner: %s</h2>"
                "<p style=\"font-size:var(--text-2xl);opacity:0.9;\">%d votes (%.1f%%)</p></div>",cname,vc,pct);
        char row[1024];
        snprintf(row,sizeof(row),
            "<div><div style=\"display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--space-3);\">"
            "<div style=\"display:flex;align-items:center;gap:var(--space-4);\">"
            "<div style=\"width:50px;height:50px;background:var(--gradient-primary);border-radius:50%;display:flex;align-items:center;justify-content:center;color:white;font-weight:bold;\">#%d</div>"
            "<div><h3 class=\"mb-1\">%s</h3><p class=\"text-sm text-gray\">%s</p></div></div>"
            "<div class=\"text-right\"><p class=\"fw-bold\" style=\"font-size:var(--text-2xl);color:var(--primary-600);\">%d</p><p class=\"text-sm text-gray\">votes</p></div></div>"
            "<div class=\"progress\"><div class=\"progress-bar\" data-width=\"%.1f\" style=\"width:%.1f%%;\">%.1f%%</div></div></div>",
            idx+1,cname, cdesc[0]?cdesc:"No description",vc,pct,pct,pct);
        strncat(results_rows,row,sizeof(results_rows)-strlen(results_rows)-1);
        idx++;
    }
    sqlite3_finalize(stmt);

    char tv_str[16]; snprintf(tv_str,16,"%d",total_votes);
    char tc_str[16]; snprintf(tc_str,16,"%d",idx);
    const char *stat_col=strcmp(estatus,"active")==0?"success":(strcmp(estatus,"upcoming")==0?"warning":"secondary");
    char no_results[256]="";
    if(!idx) strncpy(no_results,"<div class=\"card text-center\" style=\"padding:var(--space-12);\"><h3>No Candidates</h3><p class=\"text-gray\">No candidates yet.</p></div>",sizeof(no_results));

    const char *k[]={"ELECTION_TITLE","ELECTION_DESC","ELECTION_STATUS","STATUS_COLOR",
                      "TOTAL_VOTES","TOTAL_CANDIDATES","WINNER_HTML","RESULTS_ROWS","NO_RESULTS","BACK_URL"};
    const char *v[]={etitle,edesc,estatus,stat_col,tv_str,tc_str,winner_html,results_rows,no_results,"/admin/elections"};
    send_html_page(c,"results.html",k,v,10);
}

/* ================================================================
   ADMIN CHANGE PASSWORD
   ================================================================ */

void handle_admin_change_password_get(struct mg_connection *c, struct mg_http_message *hm) {
    read_flash_cookies(hm);
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}
    const char *k[]={"USER_NAME"}; const char *v[]={s.user_name};
    send_html_page(c,"admin_change_password.html",k,v,1);
}

void handle_admin_change_password_post(struct mg_connection *c, struct mg_http_message *hm) {
    Session s = get_session_from_request(hm);
    if(!s.valid||!s.is_admin){redirect_with_flash(c,"/login","Access denied.","danger");return;}
    char cur[128]="",newp[128]="",conf[128]="";
    form_get(hm,"current_password",cur,sizeof(cur));
    form_get(hm,"new_password",newp,sizeof(newp));
    form_get(hm,"confirm_password",conf,sizeof(conf));

    /* Verify current */
    char cur_hash[65]; sha256_string(cur,cur_hash);
    char cnic[20]="",email[120]="";
    int is_adm=0,is_del=0; char created[32]=""; char name[128]="";
    db_get_user(s.user_id,name,cnic,email,&is_adm,&is_del,created);
    int uid2,adm2,del2;
    int ok=db_verify_user_by_email(email,cur_hash,&uid2,&adm2,&del2);
    if(!ok){redirect_with_flash(c,"/admin/change-password","Current password is incorrect.","danger");return;}
    if(strlen(newp)<8){redirect_with_flash(c,"/admin/change-password","New password must be at least 8 characters.","danger");return;}
    if(strcmp(newp,conf)!=0){redirect_with_flash(c,"/admin/change-password","New passwords do not match.","danger");return;}
    if(strcmp(cur,newp)==0){redirect_with_flash(c,"/admin/change-password","New password must differ from current.","danger");return;}

    char new_hash[65]; sha256_string(newp,new_hash);
    db_update_password(s.user_id, new_hash);
    session_destroy(db_get(), s.session_id);
    char cpw_hdr[512];
    snprintf(cpw_hdr, sizeof(cpw_hdr),
        "Set-Cookie: %s=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT\r\n"
        "Set-Cookie: flash_msg=Password%%20changed%%20successfully%%21%%20Please%%20log%%20in%%20again.; Path=/\r\n"
        "Set-Cookie: flash_type=success; Path=/\r\n"
        "Location: /login\r\n", SESSION_COOKIE_NAME);
    mg_http_reply(c, 302, cpw_hdr, "");
}

/* ================================================================
   FORGOT PASSWORD
   ================================================================ */

/* Send email notification via PowerShell (uses smtp_config.txt) */
static void send_email_notification(const char *to_email, const char *voter_name,
                                     const char *new_password) {
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "powershell -NonInteractive -WindowStyle Hidden -Command \""
        "try {"
        "$cfg = Get-Content 'smtp_config.txt' -ErrorAction Stop | ConvertFrom-StringData;"
        "$pass = ConvertTo-SecureString $cfg.smtp_pass -AsPlainText -Force;"
        "$cred = New-Object System.Management.Automation.PSCredential($cfg.smtp_user, $pass);"
        "Send-MailMessage -SmtpServer $cfg.smtp_server -Port $cfg.smtp_port -UseSsl "
        "-Credential $cred -From $cfg.smtp_from "
        "-To '%s' "
        "-Subject 'Password Reset - Online Voting System' "
        "-Body 'Dear %s,\\n\\nYour password has been reset by the administrator.\\n\\n"
        "New Password: %s\\n\\nPlease login and change your password immediately.\\n\\n"
        "Login at http://127.0.0.1:5000\\n\\nVoting System Admin';"
        "} catch { Write-Host $_.Exception.Message }\"",
        to_email, voter_name, new_password);
    system(cmd);
}

void handle_forgot_password_get(struct mg_connection *c, struct mg_http_message *hm) {
    read_flash_cookies(hm);
    /* If already logged in, redirect away */
    Session s = get_session_from_request(hm);
    if (s.valid) {
        send_redirect(c, s.is_admin ? "/admin/dashboard" : "/dashboard");
        return;
    }
    send_html_page(c, "forgot_password.html", NULL, NULL, 0);
}

void handle_forgot_password_post(struct mg_connection *c, struct mg_http_message *hm) {
    char cnic[32]="", email[128]="";
    form_get(hm, "cnic",  cnic,  sizeof(cnic));
    form_get(hm, "email", email, sizeof(email));
    clean_cnic(cnic);

    if (strlen(cnic) != 13 || strlen(email) < 5 || !strchr(email,'@')) {
        redirect_with_flash(c, "/forgot-password",
            "Please enter your 13-digit CNIC and registered email.", "danger");
        return;
    }

    /* Look up user by CNIC */
    const char *sql =
        "SELECT user_id, name, email FROM users "
        "WHERE cnic=? AND is_admin=0 AND is_deleted=0;";
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db_get(), sql, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, cnic, -1, SQLITE_TRANSIENT);
    int uid = 0; char dbname[128]="", dbemail[128]="";
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        uid = sqlite3_column_int(stmt, 0);
        const char *n = (const char*)sqlite3_column_text(stmt, 1);
        const char *e = (const char*)sqlite3_column_text(stmt, 2);
        if (n) strncpy(dbname,  n, 127);
        if (e) strncpy(dbemail, e, 127);
    }
    sqlite3_finalize(stmt);

    if (!uid) {
        redirect_with_flash(c, "/forgot-password",
            "No account found with that CNIC.", "danger");
        return;
    }

    /* Verify email matches */
    if (strcasecmp(email, dbemail) != 0) {
        redirect_with_flash(c, "/forgot-password",
            "Email does not match our records for this CNIC.", "danger");
        return;
    }

    /* Create reset request */
    db_create_password_reset_request(uid, dbemail);
    redirect_with_flash(c, "/login",
        "Your password reset request has been forwarded to the admin. "
        "You will be updated with your new password through your registered email shortly.",
        "info");
}

/* ================================================================
   ADMIN - PASSWORD RESET REQUESTS
   ================================================================ */

typedef struct { char buf[32768]; } ResetBuf;
static void reset_row_cb(int req_id, int uid, const char *name,
                          const char *email, const char *cnic,
                          const char *requested_at, const char *status,
                          void *ud) {
    ResetBuf *rb = (ResetBuf*)ud; (void)uid;
    const char *badge = strcmp(status,"pending")==0 ? "warning" : "success";
    char cnic_fmt[20]=""; format_cnic(cnic, cnic_fmt);
    char row[1024];
    if (strcmp(status,"pending")==0) {
        snprintf(row, sizeof(row),
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td><span class=\"badge badge-%s\">%s</span></td>"
            "<td>"
            "<form method=\"POST\" action=\"/admin/password-resets/%d/resolve\" "
            "style=\"display:inline;\">"
            "<input name=\"new_password\" class=\"form-control\" style=\"width:140px;display:inline;\" "
            "placeholder=\"New password\" required minlength=\"6\"> "
            "<button class=\"btn btn-sm btn-primary\">Reset &amp; Email</button>"
            "</form>"
            "</td></tr>",
            name, cnic_fmt, email, requested_at, badge, status, req_id);
    } else {
        snprintf(row, sizeof(row),
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td><span class=\"badge badge-%s\">%s</span></td>"
            "<td><span class=\"text-gray\">Resolved</span></td></tr>",
            name, cnic_fmt, email, requested_at, badge, status);
    }
    strncat(rb->buf, row, sizeof(rb->buf)-strlen(rb->buf)-1);
}

void handle_admin_password_resets(struct mg_connection *c, struct mg_http_message *hm) {
    read_flash_cookies(hm);
    Session s = get_session_from_request(hm);
    if (!s.valid || !s.is_admin) {
        redirect_with_flash(c, "/login", "Access denied.", "danger"); return;
    }
    ResetBuf rb; memset(&rb, 0, sizeof(rb));
    db_foreach_reset_request(reset_row_cb, &rb);

    const char *no_msg = rb.buf[0] ? "" :
        "<div class=\"alert alert-info\">No password reset requests yet.</div>";
    const char *table_start = rb.buf[0] ?
        "<div class=\"table-responsive\"><table class=\"table\">"
        "<thead><tr><th>Voter</th><th>CNIC</th><th>Email</th>"
        "<th>Requested</th><th>Status</th><th>Action</th></tr></thead>"
        "<tbody>" : "";
    const char *table_end = rb.buf[0] ? "</tbody></table></div>" : "";

    char full[40000];
    snprintf(full, sizeof(full), "%s%s%s%s", no_msg, table_start, rb.buf, table_end);

    const char *keys[] = {"RESET_TABLE","USER_NAME"};
    const char *vals[] = {full, s.user_name};
    send_html_page(c, "admin_password_resets.html", keys, vals, 2);
}

void handle_admin_resolve_reset(struct mg_connection *c, struct mg_http_message *hm, int req_id) {
    Session s = get_session_from_request(hm);
    if (!s.valid || !s.is_admin) {
        redirect_with_flash(c, "/login", "Access denied.", "danger"); return;
    }
    char new_password[128]="";
    form_get(hm, "new_password", new_password, sizeof(new_password));
    if (strlen(new_password) < 6) {
        redirect_with_flash(c, "/admin/password-resets",
            "Password must be at least 6 characters.", "danger"); return;
    }

    /* Get voter email before resolving */
    const char *sel =
        "SELECT r.email, u.name FROM password_reset_requests r "
        "JOIN users u ON u.user_id=r.user_id WHERE r.req_id=?;";
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db_get(), sel, -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, req_id);
    char voter_email[128]="", voter_name[128]="";
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *e = (const char*)sqlite3_column_text(stmt, 0);
        const char *n = (const char*)sqlite3_column_text(stmt, 1);
        if (e) strncpy(voter_email, e, 127);
        if (n) strncpy(voter_name,  n, 127);
    }
    sqlite3_finalize(stmt);

    char hashed[65]; sha256_string(new_password, hashed);
    if (db_resolve_password_reset(req_id, hashed)) {
        /* Send email notification */
        if (voter_email[0]) {
            send_email_notification(voter_email, voter_name, new_password);
        }
        redirect_with_flash(c, "/admin/password-resets",
            "Password reset successfully. Email notification sent.", "success");
    } else {
        redirect_with_flash(c, "/admin/password-resets",
            "Could not resolve request. It may already be resolved.", "danger");
    }
}
