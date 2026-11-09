/* http-wordpress-users - enumerate WordPress REST API users. */
#include "arsenal_util.h"

static void ar_wp_users_from_json(AlScriptContext *ctx, const char *body) {
    const char *p = body;
    int count = 0;

    while ((p = strstr(p, "\"slug\":\"")) != NULL) {
        const char *s = p + 8;
        const char *e = strchr(s, '"');
        if (e != NULL && e > s) {
            char user[128];
            size_t n = (size_t)(e - s);
            if (n >= sizeof(user)) {
                n = sizeof(user) - 1;
            }
            memcpy(user, s, n);
            user[n] = '\0';
            ar_append(ctx, "%s%s", (count == 0) ? "" : ", ", user);
            count++;
        }
        p = (e != NULL) ? e + 1 : p + 8;
    }
    if (count == 0) {
        ar_out(ctx, "WordPress users: none disclosed");
    }
}

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    char loc[512];
    const char *body;
    int i;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx, "/wp-json/wp/v2/users", resp, sizeof(resp));
    if (n > 0 && ar_http_status(resp) == 200) {
        ar_out(ctx, "WordPress users: ");
        body = ar_http_body(resp);
        ar_wp_users_from_json(ctx, body);
        return 0;
    }
    {
        int found = 0;
        for (i = 1; i <= 5; i++) {
            char path[64];
            (void)snprintf(path, sizeof(path), "/?author=%d", i);
            n = ar_http_get(ctx, path, resp, sizeof(resp));
            if (n > 0 && ar_http_header(resp, "Location", loc, sizeof(loc))) {
                ar_append(ctx, "%s%s", (found == 0) ?
                          "WordPress users: " : ", ", loc);
                found++;
            }
        }
    }
    if (ctx->output_buf[0] == '\0') {
        ar_out(ctx, "WordPress users: none disclosed");
    }
    return 0;
}
