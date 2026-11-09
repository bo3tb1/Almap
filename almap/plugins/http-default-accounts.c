/* http-default-accounts - HTTP Basic default credential check. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *users[] = { "admin", "root", "manager", "tomcat" };
    static const char *paths[] = { "/", "/admin/", "/manager/html" };
    char resp[8192];
    char hdr[512];
    int found = 0;
    size_t u;
    size_t p;
    size_t k;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (k = 0; k < sizeof(paths) / sizeof(paths[0]); k++) {
        int n = ar_http_get(ctx, paths[k], resp, sizeof(resp));
        if (n <= 0 || ar_http_status(resp) != 401) {
            continue;
        }
        for (u = 0; u < sizeof(users) / sizeof(users[0]); u++) {
            for (p = 0; p <= 10; p++) {
                const char *pass = (p == 10) ? "" : ar_brute_words[p];
                ar_basic_auth(users[u], pass, hdr, sizeof(hdr));
                n = ar_http_request(ctx, "GET", paths[k], NULL, hdr,
                                    NULL, NULL, resp, sizeof(resp));
                if (n > 0 && ar_http_status(resp) != 401 &&
                    ar_http_status(resp) != 403) {
                    ar_append(ctx, "%s%s:%s at %s", (found == 0) ?
                              "default accounts: " : ", ",
                              users[u], (pass[0] == '\0') ? "(blank)" : pass,
                              paths[k]);
                    found++;
                }
            }
        }
    }
    if (found == 0) {
        ar_out(ctx, "default accounts: no HTTP Basic defaults found");
    }
    return 0;
}
