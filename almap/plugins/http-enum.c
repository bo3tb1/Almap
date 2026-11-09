/* http-enum - enumerate common web directories and files. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[] = {
        "/admin/", "/administrator/", "/login", "/wp-admin/", "/wp-login.php",
        "/phpmyadmin/", "/server-status", "/server-info", "/.git/HEAD",
        "/.svn/entries", "/backup/", "/uploads/", "/cgi-bin/", "/api/",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/health"
    };
    char resp[8192];
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        int n = ar_http_get(ctx, paths[i], resp, sizeof(resp));
        int code = ar_http_status(resp);
        if (n > 0 && code != 404 && code != 400) {
            ar_append(ctx, "%s%s [%d]", (found == 0) ? "http-enum: " : ", ",
                      paths[i], code);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "http-enum: no common paths found");
    }
    return 0;
}
