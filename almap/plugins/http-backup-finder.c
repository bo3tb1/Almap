/* http-backup-finder - look for common web backup archives. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[] = {
        "/backup.zip", "/backup.tar.gz", "/backup.tgz", "/www.zip",
        "/website.zip", "/site.zip", "/html.zip", "/public_html.zip",
        "/index.php.bak", "/index.html.bak", "/db.sql", "/dump.sql",
        "/backup.sql", "/wp-content/backup.zip"
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
        const char *body = ar_http_body(resp);
        if (n > 0 && code >= 200 && code < 300 &&
            !ar_contains_ci(body, "<html") &&
            !ar_contains_ci(body, "not found")) {
            ar_append(ctx, "%s%s (%d bytes)", (found == 0) ?
                      "backup files: " : ", ", paths[i], n);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "backup files: none found");
    }
    return 0;
}
