/* http-config-backup - look for exposed configuration backups. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[] = {
        "/.env", "/.env.bak", "/config.php.bak", "/config.php~",
        "/wp-config.php.bak", "/wp-config.php~", "/configuration.php.bak",
        "/web.config.bak", "/.htaccess.bak", "/settings.py.bak",
        "/config.yml.bak", "/application.properties.bak"
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
            !ar_contains_ci(body, "not found") &&
            strlen(body) > 4) {
            ar_append(ctx, "%s%s", (found == 0) ?
                      "config backups: " : ", ", paths[i]);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "config backups: none found");
    }
    return 0;
}
