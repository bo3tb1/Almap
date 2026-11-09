/* http-drupal-enum - enumerate Drupal version and common paths. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[] = {
        "/CHANGELOG.txt", "/user/login", "/node/1", "/install.php",
        "/update.php", "/sites/default/settings.php", "/robots.txt"
    };
    char resp[8192];
    char ver[64];
    const char *body;
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    ver[0] = '\0';
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        int n = ar_http_get(ctx, paths[i], resp, sizeof(resp));
        int code = ar_http_status(resp);
        if (n <= 0 || code == 404) {
            continue;
        }
        body = ar_http_body(resp);
        if (i == 0 && ver[0] == '\0') {
            if (sscanf(body, "Drupal %63s", ver) != 1) {
                const char *d = strstr(body, "Drupal ");
                if (d != NULL) {
                    (void)sscanf(d, "Drupal %63s", ver);
                }
            }
        }
        if (code >= 200 && code < 500) {
            ar_append(ctx, "%s%s", (found == 0) ? "Drupal: " : ", ", paths[i]);
            found++;
        }
    }
    if (ver[0] != '\0') {
        ar_append(ctx, " version %s", ver);
    }
    if (found == 0) {
        ar_out(ctx, "Drupal: not detected");
    }
    return 0;
}
