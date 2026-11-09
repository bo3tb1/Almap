/* http-wordpress-users-2 - probe WordPress user disclosure endpoints. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[] = {
        "/wp-json/wp/v2/users", "/?author=1", "/author/admin/"
    };
    char resp[8192];
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        int n = ar_http_get(ctx, paths[i], resp, sizeof(resp));
        if (n > 0 && ar_http_status(resp) < 400 &&
            (ar_contains_ci(resp, "\"slug\"") ||
             ar_contains_ci(resp, "author") ||
             ar_contains_ci(resp, "admin"))) {
            ar_append(ctx, "%s%s", (found == 0) ?
                      "WordPress users: " : ", ", paths[i]);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "WordPress users: no disclosure");
    }
    return 0;
}
