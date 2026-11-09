/* http-wordpress-plugins-3 - enumerate common WordPress plugins. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[] = { "/wp-content/plugins/akismet/readme.txt", "/wp-content/plugins/hello.php", "/wp-content/plugins/woocommerce/readme.txt" };
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
            ar_append(ctx, "%s%s [%d]", (found == 0) ? "WordPress plugins: " : ", ",
                      paths[i], code);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "WordPress plugins: no matching paths");
    }
    return 0;
}
