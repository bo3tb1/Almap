/* http-wordpress-plugins - detect common WordPress plugins. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *plugins[] = {
        "akismet", "contact-form-7", "woocommerce", "wordpress-seo",
        "jetpack", "elementor", "wpforms-lite", "really-simple-ssl",
        "litespeed-cache", "wordfence"
    };
    char resp[8192];
    char path[256];
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(plugins) / sizeof(plugins[0]); i++) {
        (void)snprintf(path, sizeof(path),
                       "/wp-content/plugins/%s/readme.txt", plugins[i]);
        if (ar_http_get(ctx, path, resp, sizeof(resp)) > 0 &&
            ar_http_status(resp) == 200 &&
            ar_contains_ci(resp, "stable tag")) {
            ar_append(ctx, "%s%s", (found == 0) ? "WordPress plugins: " : ", ",
                      plugins[i]);
            found++;
        }
    }
    if (ar_http_get(ctx, "/wp-content/plugins/", resp, sizeof(resp)) > 0 &&
        ar_http_status(resp) == 200 &&
        ar_contains_ci(resp, "index of")) {
        ar_append(ctx, "%sdirectory-listing", (found == 0) ?
                  "WordPress plugins: " : ", ");
        found++;
    }
    if (found == 0) {
        ar_out(ctx, "WordPress plugins: none detected");
    }
    return 0;
}
