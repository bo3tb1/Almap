/* http-vuln-cve2017-1001000-3 - WordPress REST API content injection. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[] = { "/wp-json/wp/v2/posts/1", "/wp-json/wp/v2/users/1", "/?rest_route=/wp/v2/posts/1" };
    char resp[8192];
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        int n = ar_http_get(ctx, paths[i], resp, sizeof(resp));
        if (n > 0 && ar_contains_ci(ar_http_body(resp), "\"id\"")) {
            ar_append(ctx, "%s%s", (found == 0) ? "VULNERABLE: " : ", ",
                      paths[i]);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "not vulnerable: CVE-2017-1001000 WordPress REST API");
    } else {
        ar_append(ctx, " (CVE-2017-1001000 WordPress REST API)");
    }
    return 0;
}
