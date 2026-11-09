/* http-vuln-cve2012-1823-3 - PHP-CGI query-string argument injection. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[] = { "/?-s", "/index.php?-s", "/cgi-bin/php?-s" };
    char resp[8192];
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        int n = ar_http_get(ctx, paths[i], resp, sizeof(resp));
        if (n > 0 && ar_contains_ci(ar_http_body(resp), "<?php")) {
            ar_append(ctx, "%s%s", (found == 0) ? "VULNERABLE: " : ", ",
                      paths[i]);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "not vulnerable: CVE-2012-1823 PHP-CGI source disclosure");
    } else {
        ar_append(ctx, " (CVE-2012-1823 PHP-CGI source disclosure)");
    }
    return 0;
}
