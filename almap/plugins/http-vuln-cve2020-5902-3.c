/* http-vuln-cve2020-5902-3 - F5 BIG-IP TMUI probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[] = { "/tmui/login.jsp", "/tmui/", "/mgmt/tm/util/bash" };
    static const char *needles[] = { "BIG-IP", "BIG-IP", "BIG-IP" };
    char resp[8192];
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        int n = ar_http_get(ctx, paths[i], resp, sizeof(resp));
        int code = ar_http_status(resp);
        if (n > 0 && code < 400 &&
            ar_contains_ci(ar_http_body(resp), needles[i])) {
            ar_append(ctx, "%s%s [%d]", (found == 0) ? "CVE-2020-5902: " : ", ",
                      paths[i], code);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "CVE-2020-5902: no matching paths");
    }
    return 0;
}
