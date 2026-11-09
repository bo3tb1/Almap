/* http-vuln-cve2024-3400-3 - PAN-OS GlobalProtect probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[] = { "/global-protect/login.esp", "/global-protect/", "/php/login.php" };
    static const char *needles[] = { "GlobalProtect", "GlobalProtect", "PAN-OS" };
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
            ar_append(ctx, "%s%s [%d]", (found == 0) ? "CVE-2024-3400: " : ", ",
                      paths[i], code);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "CVE-2024-3400: no matching paths");
    }
    return 0;
}
