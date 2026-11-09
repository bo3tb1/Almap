/* http-vuln-cve2024-4577-3 - PHP-CGI Windows argument injection. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[] = { "/?%ADd+allow_url_include%3d1", "/index.php?%ADd+allow_url_include%3d1", "/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1" };
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
            ar_append(ctx, "%s%s [%d]", (found == 0) ? "CVE-2024-4577: " : ", ",
                      paths[i], code);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "CVE-2024-4577: no matching paths");
    }
    return 0;
}
