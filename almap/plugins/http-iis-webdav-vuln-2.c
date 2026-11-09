/* http-iis-webdav-vuln-2 - check IIS WebDAV methods. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "OPTIONS", "/", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n > 0 && (ar_contains_ci(resp, "DAV:") ||
                  ar_contains_ci(resp, "PROPFIND"))) {
        ar_out(ctx, "potentially vulnerable: IIS WebDAV enabled");
    } else {
        ar_out(ctx, "not vulnerable: IIS WebDAV not detected (HTTP %d)",
               ar_http_status(resp));
    }
    return 0;
}
