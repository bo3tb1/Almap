/* http-webdav-scan-3 - enumerate WebDAV capabilities. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;
    int found = 0;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "OPTIONS", "/", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n > 0 && ar_contains_ci(resp, "DAV")) {
        ar_append(ctx, "WebDAV: OPTIONS advertises DAV");
        found++;
    }
    n = ar_http_request(ctx, "PROPFIND", "/", NULL, "Depth: 0\r\n",
                        NULL, NULL, resp, sizeof(resp));
    if (n > 0 && (ar_http_status(resp) == 207 ||
                  ar_http_status(resp) == 200)) {
        ar_append(ctx, "%sPROPFIND HTTP %d", found ? "; " : "WebDAV: ",
                  ar_http_status(resp));
        found++;
    }
    if (found == 0) {
        ar_out(ctx, "WebDAV: not enabled");
    }
    return 0;
}
