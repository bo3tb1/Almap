/* http-vuln-cve2015-1635-2 - IIS HTTP.sys Range header probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[4096];
    int code;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/", NULL,
                        "Range: bytes=0-18446744073709551615\r\n",
                        NULL, NULL, resp, sizeof(resp));
    code = ar_http_status(resp);
    if (n > 0 && (code == 416 || code == 200 || code == 206)) {
        ar_out(ctx, "potentially vulnerable: CVE-2015-1635 HTTP.sys "
               "Range handling (HTTP %d)", code);
    } else {
        ar_out(ctx, "not vulnerable: CVE-2015-1635 (HTTP %d)", code);
    }
    return 0;
}
