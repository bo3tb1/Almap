/* http-ntlm-info-3 - detect NTLM authentication info. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    char val[512];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/", NULL,
                        "Authorization: NTLM "
                        "TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=\r\n",
                        NULL, NULL, resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "NTLM info: no response");
        return 0;
    }
    if (ar_http_header(resp, "WWW-Authenticate", val, sizeof(val)) &&
        ar_contains_ci(val, "NTLM")) {
        ar_out(ctx, "NTLM info: %s", val);
    } else {
        ar_out(ctx, "NTLM info: not advertised (HTTP %d)",
               ar_http_status(resp));
    }
    return 0;
}
