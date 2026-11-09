/* http-method-tamper-2 - test whether PUT is accepted. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[4096];
    int code;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "PUT", "/almap-test.txt", NULL, "\r\n",
                        "ALmap method test", "text/plain",
                        resp, sizeof(resp));
    code = ar_http_status(resp);
    if (n > 0 && (code == 200 || code == 201 || code == 204)) {
        ar_out(ctx, "VULNERABLE: HTTP PUT accepted (HTTP %d)", code);
    } else {
        ar_out(ctx, "not vulnerable: HTTP PUT rejected (HTTP %d)", code);
    }
    return 0;
}
