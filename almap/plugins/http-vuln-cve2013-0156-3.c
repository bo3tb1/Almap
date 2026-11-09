/* http-vuln-cve2013-0156-3 - Rails XML parameter parsing probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int code;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "POST", "/", NULL, "\r\n",
                        "<?xml version=\"1.0\"?><hash><foo "
                        "type=\"yaml\">--- !ruby/object:Object {}</foo></hash>",
                        "application/xml", resp, sizeof(resp));
    code = ar_http_status(resp);
    if (n > 0 && (code == 200 || code == 500)) {
        ar_out(ctx, "potentially vulnerable: CVE-2013-0156 Rails XML "
               "(HTTP %d)", code);
    } else {
        ar_out(ctx, "not vulnerable: CVE-2013-0156 (HTTP %d)", code);
    }
    return 0;
}
