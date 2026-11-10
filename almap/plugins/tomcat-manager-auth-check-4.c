/* tomcat-manager-auth-check-4 - Tomcat Manager default-credential check
 * Tries a fixed 5-entry test dictionary of common defaults via HTTP Basic
 * auth against /manager/html. Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *words[5] = { "admin", "password", "root", "test", "guest" };
    char hdr[256];
    char resp[4096];
    int i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < 5; i++) {
        ar_basic_auth(words[i], words[i], hdr, sizeof(hdr));
        if (ar_http_request(ctx, "GET", "/manager/html", NULL, hdr, NULL, NULL,
                            resp, sizeof(resp)) <= 0) {
            continue;
        }
        if (ar_http_status(resp) != 401 && ar_http_status(resp) != 403) {
            ar_out(ctx, "tomcat-manager-auth-check-4: %s:%s -> HTTP %d (not rejected; verify)",
                   words[i], words[i], ar_http_status(resp));
            return 0;
        }
    }
    ar_out(ctx, "tomcat-manager-auth-check-4: all 5 default pairs rejected on /manager/html");
    return 0;
}
