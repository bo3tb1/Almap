/* http-vmware-path-vuln - probe VMware web paths and traversal. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[] = {
        "/sdk/", "/sdk/vimService.wsdl", "/sdk/vimService.wsdl?wsdl",
        "/vpx/", "/ui/", "/folder/", "/sdk/../../../../etc/passwd",
        "/ui/../../../../etc/passwd"
    };
    char resp[8192];
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        int n = ar_http_get(ctx, paths[i], resp, sizeof(resp));
        int code = ar_http_status(resp);
        const char *body = ar_http_body(resp);
        if (n > 0 && (strstr(body, "root:x:") != NULL ||
                      strstr(body, "daemon:x:") != NULL)) {
            ar_out(ctx, "VULNERABLE: VMware path traversal at %s", paths[i]);
            return 0;
        }
        if (n > 0 && code != 404 &&
            (ar_contains_ci(body, "vmware") ||
             ar_contains_ci(body, "vimService") ||
             ar_contains_ci(body, "vSphere"))) {
            ar_append(ctx, "%s%s [%d]", (found == 0) ?
                      "VMware paths: " : ", ", paths[i], code);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "VMware path vulnerability: not detected");
    }
    return 0;
}
