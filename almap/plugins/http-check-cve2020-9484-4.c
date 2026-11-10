/* http-check-cve2020-9484-4 - Apache Tomcat session persistence deserialization
 * (CVE detection probe; benign request, verify out-of-band).
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/", NULL,
                        "Cookie: JSESSIONID=../../../../../tmp/probe\r\n",
                        NULL, NULL, resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-check-cve2020-9484-4: no HTTP response");
        return 0;
    }
    ar_out(ctx, "probe sent: GET / [%d] (CVE-2020-9484; verify out-of-band)",
           ar_http_status(resp));
    return 0;
}
