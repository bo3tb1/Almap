/* mysql-vuln-cve2012-2122-2 - five wrong-password auth attempts. */
#include "arsenal_mysql.h"

int almap_script_run(AlScriptContext *ctx) {
    char version[256];
    unsigned char salt[32];
    char msg[512];
    int found = 0;
    int i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < 5; i++) {
        int fd = ar_mysql_open(ctx, version, sizeof(version), salt,
                               sizeof(salt));
        int rc;
        if (fd < 0) {
            ar_out(ctx, "MySQL CVE-2012-2122: no handshake");
            return 0;
        }
        rc = ar_mysql_login(fd, "root", "wrong", 0, ctx->timeout_ms,
                            msg, sizeof(msg));
        close(fd);
        if (rc == 0) {
            ar_out(ctx, "VULNERABLE: MySQL CVE-2012-2122 auth bypass");
            found = 1;
            break;
        }
    }
    if (!found) {
        ar_out(ctx, "not vulnerable: MySQL CVE-2012-2122");
    }
    return 0;
}
