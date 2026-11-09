/* mysql-empty-password - test MySQL/MariaDB accounts with blank passwords. */
#include "arsenal_mysql.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *users[] = { "root", "mysql", "admin", "test" };
    char version[256];
    unsigned char salt[32];
    char msg[512];
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(users) / sizeof(users[0]); i++) {
        int fd = ar_mysql_open(ctx, version, sizeof(version), salt,
                               sizeof(salt));
        int rc;
        if (fd < 0) {
            ar_out(ctx, "MySQL empty password: no MySQL handshake");
            return 0;
        }
        rc = ar_mysql_login(fd, users[i], "", 1, ctx->timeout_ms,
                            msg, sizeof(msg));
        close(fd);
        if (rc == 0) {
            ar_append(ctx, "%s%s@%s", (found == 0) ?
                      "MySQL empty password: " : ", ",
                      users[i], version);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "MySQL empty password: none accepted");
    }
    return 0;
}
