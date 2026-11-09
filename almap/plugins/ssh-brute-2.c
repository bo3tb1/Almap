/* ssh-brute-2 - five fixed SSH password attempts. */
#include "arsenal_ssh.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *users[] = {
        "admin", "root", "password", "admin", "root"
    };
    static const char *passes[] = {
        "admin", "root", "password", "password", "password"
    };
    char banner[256];
    char methods[512];
    unsigned char kex[2048];
    int fd;
    int n;
    int i;
    int found = 0;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = ar_ssh_open(ctx, banner, sizeof(banner));
    if (fd < 0) {
        ar_out(ctx, "SSH brute: no SSH banner");
        return 0;
    }
    n = ar_ssh_get_kexinit(fd, kex, sizeof(kex), ctx->timeout_ms);
    if (n <= 0) {
        close(fd);
        ar_out(ctx, "SSH brute: KEXINIT failed");
        return 0;
    }
    for (i = 0; i < 5; i++) {
        int rc = ar_ssh_auth_password(fd, users[i], passes[i], methods,
                                      sizeof(methods), ctx->timeout_ms);
        if (rc == 1) {
            ar_append(ctx, "%s%s:%s", (found == 0) ?
                      "SSH valid credentials: " : ", ",
                      users[i], passes[i]);
            found++;
        } else if (rc < 0) {
            break;
        }
    }
    close(fd);
    if (found == 0) {
        ar_out(ctx, "SSH brute: no valid credentials in 5 attempts");
    }
    return 0;
}
