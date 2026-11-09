/* ssh-brute - small fixed dictionary check for root/admin. */
#include "arsenal_ssh.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *users[] = { "root", "admin" };
    char banner[256];
    char methods[512];
    unsigned char kex[2048];
    int fd;
    int n;
    int u;
    int p;
    int found = 0;
    int attempts = 0;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (u = 0; u < 2; u++) {
        fd = ar_ssh_open(ctx, banner, sizeof(banner));
        if (fd < 0) {
            continue;
        }
        n = ar_ssh_get_kexinit(fd, kex, sizeof(kex), ctx->timeout_ms);
        if (n <= 0) {
            close(fd);
            continue;
        }
        for (p = 0; p < 10; p++) {
            int rc;
            attempts++;
            rc = ar_ssh_auth_password(fd, users[u], ar_brute_words[p],
                                      methods, sizeof(methods),
                                      ctx->timeout_ms);
            if (rc == 1) {
                ar_append(ctx, "%s%s:%s", (found == 0) ?
                          "SSH valid credentials: " : ", ",
                          users[u], ar_brute_words[p]);
                found++;
                break;
            }
            if (rc < 0) {
                break;
            }
        }
        close(fd);
    }
    if (found == 0) {
        ar_out(ctx, "SSH brute: no valid credentials in 10-word dictionary "
               "(%d attempts; full auth needs completed KEX)", attempts);
    }
    return 0;
}
