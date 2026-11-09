/* ssh-auth-methods-2 - enumerate SSH user-auth methods. */
#include "arsenal_ssh.h"

int almap_script_run(AlScriptContext *ctx) {
    char banner[256];
    char methods[512];
    unsigned char kex[2048];
    int fd;
    int n;
    int rc;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = ar_ssh_open(ctx, banner, sizeof(banner));
    if (fd < 0) {
        ar_out(ctx, "SSH auth methods: no SSH banner");
        return 0;
    }
    n = ar_ssh_get_kexinit(fd, kex, sizeof(kex), ctx->timeout_ms);
    if (n <= 0) {
        close(fd);
        ar_out(ctx, "SSH auth methods: KEXINIT failed (%s)", banner);
        return 0;
    }
    rc = ar_ssh_auth_none(fd, "root", methods, sizeof(methods),
                          ctx->timeout_ms);
    close(fd);
    if (rc == 1) {
        ar_out(ctx, "SSH auth methods: none (no authentication required)");
    } else if (rc == 0 && methods[0] != '\0') {
        ar_out(ctx, "SSH auth methods: %s", methods);
    } else {
        ar_out(ctx, "SSH auth methods: not disclosed (%s)", banner);
    }
    return 0;
}
