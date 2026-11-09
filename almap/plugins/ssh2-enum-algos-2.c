/* ssh2-enum-algos-2 - enumerate five SSH KEXINIT algorithm lists. */
#include "arsenal_ssh.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *names[5] = {
        "kex", "hostkey", "enc-c2s", "enc-s2c", "mac-c2s"
    };
    char banner[256];
    char val[1024];
    unsigned char kex[2048];
    int fd;
    int n;
    int i;
    int lines = 0;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = ar_ssh_open(ctx, banner, sizeof(banner));
    if (fd < 0) {
        ar_out(ctx, "SSH algorithms: no SSH banner");
        return 0;
    }
    n = ar_ssh_get_kexinit(fd, kex, sizeof(kex), ctx->timeout_ms);
    close(fd);
    if (n <= 0) {
        ar_out(ctx, "SSH algorithms: KEXINIT failed (%s)", banner);
        return 0;
    }
    for (i = 0; i < 5; i++) {
        if (ar_ssh_kex_field(kex, n, i, val, sizeof(val)) == 0 &&
            val[0] != '\0') {
            ar_append(ctx, "%s%s: %s", lines ? "\n" : "", names[i], val);
            lines++;
        }
    }
    if (lines == 0) {
        ar_out(ctx, "SSH algorithms: none disclosed");
    }
    return 0;
}
