/* ssh2-enum-algos - enumerate SSH KEXINIT algorithm name-lists. */
#include "arsenal_ssh.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *names[10] = {
        "kex", "hostkey", "enc-c2s", "enc-s2c", "mac-c2s",
        "mac-s2c", "comp-c2s", "comp-s2c", "lang-c2s", "lang-s2c"
    };
    char banner[256];
    char val[2048];
    unsigned char kex[4096];
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
    for (i = 0; i < 10; i++) {
        if (ar_ssh_kex_field(kex, n, i, val, sizeof(val)) == 0 &&
            val[0] != '\0') {
            if (lines > 0) {
                ar_append(ctx, "\n");
            }
            ar_append(ctx, "%s: %s", names[i], val);
            lines++;
        }
    }
    if (lines == 0) {
        ar_out(ctx, "SSH algorithms: none disclosed");
    }
    return 0;
}
