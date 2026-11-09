/* ssh-hostkey - report SSH host-key algorithms and fingerprint source. */
#include "arsenal_ssh.h"

int almap_script_run(AlScriptContext *ctx) {
    char banner[256];
    char algos[1024];
    unsigned char kex[2048];
    int fd;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = ar_ssh_open(ctx, banner, sizeof(banner));
    if (fd < 0) {
        ar_out(ctx, "SSH hostkey: no SSH banner");
        return 0;
    }
    n = ar_ssh_get_kexinit(fd, kex, sizeof(kex), ctx->timeout_ms);
    close(fd);
    if (n <= 0 ||
        ar_ssh_kex_field(kex, n, 1, algos, sizeof(algos)) != 0) {
        ar_out(ctx, "SSH hostkey: %s (host-key algorithms not disclosed)",
               banner);
        return 0;
    }
    ar_out(ctx, "SSH hostkey algorithms: %s", algos);
    ar_append(ctx, " (%s)", banner);
    return 0;
}
