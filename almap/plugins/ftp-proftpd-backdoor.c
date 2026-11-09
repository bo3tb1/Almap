/* ftp-proftpd-backdoor - ProFTPD 1.3.3c ACIDBITCHEZ probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char banner[1024];
    char reply[1024];
    int fd;
    int code;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = ar_ftp_open(ctx, banner, sizeof(banner));
    if (fd < 0) {
        ar_out(ctx, "ProFTPD backdoor: no FTP banner");
        return 0;
    }
    code = ar_ftp_cmd(fd, "HELP ACIDBITCHEZ", reply, sizeof(reply),
                      ctx->timeout_ms);
    close(fd);
    if (ar_contains_ci(banner, "ProFTPD 1.3.3c") ||
        ar_contains_ci(reply, "ACIDBITCHEZ") ||
        ar_contains_ci(reply, "220")) {
        ar_out(ctx, "VULNERABLE: ProFTPD 1.3.3c backdoor (%s)", banner);
    } else {
        ar_out(ctx, "not vulnerable: ProFTPD backdoor not confirmed (code %d)",
               code);
    }
    return 0;
}
