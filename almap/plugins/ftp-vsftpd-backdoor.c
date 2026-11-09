/* ftp-vsftpd-backdoor - vsftpd 2.3.4 smiley backdoor probe. */
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
        ar_out(ctx, "vsftpd backdoor: no FTP banner");
        return 0;
    }
    code = ar_ftp_cmd(fd, "USER anonymous:)", reply, sizeof(reply),
                      ctx->timeout_ms);
    if (code == 331) {
        code = ar_ftp_cmd(fd, "PASS almap@example.com", reply, sizeof(reply),
                          ctx->timeout_ms);
    }
    close(fd);
    if (ar_contains_ci(banner, "vsftpd 2.3.4") &&
        (code == 230 || code == 530)) {
        ar_out(ctx, "VULNERABLE: vsftpd 2.3.4 smiley backdoor (%s)", banner);
    } else {
        ar_out(ctx, "not vulnerable: vsftpd backdoor not confirmed (code %d)",
               code);
    }
    return 0;
}
