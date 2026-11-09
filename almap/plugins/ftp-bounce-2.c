/* ftp-bounce-2 - FTP PORT bounce probe. */
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
        ar_out(ctx, "FTP bounce: no FTP banner");
        return 0;
    }
    code = ar_ftp_login(fd, "anonymous", "anonymous@example.com",
                        reply, sizeof(reply), ctx->timeout_ms);
    if (code == 230) {
        code = ar_ftp_cmd(fd, "PORT 127,0,0,1,0,80", reply, sizeof(reply),
                          ctx->timeout_ms);
    }
    close(fd);
    if (code == 200) {
        ar_out(ctx, "VULNERABLE: FTP PORT bounce accepted");
    } else {
        ar_out(ctx, "not vulnerable: FTP PORT bounce (code %d)", code);
    }
    return 0;
}
