/* ftp-anon - full anonymous FTP login check. */
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
        ar_out(ctx, "FTP anon: no FTP banner");
        return 0;
    }
    code = ar_ftp_login(fd, "anonymous", "anonymous@example.com",
                        reply, sizeof(reply), ctx->timeout_ms);
    if (code != 230) {
        code = ar_ftp_login(fd, "anonymous", "anonymous",
                            reply, sizeof(reply), ctx->timeout_ms);
    }
    close(fd);
    if (code == 230) {
        ar_out(ctx, "FTP anonymous login: allowed (%s)", banner);
    } else {
        ar_out(ctx, "FTP anonymous login: denied (code %d)", code);
    }
    return 0;
}
