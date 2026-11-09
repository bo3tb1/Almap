/* ftp-bounce - FTP PORT command bounce exposure check. */
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
    (void)ar_ftp_login(fd, "anonymous", "anonymous@example.com",
                       reply, sizeof(reply), ctx->timeout_ms);
    code = ar_ftp_cmd(fd, "PORT 127,0,0,1,0,80", reply, sizeof(reply),
                      ctx->timeout_ms);
    if (code == 200) {
        ar_out(ctx, "VULNERABLE: FTP bounce (PORT to third party accepted)");
    } else {
        ar_out(ctx, "not vulnerable: FTP bounce PORT rejected (code %d)", code);
    }
    close(fd);
    return 0;
}
