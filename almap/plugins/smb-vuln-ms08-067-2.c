/* smb-vuln-ms08-067-2 - Conficker/MS08-067 SMBv1 exposure check. */
#include "arsenal_smb.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned char resp[2048];
    char os[256];
    char lan[256];
    unsigned int uid = 0;
    unsigned int dialect = 0xFFFF;
    int fd = -1;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_smb1_negotiate(ctx, resp, sizeof(resp));
    if (n > 0) {
        dialect = ar_smb1_dialect(resp, n);
    }
    if (n < 0 || dialect > 5) {
        ar_out(ctx, "MS08-067: SMBv1 not offered");
        return 0;
    }
    (void)ar_smb1_open_session(ctx, &fd, &uid, os, sizeof(os),
                               lan, sizeof(lan));
    if (fd >= 0) {
        close(fd);
    }
    ar_out(ctx, "potentially vulnerable: MS08-067 (SMBv1 %s; "
           "patch level not confirmed)", ar_smb1_dialect_name(dialect));
    return 0;
}
