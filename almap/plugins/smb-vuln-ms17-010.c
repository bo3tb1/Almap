/* smb-vuln-ms17-010 - EternalBlue SMBv1 exposure check. */
#include "arsenal_smb.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned char resp[2048];
    char os[256];
    char lan[256];
    unsigned int uid = 0;
    unsigned int d1 = 0xFFFF;
    unsigned int d2 = 0xFFFF;
    int fd = -1;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_smb2_negotiate(ctx, resp, sizeof(resp));
    if (n > 0) {
        d2 = ar_smb2_dialect(resp, n);
    }
    n = ar_smb1_negotiate(ctx, resp, sizeof(resp));
    if (n > 0) {
        d1 = ar_smb1_dialect(resp, n);
    }
    if (d1 > 5) {
        ar_out(ctx, "MS17-010: SMBv1 not offered (SMB2 dialect 0x%04x)", d2);
        return 0;
    }
    (void)ar_smb1_open_session(ctx, &fd, &uid, os, sizeof(os),
                               lan, sizeof(lan));
    if (fd >= 0) {
        close(fd);
    }
    ar_out(ctx, "potentially vulnerable: MS17-010 EternalBlue "
           "(SMBv1 %s; patch level not confirmed)",
           ar_smb1_dialect_name(d1));
    if (os[0] != '\0') {
        ar_append(ctx, " OS=%s", os);
    }
    return 0;
}
