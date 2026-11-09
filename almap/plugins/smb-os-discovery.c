/* smb-os-discovery - discover SMB Native OS and LAN Manager strings. */
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
    os[0] = '\0';
    lan[0] = '\0';
    n = ar_smb1_negotiate(ctx, resp, sizeof(resp));
    if (n > 0) {
        dialect = ar_smb1_dialect(resp, n);
    }
    (void)ar_smb1_open_session(ctx, &fd, &uid, os, sizeof(os),
                               lan, sizeof(lan));
    if (fd >= 0) {
        close(fd);
    }
    if (os[0] == '\0' && lan[0] == '\0' && dialect == 0xFFFF) {
        ar_out(ctx, "SMB OS: not detected");
        return 0;
    }
    ar_out(ctx, "SMB OS: %s", os[0] != '\0' ? os : "unknown");
    if (lan[0] != '\0') {
        ar_append(ctx, " LAN Manager: %s", lan);
    }
    if (dialect != 0xFFFF) {
        ar_append(ctx, " dialect: %s", ar_smb1_dialect_name(dialect));
    }
    return 0;
}
