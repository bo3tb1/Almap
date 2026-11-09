/* smb-ls-2 - list access to the C$ share. */
#include "arsenal_smb.h"

int almap_script_run(AlScriptContext *ctx) {
    char os[256];
    char lan[256];
    char ip[32];
    unsigned int uid = 0;
    unsigned int tid = 0;
    int fd = -1;

    if (!ar_valid(ctx)) {
        return 1;
    }
    as_ip_text(ctx->target_ip, ip, sizeof(ip));
    if (ar_smb1_open_session(ctx, &fd, &uid, os, sizeof(os),
                             lan, sizeof(lan)) != 0 || fd < 0) {
        ar_out(ctx, "SMB ls: session failed");
        return 0;
    }
    if (ar_smb1_tree_connect(fd, uid, ip, "C$", "A:",
                             &tid, ctx->timeout_ms) == 0) {
        ar_out(ctx, "SMB ls: C$ accessible via null session");
    } else {
        ar_out(ctx, "SMB ls: C$ not accessible");
    }
    close(fd);
    return 0;
}
