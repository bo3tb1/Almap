/* smb-enum-shares-3 - probe three common SMB shares. */
#include "arsenal_smb.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *shares[] = { "IPC$", "C$", "ADMIN$" };
    char os[256];
    char lan[256];
    char ip[32];
    unsigned int uid = 0;
    unsigned int tid = 0;
    int fd = -1;
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    as_ip_text(ctx->target_ip, ip, sizeof(ip));
    if (ar_smb1_open_session(ctx, &fd, &uid, os, sizeof(os),
                             lan, sizeof(lan)) != 0 || fd < 0) {
        ar_out(ctx, "SMB shares: SMBv1 negotiation failed");
        return 0;
    }
    for (i = 0; i < sizeof(shares) / sizeof(shares[0]); i++) {
        const char *service = (strcmp(shares[i], "IPC$") == 0) ? "IPC" : "A:";
        if (ar_smb1_tree_connect(fd, uid, ip, shares[i], service,
                                 &tid, ctx->timeout_ms) == 0) {
            ar_append(ctx, "%s%s", (found == 0) ? "SMB shares: " : ", ",
                      shares[i]);
            found++;
        }
    }
    close(fd);
    if (found == 0) {
        ar_out(ctx, "SMB shares: none accessible via null session");
    }
    return 0;
}
