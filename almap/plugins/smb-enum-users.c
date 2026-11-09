/* smb-enum-users - SMB null-session user/OS reconnaissance. */
#include "arsenal_smb.h"

int almap_script_run(AlScriptContext *ctx) {
    char os[256];
    char lan[256];
    unsigned int uid = 0;
    int fd = -1;

    if (!ar_valid(ctx)) {
        return 1;
    }
    os[0] = '\0';
    lan[0] = '\0';
    if (ar_smb1_open_session(ctx, &fd, &uid, os, sizeof(os),
                             lan, sizeof(lan)) != 0 || fd < 0) {
        ar_out(ctx, "SMB users: SMBv1 negotiation failed");
        return 0;
    }
    close(fd);
    if (os[0] == '\0' && lan[0] == '\0') {
        ar_out(ctx, "SMB users: null session rejected; SAMR enumeration unavailable");
    } else {
        ar_out(ctx, "SMB users: null session accepted (OS=%s LAN=%s); "
               "SAMR user list requires authenticated RPC",
               os[0] != '\0' ? os : "unknown",
               lan[0] != '\0' ? lan : "unknown");
    }
    return 0;
}
