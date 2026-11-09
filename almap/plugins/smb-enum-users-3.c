/* smb-enum-users-3 - test null-session user enumeration. */
#include "arsenal_smb.h"

int almap_script_run(AlScriptContext *ctx) {
    char os[256];
    char lan[256];
    unsigned int uid = 0;
    int fd = -1;

    if (!ar_valid(ctx)) {
        return 1;
    }
    (void)ar_smb1_open_session(ctx, &fd, &uid, os, sizeof(os),
                               lan, sizeof(lan));
    if (fd >= 0) {
        close(fd);
        ar_out(ctx, "SMB users: null session accepted; user list "
               "not exposed by this probe");
    } else {
        ar_out(ctx, "SMB users: null session denied");
    }
    return 0;
}
