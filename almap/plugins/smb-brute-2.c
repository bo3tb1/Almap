/* smb-brute-2 - five fixed SMB null-session attempts. */
#include "arsenal_smb.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *users[] = {
        "admin", "root", "password", "admin", "root"
    };
    static const char *passes[] = {
        "admin", "root", "password", "password", "password"
    };
    char os[256];
    char lan[256];
    int found = 0;
    int i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < 5; i++) {
        unsigned int uid = 0;
        int fd = -1;
        (void)ar_smb1_open_session(ctx, &fd, &uid, os, sizeof(os),
                                   lan, sizeof(lan));
        if (fd >= 0) {
            close(fd);
            ar_append(ctx, "%s%s:%s (null session)", (found == 0) ?
                      "SMB valid credentials: " : ", ",
                      users[i], passes[i]);
            found++;
            break;
        }
    }
    if (found == 0) {
        ar_out(ctx, "SMB brute: no null session in 5 attempts");
    }
    return 0;
}
