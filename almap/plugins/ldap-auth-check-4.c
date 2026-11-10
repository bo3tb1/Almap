/* ldap-auth-check-4 - LDAP default-credential check (fixed 5-entry dict)
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *words[5] = { "admin", "password", "root", "test", "guest" };
    unsigned char pkt[128];
    unsigned char resp[256];
    int i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < 5; i++) {
        size_t wl = strlen(words[i]);          /* cn=<word> as DN, pw=<word> */
        char dn[64];
        int dl = snprintf(dn, sizeof(dn), "cn=%s", words[i]);
        size_t o = 0;
        size_t inner = 3 + (2 + (size_t)dl) + (2 + wl);
        int fd;
        pkt[o++] = 0x30; pkt[o++] = (unsigned char)(3 + 2 + inner);
        pkt[o++] = 0x02; pkt[o++] = 0x01; pkt[o++] = 0x01;      /* messageID */
        pkt[o++] = 0x60; pkt[o++] = (unsigned char)inner;       /* bindRequest */
        pkt[o++] = 0x02; pkt[o++] = 0x01; pkt[o++] = 0x03;      /* version 3 */
        pkt[o++] = 0x04; pkt[o++] = (unsigned char)dl;
        memcpy(pkt + o, dn, (size_t)dl); o += (size_t)dl;
        pkt[o++] = 0x80; pkt[o++] = (unsigned char)wl;
        memcpy(pkt + o, words[i], wl); o += wl;
        fd = as_connect(ctx);
        if (fd < 0) { ar_out(ctx, "ldap-auth-check: not reachable"); return 0; }
        if (as_send_all(fd, pkt, o, ctx->timeout_ms) == 0 &&
            as_recv_all(fd, (char *)resp, sizeof(resp), ctx->timeout_ms) >= 10 &&
            resp[5] == 0x61 && resp[9] == 0x00) {
            close(fd);
            ar_out(ctx, "ldap-auth-check: %s ACCEPTED (verify)", dn);
            return 0;
        }
        close(fd);
    }
    ar_out(ctx, "ldap-auth-check: all 5 default binds rejected");
    return 0;
}
