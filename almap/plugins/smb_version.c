/*
 * plugins/smb_version.c - NSE smb-version analog.
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/smb_version.so plugins/smb_version.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 445 --scan connect --script ./plugins/smb_version.so
 *
 * Sends an SMB1 Negotiate Protocol Request that also advertises the
 * SMB2 dialect strings, then reads the negotiated dialect from either
 * an SMB1 or an SMB2 negotiate response.
 * Output: "SMB version: <dialect>" (empty when the peer is not SMB).
 * No heap, no external libs: raw POSIX sockets only.
 * Use only on networks you own or have permission to scan.
 */
#include "alscript_net.h"

static const char *smb1_dialect(unsigned int index) {
    switch (index) {
        case 0: return "PC NETWORK PROGRAM 1.0";
        case 1: return "LANMAN1.0";
        case 2: return "Windows for Workgroups 3.1a";
        case 3: return "LM1.2X002";
        case 4: return "LANMAN2.1";
        case 5: return "NT LM 0.12";
        case 6: return "SMB 2.002";
        case 7: return "SMB 2.???";
        default: return NULL;
    }
}

static const char *smb2_dialect(unsigned int revision) {
    switch (revision) {
        case 0x0202: return "SMB 2.0.2";
        case 0x0210: return "SMB 2.1";
        case 0x0300: return "SMB 3.0";
        case 0x0302: return "SMB 3.0.2";
        case 0x0311: return "SMB 3.1.1";
        case 0x02FF: return "SMB 2.???";
        default: return NULL;
    }
}

int almap_script_run(AlScriptContext *ctx) {
    static const char dialects[] =
        "\x02PC NETWORK PROGRAM 1.0\x00"
        "\x02LANMAN1.0\x00"
        "\x02Windows for Workgroups 3.1a\x00"
        "\x02LM1.2X002\x00"
        "\x02LANMAN2.1\x00"
        "\x02NT LM 0.12\x00"
        "\x02SMB 2.002\x00"
        "\x02SMB 2.???\x00";
    unsigned char req[512];
    unsigned char resp[2048];
    unsigned char *smb;
    const char *name = NULL;
    size_t dlen = sizeof(dialects) - 1;
    size_t msglen;
    unsigned int nb_len;
    unsigned int dialect;
    int fd;

    if (ctx == NULL || ctx->output_buf == NULL || ctx->output_max < 2) {
        return 1;
    }
    ctx->output_buf[0] = '\0';
    if (ctx->port < 1 || ctx->port > 65535 || ctx->timeout_ms <= 0) {
        return 1;
    }
    if (ctx->target_ip == 0) {
        return 1;
    }
    if (dlen + 35 > sizeof(req)) {
        return 1;
    }

    memset(req, 0, sizeof(req));
    msglen = 35 + dlen;
    req[0] = 0;
    req[1] = (unsigned char)((msglen >> 16) & 255u);
    req[2] = (unsigned char)((msglen >> 8) & 255u);
    req[3] = (unsigned char)(msglen & 255u);
    smb = req + 4;
    smb[0] = 0xFF;
    smb[1] = 'S';
    smb[2] = 'M';
    smb[3] = 'B';
    smb[4] = 0x72; /* SMB_COM_NEGOTIATE */
    smb[9] = 0x18; /* flags */
    smb[10] = 0x53; /* flags2 little endian */
    smb[11] = 0xC8;
    smb[26] = 0xFE; /* PID */
    smb[27] = 0xFF;
    smb[32] = 0; /* WordCount */
    smb[33] = (unsigned char)(dlen & 255u);
    smb[34] = (unsigned char)((dlen >> 8) & 255u);
    memcpy(req + 39, dialects, dlen);

    fd = as_connect(ctx);
    if (fd < 0) {
        return 1;
    }
    if (as_send_all(fd, req, msglen + 4, ctx->timeout_ms) != 0) {
        close(fd);
        return 1;
    }
    if (as_recv_exact(fd, resp, 4, ctx->timeout_ms) != 0) {
        close(fd);
        return 0;
    }
    if (resp[0] != 0) {
        close(fd);
        return 0;
    }
    nb_len = ((unsigned int)resp[1] << 16) |
             ((unsigned int)resp[2] << 8) | (unsigned int)resp[3];
    if (nb_len < 32) {
        close(fd);
        return 0;
    }
    if (nb_len > sizeof(resp) - 4) {
        nb_len = (unsigned int)sizeof(resp) - 4;
    }
    if (as_recv_exact(fd, resp + 4, nb_len, ctx->timeout_ms) != 0) {
        close(fd);
        return 0;
    }
    close(fd);

    if (nb_len >= 74 && resp[4] == 0xFE && resp[5] == 'S' &&
        resp[6] == 'M' && resp[7] == 'B') {
        dialect = (unsigned int)resp[72] | ((unsigned int)resp[73] << 8);
        name = smb2_dialect(dialect);
        if (name == NULL) {
            snprintf(ctx->output_buf, (size_t)ctx->output_max,
                     "SMB version: SMB 2/3 (dialect 0x%04x)", dialect);
            return 0;
        }
    } else if (nb_len >= 35 && resp[4] == 0xFF && resp[5] == 'S' &&
               resp[6] == 'M' && resp[7] == 'B') {
        dialect = (unsigned int)resp[37] | ((unsigned int)resp[38] << 8);
        name = smb1_dialect(dialect);
        if (name == NULL) {
            snprintf(ctx->output_buf, (size_t)ctx->output_max,
                     "SMB version: SMB1 (dialect %u)", dialect);
            return 0;
        }
    }

    if (name != NULL) {
        snprintf(ctx->output_buf, (size_t)ctx->output_max,
                 "SMB version: %s", name);
    }
    return 0;
}
