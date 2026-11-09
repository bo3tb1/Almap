/*
 * plugins/vnc_auth.c - NSE vnc-info analog (auth types only).
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/vnc_auth.so plugins/vnc_auth.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 5900 --scan connect --script ./plugins/vnc_auth.so
 *
 * Reads the RFB version banner, selects the matching protocol version,
 * and extracts the offered security/authentication types.
 * Output: "VNC auth: None, VNC Auth" (empty when none are offered).
 * No heap, no external libs: raw POSIX sockets only.
 * Use only on networks you own or have permission to scan.
 */
#include "alscript_net.h"

static const char *auth_name(unsigned int t) {
    switch (t) {
        case 0: return "Invalid";
        case 1: return "None";
        case 2: return "VNC Auth";
        case 16: return "Tight";
        case 18: return "TLS";
        case 19: return "VeNCrypt";
        case 20: return "SASL";
        case 21: return "MD5";
        case 22: return "xvp";
        case 30: return "Apple Remote Desktop";
        case 35: return "Ultra";
        case 36: return "TLSVNC";
        default: return NULL;
    }
}

static void append_auth(char *dst, size_t cap, const char *name,
                        unsigned int type) {
    size_t used = strlen(dst);
    if (used + strlen(name) + 16 > cap) {
        return;
    }
    if (used > 0) {
        dst[used++] = ',';
        dst[used++] = ' ';
        dst[used] = '\0';
    }
    snprintf(dst + used, cap - used, "%s (%u)", name, type);
}

int almap_script_run(AlScriptContext *ctx) {
    int fd;
    int n;
    int i;
    int minor = 8;
    char banner[16];
    char client[16];
    char types[1024];
    unsigned char buf[1024];
    unsigned int count;

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

    fd = as_connect(ctx);
    if (fd < 0) {
        return 1;
    }
    memset(banner, 0, sizeof(banner));
    if (as_recv_exact(fd, banner, 12, ctx->timeout_ms) != 0 ||
        strncmp(banner, "RFB ", 4) != 0) {
        close(fd);
        return 0;
    }
    banner[12] = '\0';
    if (sscanf(banner, "RFB 003.%3d", &minor) != 1) {
        minor = 8;
    }
    if (minor < 3 || minor > 889) {
        minor = 8;
    }
    snprintf(client, sizeof(client), "RFB 003.%03d\n", minor);
    if (as_send_all(fd, client, strlen(client), ctx->timeout_ms) != 0) {
        close(fd);
        return 1;
    }

    types[0] = '\0';
    if (minor >= 7) {
        if (as_recv_exact(fd, buf, 1, ctx->timeout_ms) != 0) {
            close(fd);
            return 0;
        }
        count = buf[0];
        if (count == 0) {
            unsigned char reason_len[4];
            unsigned int rlen;
            if (as_recv_exact(fd, reason_len, 4, ctx->timeout_ms) != 0) {
                close(fd);
                return 0;
            }
            rlen = ((unsigned int)reason_len[0] << 24) |
                   ((unsigned int)reason_len[1] << 16) |
                   ((unsigned int)reason_len[2] << 8) |
                   (unsigned int)reason_len[3];
            if (rlen > sizeof(buf) - 1) {
                rlen = sizeof(buf) - 1;
            }
            if (rlen > 0) {
                (void)as_recv_exact(fd, buf, rlen, ctx->timeout_ms);
                buf[rlen] = '\0';
                as_clean_field((char *)buf);
                if (buf[0] != '\0') {
                    snprintf(ctx->output_buf, (size_t)ctx->output_max,
                             "VNC auth: %s", (char *)buf);
                }
            }
            close(fd);
            return 0;
        }
        if (count > sizeof(buf)) {
            count = sizeof(buf);
        }
        if (as_recv_exact(fd, buf, count, ctx->timeout_ms) != 0) {
            close(fd);
            return 0;
        }
        for (i = 0; i < (int)count; i++) {
            const char *name = auth_name(buf[i]);
            if (name != NULL) {
                append_auth(types, sizeof(types), name, buf[i]);
            }
        }
    } else {
        unsigned int t;
        if (as_recv_exact(fd, buf, 4, ctx->timeout_ms) != 0) {
            close(fd);
            return 0;
        }
        t = ((unsigned int)buf[0] << 24) | ((unsigned int)buf[1] << 16) |
            ((unsigned int)buf[2] << 8) | (unsigned int)buf[3];
        if (t <= 255) {
            const char *name = auth_name(t);
            if (name != NULL) {
                append_auth(types, sizeof(types), name, t);
            }
        }
    }
    close(fd);

    if (types[0] != '\0') {
        snprintf(ctx->output_buf, (size_t)ctx->output_max,
                 "VNC auth: %s", types);
    }
    return 0;
}
