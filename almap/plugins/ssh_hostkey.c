/*
 * plugins/ssh_hostkey.c - NSE ssh-hostkey analog.
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/ssh_hostkey.so plugins/ssh_hostkey.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 22 --scan connect --script ./plugins/ssh_hostkey.so
 *
 * Exchanges SSH version banners, sends a minimal KEXINIT, reads the
 * server KEXINIT, and extracts the server host key algorithm name-list
 * (for example ssh-ed25519 or rsa-sha2-512).
 * Output: "Host key algorithms: <list>" (empty when unavailable).
 * No heap, no external libs: raw POSIX sockets only.
 * Use only on networks you own or have permission to scan.
 */
#include "alscript_net.h"

static void put_u32(unsigned char *p, unsigned int v) {
    p[0] = (unsigned char)((v >> 24) & 255u);
    p[1] = (unsigned char)((v >> 16) & 255u);
    p[2] = (unsigned char)((v >> 8) & 255u);
    p[3] = (unsigned char)(v & 255u);
}

static unsigned int get_u32(const unsigned char *p) {
    return ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) |
           ((unsigned int)p[2] << 8) | (unsigned int)p[3];
}

static int put_namelist(unsigned char *buf, size_t cap, size_t *off,
                        const char *s) {
    size_t n = strlen(s);

    if (*off + 4 + n > cap) {
        return 0;
    }
    put_u32(buf + *off, (unsigned int)n);
    *off += 4;
    memcpy(buf + *off, s, n);
    *off += n;
    return 1;
}

static int send_ssh_packet(int fd, const unsigned char *payload,
                           size_t paylen, int timeout_ms) {
    unsigned char pkt[1200];
    size_t pad;
    size_t plen;

    pad = 8 - ((paylen + 5) % 8);
    if (pad < 4) {
        pad += 8;
    }
    plen = 1 + paylen + pad;
    if (4 + plen > sizeof(pkt)) {
        return -1;
    }
    put_u32(pkt, (unsigned int)plen);
    pkt[4] = (unsigned char)pad;
    memcpy(pkt + 5, payload, paylen);
    memset(pkt + 5 + paylen, 0, pad);
    return as_send_all(fd, pkt, 4 + plen, timeout_ms);
}

static int recv_ssh_packet(int fd, unsigned char *payload, size_t cap,
                           int timeout_ms) {
    unsigned char hdr[4];
    unsigned char pkt[4000];
    unsigned int plen;
    unsigned int pad;
    size_t paylen;

    if (as_recv_exact(fd, hdr, 4, timeout_ms) != 0) {
        return -1;
    }
    plen = get_u32(hdr);
    if (plen < 5 || plen > sizeof(pkt)) {
        return -1;
    }
    if (as_recv_exact(fd, pkt, plen, timeout_ms) != 0) {
        return -1;
    }
    pad = pkt[0];
    if ((size_t)pad + 1 > plen) {
        return -1;
    }
    paylen = (size_t)plen - 1 - (size_t)pad;
    if (paylen > cap) {
        return -1;
    }
    memcpy(payload, pkt + 1, paylen);
    return (int)paylen;
}

static int parse_hostkey_algorithms(const unsigned char *payload, int len,
                                    char *out, size_t outcap) {
    size_t pos;
    int i;

    if (payload == NULL || out == NULL || outcap < 2 || len < 17) {
        return 0;
    }
    out[0] = '\0';
    if (payload[0] != 20) {
        return 0;
    }
    pos = 17; /* message type + 16-byte cookie */
    for (i = 0; i < 10; i++) {
        unsigned int n;
        if (pos + 4 > (size_t)len) {
            return 0;
        }
        n = get_u32(payload + pos);
        pos += 4;
        if (pos + n > (size_t)len) {
            return 0;
        }
        if (i == 1) {
            size_t copy = (n < outcap - 1) ? (size_t)n : outcap - 1;
            memcpy(out, payload + pos, copy);
            out[copy] = '\0';
            as_clean_field(out);
            return out[0] != '\0';
        }
        pos += n;
    }
    return 0;
}

int almap_script_run(AlScriptContext *ctx) {
    int fd;
    int i;
    int n;
    char banner[512];
    char keys[1024];
    unsigned char payload[1024];
    size_t off = 0;

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

    /* Both sides may send their identification string immediately. */
    {
        static const char hello[] = "SSH-2.0-ALmap_1.0\r\n";
        if (as_send_all(fd, hello, strlen(hello), ctx->timeout_ms) != 0) {
            close(fd);
            return 1;
        }
    }
    /* Consume any pre-banner lines until the SSH identification line. */
    for (i = 0; i < 8; i++) {
        if (as_recv_line(fd, banner, sizeof(banner), ctx->timeout_ms) <= 0) {
            break;
        }
        if (strncmp(banner, "SSH-", 4) == 0) {
            break;
        }
    }

    /* Minimal KEXINIT: one kex, one host key, real cipher/mac names. */
    payload[off++] = 20;
    for (i = 0; i < 16; i++) {
        payload[off++] = (unsigned char)(0x41 + i);
    }
    if (!put_namelist(payload, sizeof(payload), &off, "curve25519-sha256") ||
        !put_namelist(payload, sizeof(payload), &off, "ssh-ed25519") ||
        !put_namelist(payload, sizeof(payload), &off, "aes128-ctr") ||
        !put_namelist(payload, sizeof(payload), &off, "aes128-ctr") ||
        !put_namelist(payload, sizeof(payload), &off, "hmac-sha2-256") ||
        !put_namelist(payload, sizeof(payload), &off, "hmac-sha2-256") ||
        !put_namelist(payload, sizeof(payload), &off, "none") ||
        !put_namelist(payload, sizeof(payload), &off, "none") ||
        !put_namelist(payload, sizeof(payload), &off, "") ||
        !put_namelist(payload, sizeof(payload), &off, "")) {
        close(fd);
        return 1;
    }
    if (off + 5 > sizeof(payload)) {
        close(fd);
        return 1;
    }
    payload[off++] = 0; /* first_kex_packet_follows */
    put_u32(payload + off, 0);
    off += 4;

    if (send_ssh_packet(fd, payload, off, ctx->timeout_ms) != 0) {
        close(fd);
        return 1;
    }

    keys[0] = '\0';
    for (i = 0; i < 8; i++) {
        n = recv_ssh_packet(fd, payload, sizeof(payload), ctx->timeout_ms);
        if (n <= 0) {
            break;
        }
        if (payload[0] == 20) {
            (void)parse_hostkey_algorithms(payload, n, keys, sizeof(keys));
            break;
        }
        if (payload[0] == 1) { /* SSH_MSG_DISCONNECT */
            break;
        }
    }
    close(fd);

    if (keys[0] != '\0') {
        snprintf(ctx->output_buf, (size_t)ctx->output_max,
                 "Host key algorithms: %s", keys);
    }
    return 0;
}
