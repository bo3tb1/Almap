/*
 * plugins/arsenal_ssh.h - minimal SSH transport helpers for the Step 33
 * AlScript arsenal. Raw TCP, fixed buffers, no crypto library.
 *
 * These helpers expose the cleartext SSH banner and KEXINIT name-lists.
 * Full user-auth brute force needs a completed key exchange; the helper
 * still sends an RFC 4252 "none"/password request so a permissive or
 * test peer can answer with USERAUTH_FAILURE/SUCCESS.
 */
#ifndef ARSENAL_SSH_H
#define ARSENAL_SSH_H

#include "arsenal_util.h"

#define AR_SSH_MSG_DISCONNECT 1
#define AR_SSH_MSG_KEXINIT 20
#define AR_SSH_MSG_NEWKEYS 21
#define AR_SSH_MSG_SERVICE_REQUEST 5
#define AR_SSH_MSG_SERVICE_ACCEPT 6
#define AR_SSH_MSG_USERAUTH_REQUEST 50
#define AR_SSH_MSG_USERAUTH_FAILURE 51
#define AR_SSH_MSG_USERAUTH_SUCCESS 52
#define AR_SSH_MSG_USERAUTH_BANNER 53

static int ar_ssh_open(AlScriptContext *ctx, char *banner, size_t cap) {
    int fd;
    int n;

    if (banner == NULL || cap < 2) {
        return -1;
    }
    banner[0] = '\0';
    fd = as_connect(ctx);
    if (fd < 0) {
        return -1;
    }
    n = as_recv_line(fd, banner, cap, ctx->timeout_ms);
    if (n <= 0 || !ar_starts_ci(banner, "SSH-")) {
        close(fd);
        return -1;
    }
    ar_clean(banner);
    return fd;
}

static int ar_ssh_send_packet(int fd, const unsigned char *payload,
                              size_t plen, int timeout_ms) {
    unsigned char buf[2048];
    size_t block = 8;
    size_t pad;
    size_t total;

    if (payload == NULL || plen + 5 + 8 > sizeof(buf)) {
        return -1;
    }
    pad = block - ((plen + 5) % block);
    if (pad < 4) {
        pad += block;
    }
    total = 4 + 1 + plen + pad;
    if (total > sizeof(buf)) {
        return -1;
    }
    buf[0] = (unsigned char)((plen + 1 + pad) >> 24);
    buf[1] = (unsigned char)((plen + 1 + pad) >> 16);
    buf[2] = (unsigned char)((plen + 1 + pad) >> 8);
    buf[3] = (unsigned char)(plen + 1 + pad);
    buf[4] = (unsigned char)pad;
    memcpy(buf + 5, payload, plen);
    memset(buf + 5 + plen, 'A', pad);
    return as_send_all(fd, buf, total, timeout_ms);
}

static int ar_ssh_recv_packet(int fd, unsigned char *payload, size_t cap,
                              int timeout_ms) {
    unsigned char hdr[4];
    unsigned char buf[4096];
    unsigned int plen;
    unsigned int pad;
    unsigned int body;

    if (payload == NULL || cap < 2) {
        return -1;
    }
    if (as_recv_exact(fd, hdr, 4, timeout_ms) != 0) {
        return -1;
    }
    plen = ((unsigned int)hdr[0] << 24) | ((unsigned int)hdr[1] << 16) |
           ((unsigned int)hdr[2] << 8) | (unsigned int)hdr[3];
    if (plen < 5 || plen > sizeof(buf)) {
        return -1;
    }
    if (as_recv_exact(fd, buf, plen, timeout_ms) != 0) {
        return -1;
    }
    pad = buf[0];
    if (pad + 1 >= plen) {
        return -1;
    }
    body = plen - 1 - pad;
    if (body > cap - 1) {
        body = (unsigned int)cap - 1;
    }
    memcpy(payload, buf + 1, body);
    payload[body] = '\0';
    return (int)body;
}

static void ar_ssh_put_u32(unsigned char *p, unsigned int v) {
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

static unsigned int ar_ssh_get_u32(const unsigned char *p) {
    return ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) |
           ((unsigned int)p[2] << 8) | (unsigned int)p[3];
}

static int ar_ssh_build_kexinit(unsigned char *out, size_t cap) {
    static const char *lists[10] = {
        "curve25519-sha256,curve25519-sha256@libssh.org,"
        "ecdh-sha2-nistp256,diffie-hellman-group14-sha256,"
        "diffie-hellman-group14-sha1",
        "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256,ssh-rsa",
        "aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,"
        "chacha20-poly1305@openssh.com",
        "aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,"
        "chacha20-poly1305@openssh.com",
        "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
        "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
        "none,zlib@openssh.com,zlib",
        "none,zlib@openssh.com,zlib",
        "", ""
    };
    size_t o = 0;
    int i;

    if (out == NULL || cap < 64) {
        return -1;
    }
    out[o++] = AR_SSH_MSG_KEXINIT;
    for (i = 0; i < 16; i++) {
        out[o++] = (unsigned char)(0x20 + i);
    }
    for (i = 0; i < 10; i++) {
        size_t len = strlen(lists[i]);
        if (o + 4 + len > cap) {
            return -1;
        }
        ar_ssh_put_u32(out + o, (unsigned int)len);
        o += 4;
        memcpy(out + o, lists[i], len);
        o += len;
    }
    if (o + 5 > cap) {
        return -1;
    }
    out[o++] = 0;
    ar_ssh_put_u32(out + o, 0);
    o += 4;
    return (int)o;
}

/* Return field 0..9 from a KEXINIT payload, 0 on success. */
static int ar_ssh_kex_field(const unsigned char *payload, int len, int field,
                            char *out, size_t cap) {
    int off = 17;
    int i;

    if (payload == NULL || len < 17 || field < 0 || field > 9 ||
        out == NULL || cap < 2) {
        return -1;
    }
    out[0] = '\0';
    for (i = 0; i <= field; i++) {
        unsigned int n;
        if (off + 4 > len) {
            return -1;
        }
        n = ar_ssh_get_u32(payload + off);
        off += 4;
        if (n > (unsigned int)(len - off)) {
            return -1;
        }
        if (i == field) {
            size_t copy = n;
            if (copy >= cap) {
                copy = cap - 1;
            }
            memcpy(out, payload + off, copy);
            out[copy] = '\0';
            return 0;
        }
        off += (int)n;
    }
    return -1;
}

/* Send our KEXINIT and return the server KEXINIT payload. */
static int ar_ssh_get_kexinit(int fd, unsigned char *payload, size_t cap,
                              int timeout_ms) {
    unsigned char kex[1024];
    int klen;
    int i;

    klen = ar_ssh_build_kexinit(kex, sizeof(kex));
    if (klen < 0) {
        return -1;
    }
    if (ar_ssh_send_packet(fd, kex, (size_t)klen, timeout_ms) != 0) {
        return -1;
    }
    for (i = 0; i < 4; i++) {
        int n = ar_ssh_recv_packet(fd, payload, cap, timeout_ms);
        if (n <= 0) {
            return -1;
        }
        if (payload[0] == AR_SSH_MSG_KEXINIT) {
            return n;
        }
    }
    return -1;
}

static int ar_ssh_auth_none(int fd, const char *user, char *methods,
                            size_t cap, int timeout_ms) {
    unsigned char pkt[512];
    unsigned char resp[1024];
    size_t o = 0;
    size_t ulen;
    int n;

    if (user == NULL || methods == NULL || cap < 2) {
        return -1;
    }
    methods[0] = '\0';
    ulen = strlen(user);
    if (ulen > 200) {
        return -1;
    }
    pkt[o++] = AR_SSH_MSG_USERAUTH_REQUEST;
    ar_ssh_put_u32(pkt + o, (unsigned int)ulen);
    o += 4;
    memcpy(pkt + o, user, ulen);
    o += ulen;
    ar_ssh_put_u32(pkt + o, 14);
    o += 4;
    memcpy(pkt + o, "ssh-connection", 14);
    o += 14;
    ar_ssh_put_u32(pkt + o, 4);
    o += 4;
    memcpy(pkt + o, "none", 4);
    o += 4;
    if (ar_ssh_send_packet(fd, pkt, o, timeout_ms) != 0) {
        return -1;
    }
    n = ar_ssh_recv_packet(fd, resp, sizeof(resp), timeout_ms);
    if (n <= 0) {
        return -1;
    }
    if (resp[0] == AR_SSH_MSG_USERAUTH_SUCCESS) {
        (void)snprintf(methods, cap, "none");
        return 1;
    }
    if (resp[0] == AR_SSH_MSG_USERAUTH_FAILURE && n >= 5) {
        unsigned int mlen = ar_ssh_get_u32(resp + 1);
        if (mlen < (unsigned int)cap && 5 + (int)mlen <= n) {
            memcpy(methods, resp + 5, mlen);
            methods[mlen] = '\0';
            return 0;
        }
    }
    return -1;
}

static int ar_ssh_auth_password(int fd, const char *user, const char *pass,
                                char *methods, size_t cap, int timeout_ms) {
    unsigned char pkt[1024];
    unsigned char resp[1024];
    size_t o = 0;
    size_t ulen;
    size_t plen;
    int n;

    if (user == NULL || pass == NULL || methods == NULL || cap < 2) {
        return -1;
    }
    methods[0] = '\0';
    ulen = strlen(user);
    plen = strlen(pass);
    if (ulen > 200 || plen > 400) {
        return -1;
    }
    pkt[o++] = AR_SSH_MSG_USERAUTH_REQUEST;
    ar_ssh_put_u32(pkt + o, (unsigned int)ulen);
    o += 4;
    memcpy(pkt + o, user, ulen);
    o += ulen;
    ar_ssh_put_u32(pkt + o, 14);
    o += 4;
    memcpy(pkt + o, "ssh-connection", 14);
    o += 14;
    ar_ssh_put_u32(pkt + o, 8);
    o += 4;
    memcpy(pkt + o, "password", 8);
    o += 8;
    pkt[o++] = 0;
    ar_ssh_put_u32(pkt + o, (unsigned int)plen);
    o += 4;
    memcpy(pkt + o, pass, plen);
    o += plen;
    if (ar_ssh_send_packet(fd, pkt, o, timeout_ms) != 0) {
        return -1;
    }
    n = ar_ssh_recv_packet(fd, resp, sizeof(resp), timeout_ms);
    if (n <= 0) {
        return -1;
    }
    if (resp[0] == AR_SSH_MSG_USERAUTH_SUCCESS) {
        (void)snprintf(methods, cap, "password");
        return 1;
    }
    if (resp[0] == AR_SSH_MSG_USERAUTH_FAILURE && n >= 5) {
        unsigned int mlen = ar_ssh_get_u32(resp + 1);
        if (mlen < (unsigned int)cap && 5 + (int)mlen <= n) {
            memcpy(methods, resp + 5, mlen);
            methods[mlen] = '\0';
            return 0;
        }
    }
    return -1;
}

#endif /* ARSENAL_SSH_H */
