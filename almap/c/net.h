#ifndef ALMAP_NET_H
#define ALMAP_NET_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * net.h - Step 3: TCP connect-scan socket wrappers.
 *
 * Goose stdlib has no networking module, so sockets go through C
 * interop via extern fn (see modules/connect_scan.goose).
 *
 * Types map to Goose as: int -> i32, unsigned int -> u32.
 *
 * almap_sock_create(domain, type, protocol):
 *   Pass-through to socket(). The Goose caller passes
 *   AF_INET (2), SOCK_STREAM (1), IPPROTO_TCP (6).
 *   Returns a non-blocking fd (>= 0) or -1 on failure.
 *
 * almap_sock_connect_timeout(fd, addr_be, port, timeout_ms):
 *   addr_be is IPv4 as u32 with the first octet in the high byte
 *   (e.g. 192.168.1.1 = 0xC0A80101); C converts it with htonl.
 *   port is host order 1..65535. timeout_ms must be > 0.
 *   Uses non-blocking connect() + poll() + getsockopt(SO_ERROR).
 *   Return codes: 0 = open, 1 = closed/refused,
 *                 2 = timeout, 3 = error.
 *
 * almap_sock_close(fd): returns 0 on success, -1 on failure.
 *
 * Use only on networks you own or have permission to scan.
 * Raw sockets (SYN scan) are not implemented here; see raw.c.
 */

int almap_sock_create(int domain, int type, int protocol);
int almap_sock_connect_timeout(int fd, unsigned int addr_be, int port, int timeout_ms);
int almap_sock_close(int fd);

/*
 * almap_sock_grab_banner(addr_be, port, timeout_ms, out, out_cap):
 *   addr_be is IPv4 as u32 with the first octet high (htonl in C);
 *   port is host order 1..65535; timeout_ms must be > 0;
 *   out must hold at least out_cap bytes, out_cap >= 2.
 *   Creates a socket and connects with the same non-blocking
 *   connect + poll + getsockopt approach as connect_timeout.
 *   If the connect is not open, returns -1. If open, waits up to
 *   timeout_ms for readable data, reads up to out_cap-1 bytes,
 *   NUL-terminates out, closes, and returns the byte count
 *   (0 if no data). On any error, closes and returns -1.
 */
int almap_sock_grab_banner(unsigned int addr_be, int port, int timeout_ms, unsigned char *out, int out_cap);

/*
 * almap_sock_http_probe(addr_be, port, timeout_ms, out, out_cap):
 *   Step 16 HTTP service probe. Same connect/read helper as
 *   grab_banner, but first sends exactly:
 *     "HEAD / HTTP/1.0\r\n\r\n"
 *   (19 bytes; the request is fixed inside net.c, so Goose never has
 *   to pass a pointer to a string literal). Returns -1 when the port
 *   is not open or on error, 0 when nothing became readable in
 *   timeout_ms, and otherwise the number of bytes read. out is
 *   NUL-terminated like grab_banner.
 */
int almap_sock_http_probe(unsigned int addr_be, int port, int timeout_ms, unsigned char *out, int out_cap);

#ifdef __cplusplus
}
#endif

#endif /* ALMAP_NET_H */
