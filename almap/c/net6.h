#ifndef ALMAP_NET6_H
#define ALMAP_NET6_H

/*
 * net6.h - Step 18: limited IPv6 connect helpers.
 *
 * Only the TCP connect probe used by --scan connect and --discover is
 * implemented here. SYN, UDP, service detection, and banner grabbing over
 * IPv6 are not implemented (the CLI rejects those combinations with
 * "not implemented for IPv6").
 *
 * Addresses are passed as the 16 raw bytes of an IPv6 address in network
 * byte order (the same bytes inet_pton(AF_INET6, ...) produces). The
 * helpers build a struct sockaddr_in6 themselves; existing IPv4 C
 * signatures in net.h are unchanged.
 *
 * Return codes (same shape as the IPv4 connect helper):
 *   0  open       connect completed
 *   1  closed     connection refused (RST)
 *   2  timeout    no reply within timeout_ms
 *   3  error      invalid argument, socket/connect error, or IPv6 unavailable
 *
 * Use only on networks you own or have permission to scan.
 */

int almap6_sock_connect_timeout(const unsigned char *addr16, int port, int timeout_ms);

/*
 * Text entry point: NUL-terminates text_len bytes of an IPv6 address and
 * parses it with inet_pton(AF_INET6, ...). Returns 3 when the text is not
 * a valid IPv6 address or the socket/connect probe fails.
 */
int almap6_sock_connect_text(const unsigned char *text, int text_len, int port, int timeout_ms);

#endif /* ALMAP_NET6_H */
