#ifndef ALMAP_UDP_H
#define ALMAP_UDP_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * udp.h - Step 17: public raw-socket UDP scan helpers.
 *
 * almap_udp_can_raw() reports whether the process can open the raw
 * sockets needed for a UDP scan (requires root or CAP_NET_RAW).
 *
 * almap_udp_scan() is the one-port sequential UDP probe used by
 * modules/udp_scan.goose. It builds a single IPv4/UDP datagram with an
 * empty payload and a computed UDP checksum, sends it with a raw socket
 * (IP_HDRINCL), then waits up to timeout_ms for either:
 *   - a UDP response from the target port  => open (0)
 *   - an ICMP destination-unreachable / port-unreachable for our
 *     datagram                                => closed (1)
 *   - nothing before the timeout            => open|filtered (2)
 *
 * The source address is resolved with almap_local_ip_for() from
 * c/raw.c; packet building and response matching for UDP live only in
 * c/udp.c (c/raw.c is not modified for Step 17).
 *
 * Return codes for almap_udp_scan():
 *   0 = open (UDP response), 1 = closed (ICMP port unreachable),
 *   2 = open|filtered / timeout, 3 = error,
 *   4 = permission denied / raw socket unavailable.
 *
 * Sequential only; no libpcap, no worker pool, no banners. Requires
 * root or CAP_NET_RAW. Use only on networks you own or have permission
 * to scan.
 */

int almap_udp_can_raw(void);
int almap_udp_scan(unsigned int dst_be, int port, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* ALMAP_UDP_H */
