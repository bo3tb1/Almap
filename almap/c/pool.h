#ifndef ALMAP_POOL_H
#define ALMAP_POOL_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * pool.h - Steps 10,12,13,19: bounded pthread worker pool for connect
 * scans, SYN scans, and host discovery.
 *
 * Types map to Goose as: int -> i32, unsigned int -> u32.
 * ports is a flat array of host-order ports (length port_count).
 * states_out must have port_count bytes.
 *   connect bytes: 0 = open, 1 = closed, 2 = timeout, 3 = error.
 *   SYN bytes:     0 = open, 1 = closed, 2 = timeout/filtered,
 *                  3 = error, 4 = permission denied/raw unavailable.
 *
 * almap_connect_scan_host():
 *   Scans every ports[i] against addr_be with up to workers
 *   threads (clamped to port_count; <=1 runs sequentially).
 *
 * almap_syn_scan_host():
 *   SYN-scans every ports[i] against dst_be with src_be as the
 *   source address, using the shared probe in c/raw.c (no packet
 *   building here). One call covers one host. If src_be or dst_be
 *   is 0, all bytes are 3 (error) and no probes are sent.
 *
 * almap_syn_scan_host_os():
 *   Same scan plus Step 19 fingerprinting. fp_out must have five
 *   ints: [os_class, ttl, window, option_bits, ip_id_behavior].
 *   os_class is 0 unknown, 1 linux-like, 2 windows-like,
 *   3 network-device. Only matching SYN+ACKs are sampled; a host
 *   with no open port reports unknown. Fingerprint aggregation is
 *   mutex-guarded inside the same pool call.
 *
 * almap_discover_hosts():
 *   Discovers every hosts_be[i] (IPv4 u32, first octet high) with
 *   up to workers threads (clamped to host_count; <=1 runs
 *   sequentially). Per host it TCP-pings ports 80 then 443 via the
 *   c/net.c connect helpers (open or closed/RST both mean up), then
 *   optionally calls c/icmp.c::almap_icmp_ping when icmp_available
 *   is nonzero. up_out must have host_count bytes; each is 1 (up)
 *   or 0 (down). One call covers all hosts. There is no rate
 *   limiting for discovery.
 *
 * All functions:
 *   Return 0 on success, -1 on allocation/thread/queue failure.
 *   Must be linked with -pthread (see almap.build).
 *
 * Use only on networks you own or have permission to scan.
 */

int almap_connect_scan_host(unsigned int addr_be, const int *ports, int port_count, int timeout_ms, int workers, int rate_per_sec, unsigned char *states_out);

int almap_syn_scan_host(unsigned int src_be, unsigned int dst_be, const int *ports, int port_count, int timeout_ms, int workers, int rate_per_sec, unsigned char *states_out);

int almap_syn_scan_host_os(unsigned int src_be, unsigned int dst_be, const int *ports, int port_count, int timeout_ms, int workers, int rate_per_sec, unsigned char *states_out, int *fp_out);

int almap_discover_hosts(const unsigned int *hosts_be, int host_count, int timeout_ms, int workers, int icmp_available, unsigned char *up_out);

#ifdef __cplusplus
}
#endif

#endif /* ALMAP_POOL_H */
