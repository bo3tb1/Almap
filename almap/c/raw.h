#ifndef ALMAP_RAW_H
#define ALMAP_RAW_H

#include "os.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * raw.h - Step 31: public raw-socket helpers (T1-T7 + U1).
 *
 * almap_syn_scan() is the one-port sequential entry point used by
 * modules/syn_scan.goose. almap_syn_probe() exposes the exact same
 * single-SYN probe for the bounded pool in c/pool.c, so packet
 * building and response matching live only in c/raw.c.
 * almap_syn_probe_os() is the same probe with an optional SYN+ACK
 * fingerprint sample (Step 19); it is used only when --os is active.
 *
 * All are thread-safe: the shared incrementing source-port counter
 * is guarded by a pthread mutex, so concurrent workers get distinct
 * source ports. Each probe uses its own raw socket.
 *
 * Return codes for all probe functions:
 *   0 = open (SYN+ACK), 1 = closed (RST), 2 = timeout/filtered,
 *   3 = error, 4 = permission denied / raw socket unavailable.
 *
 * A fingerprint sample is filled only for code 0. The IP ID, TTL,
 * TCP window, and TCP option bits come from the matching SYN+ACK.
 *
 * Step 31 additions: almap_os_probe_tcp()/almap_os_probe_udp() send
 * the Nmap-style T1-T7/U1 probes and fill AlmapProbeResult (see
 * os.h), including ISN and options string. almap_os_probe_all()
 * runs the full sequence (open port for T1-T4, closed port for
 * T5-T7/U1) and builds the DB-matchable probe_string. Pure packet
 * parsing lives in almap_os_parse_tcp_packet() (c/os.c) for unit
 * tests. Requires root or CAP_NET_RAW.
 */

int almap_syn_probe(unsigned int src_be, unsigned int dst_be, int dst_port, int timeout_ms);
int almap_syn_probe_os(unsigned int src_be, unsigned int dst_be, int dst_port, int timeout_ms, AlmapOsSample *sample);
int almap_syn_can_raw(void);
unsigned int almap_local_ip_for(unsigned int dst_be);
int almap_syn_scan(unsigned int src_be, unsigned int dst_be, int dst_port, int timeout_ms);

/*
 * Step 21 evasion helpers (no Nmap code; RFC 791 fragmentation).
 * almap_packet_checksum() is the RFC 1071 checksum over data/len.
 * almap_fragment_payload(mtu) returns the per-fragment payload bytes
 * (mtu - 20 rounded down to a multiple of 8, minimum 8).
 * almap_fragment_count(total, mtu) returns the fragment count.
 */
int almap_packet_checksum(const unsigned char *data, int len);
int almap_fragment_payload(int mtu);
int almap_fragment_count(int ip_total_len, int mtu);

/*
 * almap_syn_probe_evasion() is the Step 21 SYN probe. When fragment is
 * set, the 40-byte IP+TCP packet is split into IP fragments sized by
 * mtu (default 32 = 8-byte payloads). decoys (up to 5, count 0..5)
 * each receive an identical SYN with the source rewritten to the decoy
 * (checksums recomputed); the real source is sent first. When
 * spoof_mac_enabled is set, an Ethernet header with the 6-byte source
 * MAC is prepended and sent via an AF_PACKET raw socket (local
 * networks only); if that socket is unavailable the packet falls back
 * to IP_HDRINCL so loopback scans still work. sporof_mac is ignored
 * when disabled. Returns the same 0..4 codes as the other probes.
 */
int almap_syn_probe_evasion(unsigned int src_be, unsigned int dst_be, int dst_port, int timeout_ms,
                            int fragment, int mtu,
                            const unsigned int *decoys, int decoy_count,
                            const unsigned char *spoof_mac, int spoof_mac_enabled);

/* Step 31 T1-T7/U1 probes. probe_id 1..7 selects TCP flags (see
 * ALMAP_OS_PROBE_* in os.h). Returns the same 0..4 codes as the SYN
 * probe (0 SYN+ACK, 1 RST, 2 timeout/no reply, 3 error, 4 perm) and
 * fills result whenever a reply is captured. */
int almap_os_probe_tcp(int probe_id, unsigned int src_be,
                       unsigned int dst_be, int dst_port, int timeout_ms,
                       AlmapProbeResult *result);

/* Empty UDP datagram to dst_port; captures ICMP Port Unreachable
 * (UNREACH) or timeout (NONE). Returns 0 UNREACH, 2 timeout, 3 error,
 * 4 perm. */
int almap_os_probe_udp(unsigned int src_be, unsigned int dst_be,
                       int dst_port, int timeout_ms,
                       AlmapProbeResult *result);

/* Full T1-T7+U1 sequence: T1-T4 to open_port, T5-T7/U1 to closed_port
 * (ports <1 mean skip that half). Writes the signature string into
 * probe_out (NUL-terminated). Returns 0 on at least one probe sent,
 * 4 on permission, 3 on error, -1 on invalid args.
 */
int almap_os_probe_all(unsigned int src_be, unsigned int dst_be,
                       int open_port, int closed_port, int timeout_ms,
                       char *probe_out, int probe_cap);

#ifdef __cplusplus
}
#endif

#endif /* ALMAP_RAW_H */
