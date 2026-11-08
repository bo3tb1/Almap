#ifndef ALMAP_ICMP_H
#define ALMAP_ICMP_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * icmp.h - Step 7: ICMP echo (ping) raw-socket helper.
 *
 * Types map to Goose as: int -> i32, unsigned int -> u32.
 * dst_be is IPv4 as u32 with the first octet in the high byte
 * (e.g. 192.168.1.1 = 0xC0A80101); C converts it with htonl.
 * timeout_ms must be > 0.
 *
 * almap_icmp_can_raw():
 *   Returns 1 if socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) works,
 *   else 0. Does not send any packet.
 *
 * almap_icmp_ping(dst_be, timeout_ms):
 *   Returns 1 on a matching echo reply, 0 on no reply/timeout,
 *   -1 on error/permission. Sends one ICMP echo request and
 *   waits with poll()/recvfrom() for a matching echo reply
 *   (source IP = target, ICMP type = 0 echo reply). The raw
 *   socket is closed on every path.
 *
 * Use only on networks you own or have permission to scan.
 */

int almap_icmp_can_raw(void);
int almap_icmp_ping(unsigned int dst_be, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* ALMAP_ICMP_H */
