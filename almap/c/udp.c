#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "raw.h"
#include "udp.h"

/*
 * udp.c - Step 17: minimal IPv4 UDP scanner (POSIX, Linux).
 * No libpcap, no Nmap code, no worker pool, no banners, no OS
 * fingerprinting, NSE, or evasion.
 * Requires root or CAP_NET_RAW for the raw sockets.
 * Use only on networks you own or have permission to scan.
 *
 * Probe layout (28 bytes, sent with IP_HDRINCL):
 *   IPv4 header (20) + UDP header (8, empty payload).
 *   The IP checksum covers the IPv4 header; the UDP checksum covers
 *   the pseudo-header (src, dst, zero, IPPROTO_UDP, UDP length) + the
 *   UDP header. The source port is a simple incrementing ephemeral
 *   port (start 45000, wrap to 45000); this scan is sequential only so
 *   no mutex is needed.
 *
 * Two raw sockets are used: one IPPROTO_UDP socket for sending the
 * crafted datagram and receiving UDP responses, and one IPPROTO_ICMP
 * socket for receiving the ICMP port-unreachable that reports a closed
 * port. Responses are matched on source/destination IP, source port
 * (the target port), and destination port (our chosen source port).
 *
 * Packet building and matching live only in this file; c/raw.c is not
 * modified for Step 17 (it only provides almap_local_ip_for()).
 */

static uint16_t almap_udp_checksum(const unsigned char *data, size_t len) {
    uint32_t sum = 0;
    size_t i;
    for (i = 0; i + 1 < len; i += 2) {
        sum += (uint32_t)((unsigned int)data[i] << 8 | (unsigned int)data[i + 1]);
    }
    if (i < len) {
        sum += (uint32_t)((unsigned int)data[i] << 8);
    }
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

/* Sequential-only source port allocation; skipping the target port
 * keeps the response match unambiguous. */
static unsigned short almap_udp_next_sport = 45000;

static unsigned short almap_udp_alloc_sport(int dst_port) {
    unsigned short sport = almap_udp_next_sport;
    almap_udp_next_sport = (unsigned short)(almap_udp_next_sport + 1);
    if (almap_udp_next_sport < 45000) {
        almap_udp_next_sport = 45000;
    }
    if ((int)sport == dst_port) {
        sport = almap_udp_next_sport;
        almap_udp_next_sport = (unsigned short)(almap_udp_next_sport + 1);
        if (almap_udp_next_sport < 45000) {
            almap_udp_next_sport = 45000;
        }
    }
    return sport;
}

int almap_udp_can_raw(void) {
    int fd_udp;
    int fd_icmp;
    fd_udp = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (fd_udp < 0) {
        return 0;
    }
    fd_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd_icmp < 0) {
        close(fd_udp);
        return 0;
    }
    close(fd_udp);
    close(fd_icmp);
    return 1;
}

/* Does an incoming IP/UDP datagram answer our probe? */
static int almap_udp_match_response(const unsigned char *buf, size_t len,
                                    unsigned int dst_be, unsigned int src_be,
                                    unsigned short sport, int dst_port) {
    size_t ihl;
    unsigned int saddr;
    unsigned int daddr;
    unsigned int usport;
    unsigned int udport;

    if (len < 28) {
        return 0;
    }
    if ((buf[0] >> 4) != 4) {
        return 0;
    }
    ihl = (size_t)(buf[0] & 0x0F) * 4u;
    if (ihl < 20 || len < ihl + 8) {
        return 0;
    }
    if (buf[9] != (unsigned char)IPPROTO_UDP) {
        return 0;
    }
    saddr = ((unsigned int)buf[12] << 24) | ((unsigned int)buf[13] << 16)
        | ((unsigned int)buf[14] << 8) | (unsigned int)buf[15];
    daddr = ((unsigned int)buf[16] << 24) | ((unsigned int)buf[17] << 16)
        | ((unsigned int)buf[18] << 8) | (unsigned int)buf[19];
    if (saddr != dst_be || daddr != src_be) {
        return 0;
    }
    usport = ((unsigned int)buf[ihl] << 8) | (unsigned int)buf[ihl + 1];
    udport = ((unsigned int)buf[ihl + 2] << 8) | (unsigned int)buf[ihl + 3];
    if (usport != (unsigned int)dst_port || udport != (unsigned int)sport) {
        return 0;
    }
    return 1;
}

/* Does an incoming ICMP message carry a port-unreachable for our probe? */
static int almap_udp_match_icmp(const unsigned char *buf, size_t len,
                                unsigned int dst_be, unsigned int src_be,
                                unsigned short sport, int dst_port) {
    size_t ihl;
    size_t inner;
    size_t inner_ihl;
    unsigned int saddr;
    unsigned int inner_daddr;
    unsigned int isport;
    unsigned int idport;

    if (len < 28) {
        return 0;
    }
    if ((buf[0] >> 4) != 4) {
        return 0;
    }
    ihl = (size_t)(buf[0] & 0x0F) * 4u;
    if (ihl < 20 || len < ihl + 8 + 20) {
        return 0;
    }
    if (buf[9] != (unsigned char)IPPROTO_ICMP) {
        return 0;
    }
    saddr = ((unsigned int)buf[12] << 24) | ((unsigned int)buf[13] << 16)
        | ((unsigned int)buf[14] << 8) | (unsigned int)buf[15];
    if (saddr != dst_be) {
        return 0;
    }
    /* ICMP destination unreachable, code 3 = port unreachable. */
    if (buf[ihl] != 3 || buf[ihl + 1] != 3) {
        return 0;
    }
    inner = ihl + 8;
    if ((buf[inner] >> 4) != 4) {
        return 0;
    }
    inner_ihl = (size_t)(buf[inner] & 0x0F) * 4u;
    if (inner_ihl < 20 || len < inner + inner_ihl + 8) {
        return 0;
    }
    if (buf[inner + 9] != (unsigned char)IPPROTO_UDP) {
        return 0;
    }
    if (buf[inner + 12] != (unsigned char)((src_be >> 24) & 0xFF)
        || buf[inner + 13] != (unsigned char)((src_be >> 16) & 0xFF)
        || buf[inner + 14] != (unsigned char)((src_be >> 8) & 0xFF)
        || buf[inner + 15] != (unsigned char)(src_be & 0xFF)) {
        return 0;
    }
    inner_daddr = ((unsigned int)buf[inner + 16] << 24)
        | ((unsigned int)buf[inner + 17] << 16)
        | ((unsigned int)buf[inner + 18] << 8)
        | (unsigned int)buf[inner + 19];
    if (inner_daddr != dst_be) {
        return 0;
    }
    isport = ((unsigned int)buf[inner + inner_ihl] << 8)
        | (unsigned int)buf[inner + inner_ihl + 1];
    idport = ((unsigned int)buf[inner + inner_ihl + 2] << 8)
        | (unsigned int)buf[inner + inner_ihl + 3];
    if (isport != (unsigned int)sport || idport != (unsigned int)dst_port) {
        return 0;
    }
    return 1;
}

int almap_udp_scan(unsigned int dst_be, int port, int timeout_ms) {
    int send_fd = -1;
    int icmp_fd = -1;
    int result = 3;
    unsigned int src_be;
    unsigned short sport;
    unsigned char packet[28];
    unsigned char pseudo[20];
    uint16_t ip_sum;
    uint16_t udp_sum;
    struct sockaddr_in dest;
    struct timespec start;
    struct timespec now;

    if (dst_be == 0 || port < 1 || port > 65535 || timeout_ms <= 0) {
        return 3;
    }
    src_be = almap_local_ip_for(dst_be);
    if (src_be == 0) {
        return 3;
    }
    sport = almap_udp_alloc_sport(port);

    send_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (send_fd < 0) {
        if (errno == EPERM || errno == EACCES) {
            return 4;
        }
        return 3;
    }
    icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_fd < 0) {
        int saved = errno;
        close(send_fd);
        if (saved == EPERM || saved == EACCES) {
            return 4;
        }
        return 3;
    }
    {
        int one = 1;
        if (setsockopt(send_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) != 0) {
            close(send_fd);
            close(icmp_fd);
            return 3;
        }
    }

    /* IPv4 header (20 bytes). */
    memset(packet, 0, sizeof(packet));
    packet[0] = 0x45; /* version 4, IHL 5 */
    packet[1] = 0; /* TOS */
    packet[2] = 0; /* total length high: 28 */
    packet[3] = 28; /* total length low */
    packet[4] = (unsigned char)((sport >> 8) & 0xFF); /* ID high */
    packet[5] = (unsigned char)(sport & 0xFF); /* ID low */
    packet[6] = 0x40; /* flags/fragment: DF */
    packet[7] = 0;
    packet[8] = 64; /* TTL */
    packet[9] = (unsigned char)IPPROTO_UDP;
    packet[10] = 0; /* checksum (filled below) */
    packet[11] = 0;
    packet[12] = (unsigned char)((src_be >> 24) & 0xFF);
    packet[13] = (unsigned char)((src_be >> 16) & 0xFF);
    packet[14] = (unsigned char)((src_be >> 8) & 0xFF);
    packet[15] = (unsigned char)(src_be & 0xFF);
    packet[16] = (unsigned char)((dst_be >> 24) & 0xFF);
    packet[17] = (unsigned char)((dst_be >> 16) & 0xFF);
    packet[18] = (unsigned char)((dst_be >> 8) & 0xFF);
    packet[19] = (unsigned char)(dst_be & 0xFF);
    ip_sum = almap_udp_checksum(packet, 20);
    packet[10] = (unsigned char)((ip_sum >> 8) & 0xFF);
    packet[11] = (unsigned char)(ip_sum & 0xFF);

    /* UDP header (8 bytes, empty payload). */
    packet[20] = (unsigned char)((sport >> 8) & 0xFF);
    packet[21] = (unsigned char)(sport & 0xFF);
    packet[22] = (unsigned char)(((unsigned int)port >> 8) & 0xFF);
    packet[23] = (unsigned char)((unsigned int)port & 0xFF);
    packet[24] = 0; /* UDP length 8 high */
    packet[25] = 8; /* UDP length 8 low */
    packet[26] = 0; /* checksum (filled below) */
    packet[27] = 0;

    /* Pseudo-header + UDP header for the UDP checksum. */
    memset(pseudo, 0, sizeof(pseudo));
    pseudo[0] = packet[12];
    pseudo[1] = packet[13];
    pseudo[2] = packet[14];
    pseudo[3] = packet[15];
    pseudo[4] = packet[16];
    pseudo[5] = packet[17];
    pseudo[6] = packet[18];
    pseudo[7] = packet[19];
    pseudo[8] = 0;
    pseudo[9] = (unsigned char)IPPROTO_UDP;
    pseudo[10] = 0; /* UDP length 8 high */
    pseudo[11] = 8; /* UDP length 8 low */
    memcpy(&pseudo[12], &packet[20], 8);
    udp_sum = almap_udp_checksum(pseudo, sizeof(pseudo));
    packet[26] = (unsigned char)((udp_sum >> 8) & 0xFF);
    packet[27] = (unsigned char)(udp_sum & 0xFF);

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons((uint16_t)port);
    dest.sin_addr.s_addr = htonl(dst_be);
    if (sendto(send_fd, packet, sizeof(packet), 0,
               (struct sockaddr *)&dest, sizeof(dest)) != (ssize_t)sizeof(packet)) {
        if (errno == EPERM || errno == EACCES) {
            result = 4;
        } else {
            result = 3;
        }
        close(send_fd);
        close(icmp_fd);
        return result;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        close(send_fd);
        close(icmp_fd);
        return 3;
    }

    for (;;) {
        struct pollfd fds[2];
        long elapsed_ms;
        long remain_ms;
        int pr;

        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            result = 3;
            break;
        }
        elapsed_ms = (long)(now.tv_sec - start.tv_sec) * 1000L
            + (long)(now.tv_nsec - start.tv_nsec) / 1000000L;
        remain_ms = (long)timeout_ms - elapsed_ms;
        if (remain_ms <= 0) {
            result = 2;
            break;
        }
        fds[0].fd = send_fd;
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        fds[1].fd = icmp_fd;
        fds[1].events = POLLIN;
        fds[1].revents = 0;
        pr = poll(fds, 2, (int)remain_ms);
        if (pr == 0) {
            result = 2;
            break;
        }
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            result = 3;
            break;
        }
        if ((fds[0].revents & POLLIN) != 0) {
            unsigned char rbuf[2048];
            ssize_t rlen = recvfrom(send_fd, rbuf, sizeof(rbuf), 0, NULL, NULL);
            if (rlen > 0
                && almap_udp_match_response(rbuf, (size_t)rlen, dst_be, src_be,
                                            sport, port) != 0) {
                result = 0;
                break;
            }
        }
        if ((fds[1].revents & POLLIN) != 0) {
            unsigned char rbuf[2048];
            ssize_t rlen = recvfrom(icmp_fd, rbuf, sizeof(rbuf), 0, NULL, NULL);
            if (rlen > 0
                && almap_udp_match_icmp(rbuf, (size_t)rlen, dst_be, src_be,
                                        sport, port) != 0) {
                result = 1;
                break;
            }
        }
    }

    close(send_fd);
    close(icmp_fd);
    return result;
}
