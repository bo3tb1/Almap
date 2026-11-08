#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "icmp.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * icmp.c - Step 7: minimal ICMP echo (ping) via raw socket.
 * No libpcap, no Nmap code, no host discovery beyond echo,
 * no banner grabbing, fingerprinting, NSE, or evasion.
 * Requires root or CAP_NET_RAW to create the raw socket.
 * Use only on networks you own or have permission to scan.
 *
 * Echo layout (8 bytes, no payload):
 *   type 8 (echo request), code 0, checksum, identifier 0x1234,
 *   sequence 0. The reply is matched on source IP = target,
 *   ICMP type = 0 (echo reply), and identifier/sequence equal
 *   to the request. Other packets are ignored until the timeout.
 */

static uint16_t almap_icmp_checksum(const unsigned char *data, size_t len) {
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

int almap_icmp_can_raw(void) {
    int fd;
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) {
        return 0;
    }
    close(fd);
    return 1;
}

int almap_icmp_ping(unsigned int dst_be, int timeout_ms) {
    int fd = -1;
    int result = -1;
    unsigned char pkt[8];
    uint16_t csum;
    struct sockaddr_in dest;
    struct timespec start;
    struct timespec now;

    if (dst_be == 0 || timeout_ms <= 0) {
        return -1;
    }

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) {
        return -1;
    }

    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 8; /* echo request */
    pkt[1] = 0; /* code */
    pkt[2] = 0; /* checksum (filled below) */
    pkt[3] = 0;
    pkt[4] = 0x12; /* identifier 0x1234 high */
    pkt[5] = 0x34; /* identifier low */
    pkt[6] = 0; /* sequence 0 high */
    pkt[7] = 0; /* sequence low */
    csum = almap_icmp_checksum(pkt, sizeof(pkt));
    pkt[2] = (unsigned char)((csum >> 8) & 0xFF);
    pkt[3] = (unsigned char)(csum & 0xFF);

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = 0;
    dest.sin_addr.s_addr = htonl(dst_be);
    if (sendto(fd, pkt, sizeof(pkt), 0,
               (struct sockaddr *)&dest, sizeof(dest)) != (ssize_t)sizeof(pkt)) {
        close(fd);
        return -1;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        close(fd);
        return -1;
    }

    for (;;) {
        struct pollfd pfd;
        long elapsed_ms;
        long remain_ms;
        int pr;
        unsigned char rbuf[2048];
        ssize_t rlen;

        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            result = -1;
            break;
        }
        elapsed_ms = (long)(now.tv_sec - start.tv_sec) * 1000L
            + (long)(now.tv_nsec - start.tv_nsec) / 1000000L;
        remain_ms = (long)timeout_ms - elapsed_ms;
        if (remain_ms <= 0) {
            result = 0;
            break;
        }
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        pr = poll(&pfd, 1, (int)remain_ms);
        if (pr == 0) {
            result = 0;
            break;
        }
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            result = -1;
            break;
        }
        if ((pfd.revents & POLLIN) == 0) {
            result = -1;
            break;
        }
        rlen = recvfrom(fd, rbuf, sizeof(rbuf), 0, NULL, NULL);
        if (rlen < 0) {
            if (errno == EINTR) {
                continue;
            }
            result = -1;
            break;
        }
        {
            size_t len = (size_t)rlen;
            size_t ihl;
            uint32_t resp_saddr;
            const unsigned char *icmp;
            size_t icmp_len;

            if (len < 28) {
                continue;
            }
            if ((rbuf[0] >> 4) != 4) {
                continue;
            }
            ihl = (size_t)(rbuf[0] & 0x0F) * 4u;
            if (ihl < 20 || len < ihl + 8) {
                continue;
            }
            if (rbuf[9] != (unsigned char)IPPROTO_ICMP) {
                continue;
            }
            icmp = &rbuf[ihl];
            icmp_len = len - ihl;
            if (icmp_len < 8) {
                continue;
            }
            resp_saddr = ((uint32_t)rbuf[12] << 24)
                | ((uint32_t)rbuf[13] << 16)
                | ((uint32_t)rbuf[14] << 8)
                | (uint32_t)rbuf[15];
            if (resp_saddr != dst_be) {
                continue;
            }
            if (icmp[0] != 0) {
                continue;
            }
            if (icmp[4] != 0x12 || icmp[5] != 0x34) {
                continue;
            }
            if (icmp[6] != 0 || icmp[7] != 0) {
                continue;
            }
            result = 1;
            break;
        }
    }

    close(fd);
    return result;
}
