#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <unistd.h>

#include "raw.h"

/*
 * raw.c - Steps 5,12,19: minimal IPv4 TCP SYN scanner (POSIX, Linux).
 * No libpcap, no Nmap code, no host discovery, banner grabbing, NSE,
 * or evasion. Step 19 extracts coarse OS heuristics from a matching
 * SYN+ACK; it does not send fingerprint-specific probes.
 * Requires root or CAP_NET_RAW to create the raw socket.
 * Use only on networks you own or have permission to scan.
 *
 * Packet layout (40 bytes, sent with IP_HDRINCL):
 *   IPv4 header (20) + TCP header (20, SYN, no options).
 *   IP checksum over the IPv4 header; TCP checksum over the
 *   pseudo-header (src, dst, zero, IPPROTO_TCP, TCP length) + TCP.
 *   Source port is a simple incrementing ephemeral port (start 40000,
 *   wrap to 40000); no randomness is required. The response is
 *   matched on source IP = target, source port = target port,
 *   destination port = chosen local source port. SYN+ACK => open,
 *   RST => closed, otherwise keep waiting until the timeout.
 *   For a SYN+ACK, optional Step 19 output captures the received TTL,
 *   IP ID, TCP window, and MSS/SACK/Timestamps option presence.
 */

static uint16_t almap_checksum(const unsigned char *data, size_t len) {
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

/* Step 21: public RFC 1071 checksum for unit tests. */
int almap_packet_checksum(const unsigned char *data, int len) {
    if (data == NULL || len <= 0) {
        return 0;
    }
    return (int)almap_checksum(data, (size_t)len);
}

int almap_fragment_payload(int mtu) {
    int payload;
    if (mtu < 28) {
        return 8;
    }
    payload = mtu - 20;
    payload = (payload / 8) * 8;
    if (payload < 8) {
        return 8;
    }
    return payload;
}

int almap_fragment_count(int ip_total_len, int mtu) {
    int payload;
    int per;
    if (ip_total_len < 20 || mtu < 28) {
        return 0;
    }
    payload = ip_total_len - 20;
    if (payload <= 0) {
        return 0;
    }
    per = almap_fragment_payload(mtu);
    if (payload <= per) {
        return 1;
    }
    return (payload + per - 1) / per;
}

int almap_syn_can_raw(void) {
    int fd;
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd < 0) {
        return 0;
    }
    close(fd);
    return 1;
}

unsigned int almap_local_ip_for(unsigned int dst_be) {
    int fd;
    struct sockaddr_in dst;
    struct sockaddr_in local;
    socklen_t len;
    unsigned int result;

    if (dst_be == 0) {
        return 0;
    }
    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return 0;
    }
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons((uint16_t)80);
    dst.sin_addr.s_addr = htonl(dst_be);
    if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) != 0) {
        close(fd);
        return 0;
    }
    memset(&local, 0, sizeof(local));
    len = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &len) != 0) {
        close(fd);
        return 0;
    }
    result = ntohl(local.sin_addr.s_addr);
    close(fd);
    return result;
}

/* Source ports are allocated under a mutex so the sequential path
 * and concurrent pool workers never share a source port. */
static pthread_mutex_t almap_sport_mu = PTHREAD_MUTEX_INITIALIZER;
static unsigned short almap_next_sport = 40000;

static unsigned short almap_alloc_sport(int dst_port) {
    unsigned short sport;

    pthread_mutex_lock(&almap_sport_mu);
    sport = almap_next_sport;
    almap_next_sport = (unsigned short)(almap_next_sport + 1);
    if (almap_next_sport < 40000) {
        almap_next_sport = 40000;
    }
    if ((int)sport == dst_port) {
        sport = almap_next_sport;
        almap_next_sport = (unsigned short)(almap_next_sport + 1);
        if (almap_next_sport < 40000) {
            almap_next_sport = 40000;
        }
    }
    pthread_mutex_unlock(&almap_sport_mu);
    return sport;
}

/* Parse a TCP option area and return ALMAP_OS_OPT_* presence bits.
 * Malformed lengths stop parsing; the rest of the SYN+ACK is still
 * usable. EOL and NOP are handled explicitly. */
static int almap_parse_tcp_options(const unsigned char *opts, int len) {
    int bits = 0;
    int i = 0;

    while (i < len) {
        int kind = (int)opts[i];
        int olen;
        if (kind == 0) {
            break;
        }
        if (kind == 1) {
            i++;
            continue;
        }
        if (i + 1 >= len) {
            break;
        }
        olen = (int)opts[i + 1];
        if (olen < 2 || i + olen > len) {
            break;
        }
        if (kind == 2 && olen == 4) {
            bits |= ALMAP_OS_OPT_MSS;
        } else if (kind == 4 && olen == 2) {
            bits |= ALMAP_OS_OPT_SACK;
        } else if (kind == 8 && olen == 10) {
            bits |= ALMAP_OS_OPT_TIMESTAMPS;
        }
        i += olen;
    }
    return bits;
}

/* Single-SYN probe shared by almap_syn_scan(), almap_syn_probe(), and
 * almap_syn_probe_os(). sample may be NULL; when non-NULL it is filled
 * only for a matching SYN+ACK. See raw.h for return codes. */
static int syn_probe_once(unsigned int src_be, unsigned int dst_be, int dst_port, int timeout_ms, AlmapOsSample *sample) {
    int fd = -1;
    int result = 3;
    unsigned char packet[40];
    unsigned char pseudo[32];
    uint16_t ip_sum;
    uint16_t tcp_sum;
    struct sockaddr_in dest;
    struct timespec start;
    struct timespec now;
    unsigned short sport;

    if (sample != NULL) {
        memset(sample, 0, sizeof(*sample));
    }
    if (src_be == 0 || dst_be == 0 || dst_port < 1 || dst_port > 65535 || timeout_ms <= 0) {
        return 3;
    }

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd < 0) {
        if (errno == EPERM || errno == EACCES) {
            return 4;
        }
        return 3;
    }

    /* Choose the next incrementing source port (skip the target port). */
    sport = almap_alloc_sport(dst_port);

    memset(packet, 0, sizeof(packet));
    /* IPv4 header (20 bytes). */
    packet[0] = 0x45; /* version 4, IHL 5 */
    packet[1] = 0; /* TOS */
    packet[2] = 0; /* total length high: 40 */
    packet[3] = 40; /* total length low */
    packet[4] = (unsigned char)((sport >> 8) & 0xFF); /* ID high (reuse seq) */
    packet[5] = (unsigned char)(sport & 0xFF); /* ID low */
    packet[6] = 0x40; /* flags/fragment: DF */
    packet[7] = 0;
    packet[8] = 64; /* TTL */
    packet[9] = (unsigned char)IPPROTO_TCP;
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
    ip_sum = almap_checksum(packet, 20);
    packet[10] = (unsigned char)((ip_sum >> 8) & 0xFF);
    packet[11] = (unsigned char)(ip_sum & 0xFF);

    /* TCP header (20 bytes). */
    packet[20] = (unsigned char)((sport >> 8) & 0xFF);
    packet[21] = (unsigned char)(sport & 0xFF);
    packet[22] = (unsigned char)(((unsigned int)dst_port >> 8) & 0xFF);
    packet[23] = (unsigned char)((unsigned int)dst_port & 0xFF);
    packet[24] = 0; /* seq (0) */
    packet[25] = 0;
    packet[26] = 0;
    packet[27] = 0;
    packet[28] = 0; /* ack (0) */
    packet[29] = 0;
    packet[30] = 0;
    packet[31] = 0;
    packet[32] = 0x50; /* data offset 5 (20 bytes) */
    packet[33] = 0x02; /* SYN */
    packet[34] = 0x04; /* window 1024 high */
    packet[35] = 0x00; /* window low */
    packet[36] = 0; /* checksum (filled below) */
    packet[37] = 0;
    packet[38] = 0; /* urgent pointer */
    packet[39] = 0;

    /* Pseudo-header + TCP header for the TCP checksum. */
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
    pseudo[9] = (unsigned char)IPPROTO_TCP;
    pseudo[10] = 0; /* TCP length 20 (high) */
    pseudo[11] = 20; /* TCP length low */
    memcpy(&pseudo[12], &packet[20], 20);
    tcp_sum = almap_checksum(pseudo, sizeof(pseudo));
    packet[36] = (unsigned char)((tcp_sum >> 8) & 0xFF);
    packet[37] = (unsigned char)(tcp_sum & 0xFF);

    /* Send with the kernel-provided destination from the packet. */
    {
        int one = 1;
        if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) != 0) {
            close(fd);
            return 3;
        }
    }
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons((uint16_t)dst_port);
    dest.sin_addr.s_addr = htonl(dst_be);
    if (sendto(fd, packet, sizeof(packet), 0,
               (struct sockaddr *)&dest, sizeof(dest)) != (ssize_t)sizeof(packet)) {
        if (errno == EPERM || errno == EACCES) {
            result = 4;
        } else {
            result = 3;
        }
        close(fd);
        return result;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        close(fd);
        return 3;
    }

    for (;;) {
        struct pollfd pfd;
        long elapsed_ms;
        long remain_ms;
        int pr;
        unsigned char rbuf[2048];
        ssize_t rlen;

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
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        pr = poll(&pfd, 1, (int)remain_ms);
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
        if ((pfd.revents & POLLIN) == 0) {
            result = 3;
            break;
        }
        rlen = recvfrom(fd, rbuf, sizeof(rbuf), 0, NULL, NULL);
        if (rlen < 0) {
            if (errno == EINTR) {
                continue;
            }
            result = 3;
            break;
        }
        {
            size_t len = (size_t)rlen;
            size_t ihl;
            unsigned int resp_sport;
            unsigned int resp_dport;
            uint32_t resp_saddr;
            unsigned char tflags;

            if (len < 40) {
                continue;
            }
            if ((rbuf[0] >> 4) != 4) {
                continue;
            }
            ihl = (size_t)(rbuf[0] & 0x0F) * 4u;
            if (ihl < 20 || len < ihl + 20) {
                continue;
            }
            if (rbuf[9] != (unsigned char)IPPROTO_TCP) {
                continue;
            }
            resp_saddr = ((uint32_t)rbuf[12] << 24)
                | ((uint32_t)rbuf[13] << 16)
                | ((uint32_t)rbuf[14] << 8)
                | (uint32_t)rbuf[15];
            if (resp_saddr != dst_be) {
                continue;
            }
            resp_sport = ((unsigned int)rbuf[ihl] << 8) | (unsigned int)rbuf[ihl + 1];
            resp_dport = ((unsigned int)rbuf[ihl + 2] << 8) | (unsigned int)rbuf[ihl + 3];
            if (resp_sport != (unsigned int)dst_port) {
                continue;
            }
            if (resp_dport != (unsigned int)sport) {
                continue;
            }
            tflags = rbuf[ihl + 13];
            if ((tflags & 0x04) != 0) {
                result = 1;
                break;
            }
            if ((tflags & 0x02) != 0 && (tflags & 0x10) != 0) {
                if (sample != NULL) {
                    size_t tcp_len = len - ihl;
                    size_t doff = (size_t)(rbuf[ihl + 12] >> 4) * 4u;
                    sample->ttl = (int)rbuf[8];
                    sample->ip_id = ((int)rbuf[4] << 8) | (int)rbuf[5];
                    sample->window = ((int)rbuf[ihl + 14] << 8)
                        | (int)rbuf[ihl + 15];
                    sample->options = 0;
                    if (doff >= 20 && doff <= tcp_len) {
                        sample->options = almap_parse_tcp_options(
                            &rbuf[ihl + 20], (int)(doff - 20));
                    }
                }
                result = 0;
                break;
            }
            /* Other flags: keep waiting until the timeout. */
        }
    }

    close(fd);
    return result;
}

int almap_syn_scan(unsigned int src_be, unsigned int dst_be, int dst_port, int timeout_ms) {
    return syn_probe_once(src_be, dst_be, dst_port, timeout_ms, NULL);
}

int almap_syn_probe(unsigned int src_be, unsigned int dst_be, int dst_port, int timeout_ms) {
    return syn_probe_once(src_be, dst_be, dst_port, timeout_ms, NULL);
}

int almap_syn_probe_os(unsigned int src_be, unsigned int dst_be, int dst_port, int timeout_ms, AlmapOsSample *sample) {
    return syn_probe_once(src_be, dst_be, dst_port, timeout_ms, sample);
}

/* Step 21: send one IP+TCP variant (real or decoy) with optional
 * fragmentation and optional Ethernet spoofing. Returns 0 on success,
 * -1 on failure. The base packet must already have IP/TCP checksums
 * filled for its source address. */
static int almap_send_variant(int fd, const unsigned char *base, int base_len,
                              unsigned int dst_be, int dst_port,
                              int fragment, int mtu,
                              const unsigned char *spoof_mac, int spoof_mac_enabled) {
    struct sockaddr_in dest;
    int frag_count = 1;
    int i;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons((uint16_t)dst_port);
    dest.sin_addr.s_addr = htonl(dst_be);

    if (fragment != 0) {
        frag_count = almap_fragment_count(base_len, mtu);
        if (frag_count <= 0) {
            return -1;
        }
    }

    for (i = 0; i < frag_count; i++) {
        unsigned char frag[60];
        int payload_len;
        int frag_len;
        int off;
        uint16_t sum;
        int more;

        if (fragment == 0) {
            payload_len = base_len;
            off = 0;
            more = 0;
        } else {
            int total_payload = base_len - 20;
            int per = almap_fragment_payload(mtu);
            off = i * per;
            if (total_payload - off < per) {
                payload_len = total_payload - off;
            } else {
                payload_len = per;
            }
            more = (i + 1 < frag_count) ? 1 : 0;
        }
        frag_len = 20 + payload_len;
        if (frag_len < 20 || frag_len > (int)sizeof(frag)) {
            return -1;
        }
        memset(frag, 0, sizeof(frag));
        memcpy(frag, base, 20);
        frag[2] = (unsigned char)(((unsigned int)frag_len >> 8) & 0xFF);
        frag[3] = (unsigned char)((unsigned int)frag_len & 0xFF);
        /* Flags/fragment offset: DF cleared when fragmenting. */
        frag[6] = (unsigned char)((more ? 0x20 : 0x00) | (((off / 8) >> 8) & 0x1F));
        frag[7] = (unsigned char)((off / 8) & 0xFF);
        frag[10] = 0;
        frag[11] = 0;
        if (fragment == 0) {
            memcpy(&frag[20], &base[20], payload_len);
        } else {
            memcpy(&frag[20], &base[20 + off], payload_len);
        }
        sum = almap_checksum(frag, 20);
        frag[10] = (unsigned char)((sum >> 8) & 0xFF);
        frag[11] = (unsigned char)(sum & 0xFF);

        if (spoof_mac_enabled != 0 && spoof_mac != NULL) {
            /* Best-effort Ethernet path (local networks only). A
             * failure falls back to the IP_HDRINCL send so loopback
             * integration still exercises the code path. */
            int pfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
            if (pfd >= 0) {
                unsigned char frame[14 + 60];
                struct sockaddr_ll ll;
                memset(frame, 0, sizeof(frame));
                memset(&frame[0], 0xFF, 6); /* dst broadcast (ARP will decide) */
                memcpy(&frame[6], spoof_mac, 6);
                frame[12] = 0x08;
                frame[13] = 0x00; /* IPv4 */
                memcpy(&frame[14], frag, (size_t)frag_len);
                memset(&ll, 0, sizeof(ll));
                ll.sll_family = AF_PACKET;
                ll.sll_protocol = htons(ETH_P_IP);
                ll.sll_ifindex = 0;
                if (sendto(pfd, frame, (size_t)(14 + frag_len), 0,
                           (struct sockaddr *)&ll, sizeof(ll)) == (ssize_t)(14 + frag_len)) {
                    close(pfd);
                    continue;
                }
                close(pfd);
            }
        }
        if (sendto(fd, frag, (size_t)frag_len, 0,
                   (struct sockaddr *)&dest, sizeof(dest)) != (ssize_t)frag_len) {
            return -1;
        }
    }
    return 0;
}

static int almap_fix_checksums(unsigned char *packet, unsigned int src_be) {
    unsigned char pseudo[12];
    uint16_t ip_sum;
    uint16_t tcp_sum;

    packet[12] = (unsigned char)((src_be >> 24) & 0xFF);
    packet[13] = (unsigned char)((src_be >> 16) & 0xFF);
    packet[14] = (unsigned char)((src_be >> 8) & 0xFF);
    packet[15] = (unsigned char)(src_be & 0xFF);
    packet[10] = 0;
    packet[11] = 0;
    ip_sum = almap_checksum(packet, 20);
    packet[10] = (unsigned char)((ip_sum >> 8) & 0xFF);
    packet[11] = (unsigned char)(ip_sum & 0xFF);
    packet[36] = 0;
    packet[37] = 0;
    memset(pseudo, 0, sizeof(pseudo));
    memcpy(pseudo, &packet[12], 8);
    pseudo[8] = 0;
    pseudo[9] = (unsigned char)IPPROTO_TCP;
    pseudo[10] = 0;
    pseudo[11] = 20;
    tcp_sum = almap_checksum(pseudo, 12);
    {
        unsigned char tcp[20];
        memcpy(tcp, &packet[20], 20);
        tcp_sum = almap_checksum(pseudo, 12);
        /* checksum over pseudo + tcp together */
        {
            unsigned char both[32];
            memcpy(both, pseudo, 12);
            memcpy(&both[12], tcp, 20);
            tcp_sum = almap_checksum(both, sizeof(both));
        }
    }
    packet[36] = (unsigned char)((tcp_sum >> 8) & 0xFF);
    packet[37] = (unsigned char)(tcp_sum & 0xFF);
    return 0;
}

int almap_syn_probe_evasion(unsigned int src_be, unsigned int dst_be, int dst_port, int timeout_ms,
                            int fragment, int mtu,
                            const unsigned int *decoys, int decoy_count,
                            const unsigned char *spoof_mac, int spoof_mac_enabled) {
    int fd = -1;
    int result = 3;
    unsigned char packet[40];
    unsigned short sport;
    struct sockaddr_in dest;
    struct timespec start;
    struct timespec now;
    int d;
    int ndecoys;

    if (src_be == 0 || dst_be == 0 || dst_port < 1 || dst_port > 65535 || timeout_ms <= 0) {
        return 3;
    }
    if (mtu <= 0) {
        mtu = 32;
    }
    (void)mtu;
    if (decoys == NULL || decoy_count <= 0) {
        ndecoys = 0;
    } else if (decoy_count > 5) {
        ndecoys = 5;
    } else {
        ndecoys = decoy_count;
    }

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd < 0) {
        if (errno == EPERM || errno == EACCES) {
            return 4;
        }
        return 3;
    }
    {
        int one = 1;
        if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) != 0) {
            close(fd);
            return 3;
        }
    }

    sport = almap_alloc_sport(dst_port);
    memset(packet, 0, sizeof(packet));
    packet[0] = 0x45;
    packet[1] = 0;
    packet[2] = 0;
    packet[3] = 40;
    packet[4] = (unsigned char)((sport >> 8) & 0xFF);
    packet[5] = (unsigned char)(sport & 0xFF);
    packet[6] = (fragment != 0) ? 0x00 : 0x40;
    packet[7] = 0;
    packet[8] = 64;
    packet[9] = (unsigned char)IPPROTO_TCP;
    packet[12] = (unsigned char)((src_be >> 24) & 0xFF);
    packet[13] = (unsigned char)((src_be >> 16) & 0xFF);
    packet[14] = (unsigned char)((src_be >> 8) & 0xFF);
    packet[15] = (unsigned char)(src_be & 0xFF);
    packet[16] = (unsigned char)((dst_be >> 24) & 0xFF);
    packet[17] = (unsigned char)((dst_be >> 16) & 0xFF);
    packet[18] = (unsigned char)((dst_be >> 8) & 0xFF);
    packet[19] = (unsigned char)(dst_be & 0xFF);
    packet[20] = (unsigned char)((sport >> 8) & 0xFF);
    packet[21] = (unsigned char)(sport & 0xFF);
    packet[22] = (unsigned char)(((unsigned int)dst_port >> 8) & 0xFF);
    packet[23] = (unsigned char)((unsigned int)dst_port & 0xFF);
    packet[32] = 0x50;
    packet[33] = 0x02;
    packet[34] = 0x04;
    packet[35] = 0x00;
    almap_fix_checksums(packet, src_be);

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons((uint16_t)dst_port);
    dest.sin_addr.s_addr = htonl(dst_be);

    /* Real source first, then identical decoys (same sport/IP ID/seq). */
    if (almap_send_variant(fd, packet, 40, dst_be, dst_port, fragment, mtu, spoof_mac, spoof_mac_enabled) != 0) {
        if (errno == EPERM || errno == EACCES) {
            result = 4;
        }
        close(fd);
        return result;
    }
    for (d = 0; d < ndecoys; d++) {
        unsigned char dpacket[40];
        memcpy(dpacket, packet, sizeof(dpacket));
        almap_fix_checksums(dpacket, decoys[d]);
        /* Decoys are best-effort: their send result does not change
         * the outcome for the real probe. */
        (void)almap_send_variant(fd, dpacket, 40, dst_be, dst_port, fragment, mtu, spoof_mac, spoof_mac_enabled);
    }

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        close(fd);
        return 3;
    }
    for (;;) {
        struct pollfd pfd;
        long elapsed_ms;
        long remain_ms;
        int pr;
        unsigned char rbuf[2048];
        ssize_t rlen;

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
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        pr = poll(&pfd, 1, (int)remain_ms);
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
        if ((pfd.revents & POLLIN) == 0) {
            result = 3;
            break;
        }
        rlen = recvfrom(fd, rbuf, sizeof(rbuf), 0, NULL, NULL);
        if (rlen < 0) {
            if (errno == EINTR) {
                continue;
            }
            result = 3;
            break;
        }
        {
            size_t len = (size_t)rlen;
            size_t ihl;
            unsigned int resp_sport;
            unsigned int resp_dport;
            unsigned int resp_saddr;
            unsigned char tflags;

            if (len < 40) {
                continue;
            }
            if ((rbuf[0] >> 4) != 4) {
                continue;
            }
            ihl = (size_t)(rbuf[0] & 0x0F) * 4u;
            if (ihl < 20 || len < ihl + 20) {
                continue;
            }
            if (rbuf[9] != (unsigned char)IPPROTO_TCP) {
                continue;
            }
            resp_saddr = ((unsigned int)rbuf[12] << 24)
                | ((unsigned int)rbuf[13] << 16)
                | ((unsigned int)rbuf[14] << 8)
                | (unsigned int)rbuf[15];
            if (resp_saddr != dst_be) {
                continue;
            }
            resp_sport = ((unsigned int)rbuf[ihl] << 8) | (unsigned int)rbuf[ihl + 1];
            resp_dport = ((unsigned int)rbuf[ihl + 2] << 8) | (unsigned int)rbuf[ihl + 3];
            if (resp_sport != (unsigned int)dst_port) {
                continue;
            }
            if (resp_dport != (unsigned int)sport) {
                continue;
            }
            tflags = rbuf[ihl + 13];
            if ((tflags & 0x04) != 0) {
                result = 1;
                break;
            }
            if ((tflags & 0x02) != 0 && (tflags & 0x10) != 0) {
                result = 0;
                break;
            }
        }
    }
    close(fd);
    return result;
}

/* ---- Step 31 T1-T7 + U1 probes (raw packet crafting, IP_HDRINCL) ---- */

static int flags_for_probe(int probe_id) {
    switch (probe_id) {
    case 1: return 0x02; /* SYN */
    case 2: return 0x00; /* NULL */
    case 3: return 0x2B; /* SYN|FIN|URG|PSH */
    case 4: return 0x10; /* ACK */
    case 5: return 0x02; /* SYN (closed) */
    case 6: return 0x10; /* ACK (closed) */
    case 7: return 0x29; /* FIN|PSH|URG */
    default: return -1;
    }
}

int almap_os_probe_tcp(int probe_id, unsigned int src_be, unsigned int dst_be,
                       int dst_port, int timeout_ms,
                       AlmapProbeResult *result) {
    int fd = -1;
    int flags_byte;
    unsigned char packet[40];
    unsigned char pseudo[32];
    uint16_t ip_sum;
    uint16_t tcp_sum;
    struct sockaddr_in dest;
    struct timespec start;
    struct timespec now;
    unsigned short sport;
    int ret = 3;

    if (result != NULL) {
        memset(result, 0, sizeof(*result));
    }
    if (probe_id < 1 || probe_id > 7 || src_be == 0 || dst_be == 0
        || dst_port < 1 || dst_port > 65535 || timeout_ms <= 0) {
        return 3;
    }
    flags_byte = flags_for_probe(probe_id);
    if (flags_byte < 0) {
        return 3;
    }
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd < 0) {
        if (errno == EPERM || errno == EACCES) {
            return 4;
        }
        return 3;
    }
    sport = almap_alloc_sport(dst_port);
    memset(packet, 0, sizeof(packet));
    packet[0] = 0x45;
    packet[1] = 0;
    packet[2] = 0;
    packet[3] = 40;
    packet[4] = (unsigned char)((sport >> 8) & 0xFF);
    packet[5] = (unsigned char)(sport & 0xFF);
    packet[6] = 0x40;
    packet[7] = 0;
    packet[8] = 64;
    packet[9] = (unsigned char)IPPROTO_TCP;
    packet[12] = (unsigned char)((src_be >> 24) & 0xFF);
    packet[13] = (unsigned char)((src_be >> 16) & 0xFF);
    packet[14] = (unsigned char)((src_be >> 8) & 0xFF);
    packet[15] = (unsigned char)(src_be & 0xFF);
    packet[16] = (unsigned char)((dst_be >> 24) & 0xFF);
    packet[17] = (unsigned char)((dst_be >> 16) & 0xFF);
    packet[18] = (unsigned char)((dst_be >> 8) & 0xFF);
    packet[19] = (unsigned char)(dst_be & 0xFF);
    ip_sum = almap_checksum(packet, 20);
    packet[10] = (unsigned char)((ip_sum >> 8) & 0xFF);
    packet[11] = (unsigned char)(ip_sum & 0xFF);

    packet[20] = (unsigned char)((sport >> 8) & 0xFF);
    packet[21] = (unsigned char)(sport & 0xFF);
    packet[22] = (unsigned char)(((unsigned int)dst_port >> 8) & 0xFF);
    packet[23] = (unsigned char)((unsigned int)dst_port & 0xFF);
    packet[24] = 0; packet[25] = 0; packet[26] = 0; packet[27] = 0; /* seq 0 */
    packet[28] = 0; packet[29] = 0; packet[30] = 0; packet[31] = 0; /* ack 0 */
    packet[32] = 0x50;
    packet[33] = (unsigned char)flags_byte;
    packet[34] = 0x04; packet[35] = 0x00; /* window 1024 */
    packet[36] = 0; packet[37] = 0;
    packet[38] = 0; packet[39] = 0;

    memset(pseudo, 0, sizeof(pseudo));
    memcpy(pseudo, &packet[12], 8);
    pseudo[8] = 0;
    pseudo[9] = (unsigned char)IPPROTO_TCP;
    pseudo[10] = 0; pseudo[11] = 20;
    memcpy(&pseudo[12], &packet[20], 20);
    tcp_sum = almap_checksum(pseudo, sizeof(pseudo));
    packet[36] = (unsigned char)((tcp_sum >> 8) & 0xFF);
    packet[37] = (unsigned char)(tcp_sum & 0xFF);

    {
        int one = 1;
        if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) != 0) {
            close(fd);
            return 3;
        }
    }
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons((uint16_t)dst_port);
    dest.sin_addr.s_addr = htonl(dst_be);
    if (sendto(fd, packet, sizeof(packet), 0,
               (struct sockaddr *)&dest, sizeof(dest)) != (ssize_t)sizeof(packet)) {
        if (errno == EPERM || errno == EACCES) {
            ret = 4;
        } else {
            ret = 3;
        }
        close(fd);
        return ret;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        close(fd);
        return 3;
    }
    for (;;) {
        struct pollfd pfd;
        long elapsed_ms;
        long remain_ms;
        int pr;
        unsigned char rbuf[2048];
        ssize_t rlen;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            ret = 3;
            break;
        }
        elapsed_ms = (long)(now.tv_sec - start.tv_sec) * 1000L
            + (long)(now.tv_nsec - start.tv_nsec) / 1000000L;
        remain_ms = (long)timeout_ms - elapsed_ms;
        if (remain_ms <= 0) {
            ret = 2;
            break;
        }
        pfd.fd = fd; pfd.events = POLLIN; pfd.revents = 0;
        pr = poll(&pfd, 1, (int)remain_ms);
        if (pr == 0) { ret = 2; break; }
        if (pr < 0) {
            if (errno == EINTR) { continue; }
            ret = 3; break;
        }
        if ((pfd.revents & POLLIN) == 0) { ret = 3; break; }
        rlen = recvfrom(fd, rbuf, sizeof(rbuf), 0, NULL, NULL);
        if (rlen < 0) {
            if (errno == EINTR) { continue; }
            ret = 3; break;
        }
        {
            size_t len = (size_t)rlen;
            size_t ihl;
            unsigned int resp_sport;
            unsigned int resp_dport;
            uint32_t resp_saddr;
            if (len < 40) { continue; }
            if ((rbuf[0] >> 4) != 4) { continue; }
            ihl = (size_t)(rbuf[0] & 0x0F) * 4u;
            if (ihl < 20 || len < ihl + 20) { continue; }
            if (rbuf[9] != (unsigned char)IPPROTO_TCP) { continue; }
            resp_saddr = ((uint32_t)rbuf[12] << 24)
                | ((uint32_t)rbuf[13] << 16)
                | ((uint32_t)rbuf[14] << 8)
                | (uint32_t)rbuf[15];
            if (resp_saddr != dst_be) { continue; }
            resp_sport = ((unsigned int)rbuf[ihl] << 8) | (unsigned int)rbuf[ihl + 1];
            resp_dport = ((unsigned int)rbuf[ihl + 2] << 8) | (unsigned int)rbuf[ihl + 3];
            if (resp_sport != (unsigned int)dst_port) { continue; }
            if (resp_dport != (unsigned int)sport) { continue; }
            /* Matched reply: fill detailed result via pure parser. */
            {
                AlmapProbeResult parsed;
                if (almap_os_parse_tcp_packet(rbuf, (int)len, &parsed) == 1) {
                    if (result != NULL) {
                        *result = parsed;
                    }
                    /* Classify for return code. */
                    if (parsed.is_rst) { ret = 1; }
                    else if (parsed.is_synack) { ret = 0; }
                    else { ret = 1; /* other TCP reply counts as answered */ }
                    break;
                }
            }
        }
    }
    close(fd);
    return ret;
}

int almap_os_probe_udp(unsigned int src_be, unsigned int dst_be,
                       int dst_port, int timeout_ms,
                       AlmapProbeResult *result) {
    int fd_udp = -1;
    int fd_icmp = -1;
    int ret = 3;
    unsigned char packet[28];
    unsigned char pseudo[20];
    uint16_t ip_sum;
    uint16_t udp_sum;
    struct sockaddr_in dest;
    struct timespec start;
    struct timespec now;
    unsigned short sport;

    if (result != NULL) {
        memset(result, 0, sizeof(*result));
    }
    if (src_be == 0 || dst_be == 0 || dst_port < 1 || dst_port > 65535 || timeout_ms <= 0) {
        return 3;
    }
    fd_udp = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (fd_udp < 0) {
        if (errno == EPERM || errno == EACCES) { return 4; }
        return 3;
    }
    fd_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd_icmp < 0) {
        close(fd_udp);
        if (errno == EPERM || errno == EACCES) { return 4; }
        return 3;
    }
    sport = almap_alloc_sport(dst_port);
    memset(packet, 0, sizeof(packet));
    packet[0] = 0x45; packet[1] = 0;
    packet[2] = 0; packet[3] = 28;
    packet[4] = (unsigned char)((sport >> 8) & 0xFF);
    packet[5] = (unsigned char)(sport & 0xFF);
    packet[6] = 0x40; packet[7] = 0;
    packet[8] = 64;
    packet[9] = (unsigned char)IPPROTO_UDP;
    packet[12] = (unsigned char)((src_be >> 24) & 0xFF);
    packet[13] = (unsigned char)((src_be >> 16) & 0xFF);
    packet[14] = (unsigned char)((src_be >> 8) & 0xFF);
    packet[15] = (unsigned char)(src_be & 0xFF);
    packet[16] = (unsigned char)((dst_be >> 24) & 0xFF);
    packet[17] = (unsigned char)((dst_be >> 16) & 0xFF);
    packet[18] = (unsigned char)((dst_be >> 8) & 0xFF);
    packet[19] = (unsigned char)(dst_be & 0xFF);
    ip_sum = almap_checksum(packet, 20);
    packet[10] = (unsigned char)((ip_sum >> 8) & 0xFF);
    packet[11] = (unsigned char)(ip_sum & 0xFF);
    /* UDP header: sport, dport, len 8, checksum. */
    packet[20] = (unsigned char)((sport >> 8) & 0xFF);
    packet[21] = (unsigned char)(sport & 0xFF);
    packet[22] = (unsigned char)(((unsigned int)dst_port >> 8) & 0xFF);
    packet[23] = (unsigned char)((unsigned int)dst_port & 0xFF);
    packet[24] = 0; packet[25] = 8;
    packet[26] = 0; packet[27] = 0;
    memset(pseudo, 0, sizeof(pseudo));
    memcpy(pseudo, &packet[12], 8);
    pseudo[8] = 0; pseudo[9] = (unsigned char)IPPROTO_UDP;
    pseudo[10] = 0; pseudo[11] = 8;
    {
        unsigned char both[20];
        memcpy(both, pseudo, 12);
        memcpy(&both[12], &packet[20], 8);
        udp_sum = almap_checksum(both, sizeof(both));
    }
    packet[26] = (unsigned char)((udp_sum >> 8) & 0xFF);
    packet[27] = (unsigned char)(udp_sum & 0xFF);

    {
        int one = 1;
        if (setsockopt(fd_udp, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) != 0) {
            close(fd_udp); close(fd_icmp); return 3;
        }
    }
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons((uint16_t)dst_port);
    dest.sin_addr.s_addr = htonl(dst_be);
    if (sendto(fd_udp, packet, sizeof(packet), 0,
               (struct sockaddr *)&dest, sizeof(dest)) != (ssize_t)sizeof(packet)) {
        if (errno == EPERM || errno == EACCES) { ret = 4; } else { ret = 3; }
        close(fd_udp); close(fd_icmp); return ret;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        close(fd_udp); close(fd_icmp); return 3;
    }
    for (;;) {
        struct pollfd pfd;
        long elapsed_ms;
        long remain_ms;
        int pr;
        unsigned char rbuf[2048];
        ssize_t rlen;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) { ret = 3; break; }
        elapsed_ms = (long)(now.tv_sec - start.tv_sec) * 1000L
            + (long)(now.tv_nsec - start.tv_nsec) / 1000000L;
        remain_ms = (long)timeout_ms - elapsed_ms;
        if (remain_ms <= 0) { ret = 2; break; }
        pfd.fd = fd_icmp; pfd.events = POLLIN; pfd.revents = 0;
        pr = poll(&pfd, 1, (int)remain_ms);
        if (pr == 0) { ret = 2; break; }
        if (pr < 0) {
            if (errno == EINTR) { continue; }
            ret = 3; break;
        }
        if ((pfd.revents & POLLIN) == 0) { ret = 3; break; }
        rlen = recvfrom(fd_icmp, rbuf, sizeof(rbuf), 0, NULL, NULL);
        if (rlen < 0) {
            if (errno == EINTR) { continue; }
            ret = 3; break;
        }
        {
            size_t len = (size_t)rlen;
            size_t ihl = 0;
            size_t inner = 0;
            size_t inner_ihl = 0;
            unsigned int saddr;
            unsigned int isport = 0;
            unsigned int idport = 0;
            if (len < 20 + 8 + 20 + 8) { continue; }
            if ((rbuf[0] >> 4) != 4) { continue; }
            ihl = (size_t)(rbuf[0] & 0x0F) * 4u;
            if (ihl < 20 || len < ihl + 8) { continue; }
            if (rbuf[9] != (unsigned char)IPPROTO_ICMP) { continue; }
            saddr = ((unsigned int)rbuf[12] << 24)
                | ((unsigned int)rbuf[13] << 16)
                | ((unsigned int)rbuf[14] << 8)
                | (unsigned int)rbuf[15];
            if (saddr != dst_be) { continue; }
            /* ICMP header at ihl: type, code. */
            if (rbuf[ihl] != 3 || rbuf[ihl + 1] != 3) { continue; }
            inner = ihl + 8;
            if (len < inner + 28) { continue; }
            if ((rbuf[inner] >> 4) != 4) { continue; }
            inner_ihl = (size_t)(rbuf[inner] & 0x0F) * 4u;
            if (inner_ihl < 20 || len < inner + inner_ihl + 8) { continue; }
            isport = ((unsigned int)rbuf[inner + inner_ihl] << 8)
                | (unsigned int)rbuf[inner + inner_ihl + 1];
            idport = ((unsigned int)rbuf[inner + inner_ihl + 2] << 8)
                | (unsigned int)rbuf[inner + inner_ihl + 3];
            if (isport != (unsigned int)dst_port || idport != (unsigned int)sport) { continue; }
            /* Matched ICMP Port Unreachable. */
            if (result != NULL) {
                memset(result, 0, sizeof(*result));
                result->present = 1;
                result->ttl = (int)rbuf[8];
                result->icmp_type = (int)rbuf[ihl];
                result->icmp_code = (int)rbuf[ihl + 1];
                result->ip_id = ((int)rbuf[4] << 8) | (int)rbuf[5];
            }
            ret = 0; /* UNREACH mapped to 0 for probe_all ordering */
            /* Use ret=0 to signal captured; probe string uses UNREACH. */
            break;
        }
    }
    close(fd_udp); close(fd_icmp);
    return ret == 0 ? 0 : ret;
}

int almap_os_probe_all(unsigned int src_be, unsigned int dst_be,
                       int open_port, int closed_port, int timeout_ms,
                       char *probe_out, int probe_cap) {
    AlmapProbeResult local[8];
    int rc;
    int first_rc = 0;
    if (src_be == 0 || dst_be == 0 || timeout_ms <= 0 || probe_out == NULL || probe_cap < 2) {
        return -1;
    }
    memset(local, 0, sizeof(local));
    if (open_port >= 1 && open_port <= 65535) {
        rc = almap_os_probe_tcp(1, src_be, dst_be, open_port, timeout_ms, &local[0]);
        if (rc == 4) { return 4; }
        if (first_rc == 0) { first_rc = rc; }
        rc = almap_os_probe_tcp(2, src_be, dst_be, open_port, timeout_ms, &local[1]);
        if (rc == 4) { return 4; }
        rc = almap_os_probe_tcp(3, src_be, dst_be, open_port, timeout_ms, &local[2]);
        if (rc == 4) { return 4; }
        rc = almap_os_probe_tcp(4, src_be, dst_be, open_port, timeout_ms, &local[3]);
        if (rc == 4) { return 4; }
    }
    if (closed_port >= 1 && closed_port <= 65535) {
        rc = almap_os_probe_tcp(5, src_be, dst_be, closed_port, timeout_ms, &local[4]);
        if (rc == 4) { return 4; }
        rc = almap_os_probe_tcp(6, src_be, dst_be, closed_port, timeout_ms, &local[5]);
        if (rc == 4) { return 4; }
        rc = almap_os_probe_tcp(7, src_be, dst_be, closed_port, timeout_ms, &local[6]);
        if (rc == 4) { return 4; }
        rc = almap_os_probe_udp(src_be, dst_be, closed_port, timeout_ms, &local[7]);
        if (rc == 4) { return 4; }
    }
    almap_os_build_probe_string(local, probe_out, probe_cap);
    (void)first_rc;
    return 0;
}
