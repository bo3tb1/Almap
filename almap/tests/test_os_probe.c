/*
 * test_os_probe.c - Step 31 unit tests for T1-T7 packet parsing and
 * probe-string construction (no raw sockets needed).
 *
 * Build: gcc -std=c99 -Wall -Wextra -pthread -Ic tests/test_os_probe.c c/os.c -o /tmp/test_os_probe && /tmp/test_os_probe
 */
#include "os.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint16_t checksum(const unsigned char *data, size_t len) {
    uint32_t sum = 0;
    size_t i;
    for (i = 0; i + 1 < len; i += 2) sum += (uint32_t)((unsigned int)data[i] << 8 | (unsigned int)data[i + 1]);
    if (i < len) sum += (uint32_t)((unsigned int)data[i] << 8);
    while ((sum >> 16) != 0) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

static void build_synack(unsigned char *pkt, const char *opts, int opts_len) {
    memset(pkt, 0, 60);
    pkt[0] = 0x45; pkt[3] = 40 + opts_len; pkt[4] = 0x12; pkt[5] = 0x34; pkt[8] = 64; pkt[9] = 6;
    pkt[12] = 10; pkt[13] = 0; pkt[14] = 0; pkt[15] = 1;
    pkt[16] = 192; pkt[17] = 168; pkt[18] = 1; pkt[19] = 1;
    uint16_t s = checksum(pkt, 20); pkt[10] = (s>>8)&0xFF; pkt[11] = s&0xFF;
    pkt[20] = 0x04; pkt[21] = 0x00; pkt[22] = 0x03; pkt[23] = 0xE8;
    pkt[24] = 0x12; pkt[25] = 0x34; pkt[26] = 0x56; pkt[27] = 0x78;
    pkt[32] = (unsigned char)(((20 + opts_len)/4) << 4);
    pkt[33] = 0x12; /* SYN+ACK */
    pkt[34] = 0x17; pkt[35] = 0x00; /* 5888 */
    size_t tcp_len = 20 + (size_t)opts_len;
    unsigned char pseudo[12 + 60];
    memset(pseudo, 0, sizeof(pseudo));
    memcpy(pseudo, &pkt[12], 8);
    pseudo[8] = 0; pseudo[9] = 6; pseudo[10] = (tcp_len>>8)&0xFF; pseudo[11] = tcp_len&0xFF;
    memcpy(&pseudo[12], &pkt[20], 20);
    for (int i = 0; i < opts_len; i++) pkt[40+i] = (unsigned char)opts[i];
    /* checksum over pseudo+tcp (tcp includes opts) */
    {
        unsigned char tcp[60];
        memcpy(tcp, &pkt[20], tcp_len);
        unsigned char both[12+60];
        memcpy(both, pseudo, 12);
        memcpy(&both[12], tcp, tcp_len);
        uint16_t tcs = checksum(both, 12+tcp_len);
        pkt[36] = (tcs>>8)&0xFF; pkt[37] = tcs&0xFF;
    }
}

int main(void) {
    unsigned char pkt[80];
    AlmapProbeResult r;
    /* MSS+SACK+TS options: 02 04 05 B4 04 02 08 0A 00 00 00 00 00 00 00 00 00 00 (MSS 1460, SACK, TS) -> opts len 18 */
    const char opts[] = "\x02\x04\x05\xB4\x04\x02\x08\x0A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    build_synack(pkt, opts, 18);
    if (almap_os_parse_tcp_packet(pkt, 40+18, &r) != 1) { fprintf(stderr, "parse synack failed\n"); return 1; }
    if (!r.is_synack || r.ttl != 64 || r.window != 5888 || r.ip_id != 0x1234) { fprintf(stderr, "synack fields wrong: ttl=%d win=%d id=%d flags=%02x\n", r.ttl, r.window, r.ip_id, r.tcp_flags); return 1; }
    if (r.isn != 0x12345678u) { fprintf(stderr, "isn wrong %u\n", r.isn); return 1; }
    if ((r.options & 7) != 7) { fprintf(stderr, "opts wrong %d\n", r.options); return 1; }
    if (strcmp(r.options_str, "MSS+SACK+TS") != 0) { fprintf(stderr, "opts_str %s\n", r.options_str); return 1; }
    printf("parse synack ok: TTL=%d WIN=%d OPTS=%s ISN=0x%x ID=0x%x\n", r.ttl, r.window, r.options_str, r.isn, r.ip_id);

    /* IPID classification */
    int inc[] = {10, 11, 12};
    int zero[] = {0, 0, 0};
    int rnd[] = {100, 500, 900};
    int brkn[] = {5, 5, 6};
    if (almap_os_ipid_classify_seq(inc, 3) != 2) { fprintf(stderr, "inc classify\n"); return 1; }
    if (almap_os_ipid_classify_seq(zero, 3) != 1) { fprintf(stderr, "zero classify\n"); return 1; }
    if (almap_os_ipid_classify_seq(rnd, 3) != 4) { fprintf(stderr, "rand classify\n"); return 1; }
    if (almap_os_ipid_classify_seq(brkn, 3) != 5) { fprintf(stderr, "brkn classify\n"); return 1; }
    printf("ipid classify ok\n");

    /* Probe string */
    AlmapProbeResult results[8];
    memset(results, 0, sizeof(results));
    results[0].present = 1; results[0].is_synack = 1; results[0].ttl = 64; results[0].window = 5888; results[0].ip_id = 0; results[0].options = 7; results[0].isn = 12345;
    results[1].present = 1; results[1].is_rst = 1;
    results[2].present = 1; results[2].is_rst = 1;
    results[3].present = 1; results[3].is_rst = 1;
    results[4].present = 1; results[4].is_rst = 1;
    results[5].present = 0;
    results[6].present = 0;
    results[7].present = 1; results[7].icmp_type = 3; results[7].icmp_code = 3;
    char sig[2048];
    almap_os_build_probe_string(results, sig, sizeof(sig));
    printf("probe_string: %s\n", sig);
    if (strstr(sig, "T1=SYNACK") == NULL || strstr(sig, "U1=UNREACH") == NULL || strstr(sig, "ID=ZERO") == NULL) { fprintf(stderr, "probe string mismatch\n"); return 1; }
    printf("ok: os probe tests passed\n");
    return 0;
}
