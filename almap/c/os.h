#ifndef ALMAP_OS_H
#define ALMAP_OS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * os.h - Step 31: minimal OS fingerprinting helpers + T1-T7 probes.
 *
 * This is deliberately not a full port of Nmap's fingerprint
 * database. It keeps the Step 19 SYN/ACK heuristics and adds the
 * Step 31 T1-T7 + U1 probe analysis (IP ID, ISN, TCP options).
 *
 * The coarse label mapping is unchanged:
 *
 *   0 = unknown
 *   1 = linux-like
 *   2 = windows-like
 *   3 = network-device
 *
 * The classification is advisory only. TTL is decremented by routers,
 * middleboxes rewrite TCP options, NAT/proxies can hide the real stack,
 * and every value here can be forged. See README.md for limitations.
 *
 * The raw SYN/ACK fields are passed in AlmapOsSample; c/raw.c fills it
 * only after matching a SYN+ACK (an RST or timeout provides no sample).
 * c/pool.c aggregates samples for one host and c/os.c classifies them.
 * The T1-T7 extension (AlmapProbeResult / AlmapOsFullFingerprint) is
 * filled by c/raw.c probe functions and formatted into a signature
 * string compared against the os-signatures.db probe field.
 */

#define ALMAP_OS_UNKNOWN 0
#define ALMAP_OS_LINUX 1
#define ALMAP_OS_WINDOWS 2
#define ALMAP_OS_NETWORK 3

/* TCP option presence bits. */
#define ALMAP_OS_OPT_MSS 0x01
#define ALMAP_OS_OPT_SACK 0x02
#define ALMAP_OS_OPT_TIMESTAMPS 0x04
#define ALMAP_OS_OPT_WINDOWSCALE 0x08

/* IP ID behaviour codes. */
#define ALMAP_OS_IPID_UNKNOWN 0
#define ALMAP_OS_IPID_ZERO 1
#define ALMAP_OS_IPID_INCREMENTAL 2
#define ALMAP_OS_IPID_OTHER 3
#define ALMAP_OS_IPID_RANDOM 4
#define ALMAP_OS_IPID_BROKEN 5

/* TCP probe identifiers (Nmap-style T1..T7; U1 is UDP). */
#define ALMAP_OS_PROBE_T1 1
#define ALMAP_OS_PROBE_T2 2
#define ALMAP_OS_PROBE_T3 3
#define ALMAP_OS_PROBE_T4 4
#define ALMAP_OS_PROBE_T5 5
#define ALMAP_OS_PROBE_T6 6
#define ALMAP_OS_PROBE_T7 7
#define ALMAP_OS_PROBE_U1 8

/* One probe response. Filled by c/raw.c whenever a reply is captured;
 * present=0 means timeout/no reply. Method names are stable strings
 * used to build the signature: SYNACK, RST, NONE, OTHER, UNREACH. */
typedef struct {
    int present;            /* 1 when a reply packet was captured. */
    int tcp_flags;          /* Reply TCP flags byte (host order). */
    int is_synack;          /* Reply had SYN+ACK. */
    int is_rst;             /* Reply had RST. */
    int ttl;                /* Outer IP TTL. */
    int window;             /* Reply TCP receive window. */
    int ip_id;              /* Outer IP identification. */
    unsigned int isn;       /* Reply TCP sequence (host order). */
    int options;            /* ALMAP_OS_OPT_* presence bits. */
    char options_str[64];   /* e.g. "MSS+SACK+TS+WS". */
    int icmp_type;          /* ICMP type (UDP U1 only). */
    int icmp_code;          /* ICMP code (UDP U1 only). */
} AlmapProbeResult;

/* Full T1-T7+U1 fingerprint for one host. probe_string is the
 * DB-matchable signature built by almap_os_build_probe_string(). */
typedef struct {
    AlmapProbeResult t1;
    AlmapProbeResult t2;
    AlmapProbeResult t3;
    AlmapProbeResult t4;
    AlmapProbeResult t5;
    AlmapProbeResult t6;
    AlmapProbeResult t7;
    AlmapProbeResult u1;
    int ip_id_behavior;     /* Aggregate ALMAP_OS_IPID_* across probes. */
    char probe_string[2048];
} AlmapOsFullFingerprint;

typedef struct {
    int ttl;        /* IPv4 TTL as received. */
    int window;     /* TCP receive window from the SYN+ACK, host order. */
    int options;    /* ALMAP_OS_OPT_* presence bits. */
    int ip_id;      /* IPv4 identification field, host order. */
} AlmapOsSample;

typedef struct {
    int samples;          /* Number of SYN+ACK samples observed. */
    int ttl;              /* First sample's TTL. */
    int window;           /* First sample's TCP window. */
    int options;          /* First sample's option bits. */
    int first_ip_id;      /* First observed IP ID. */
    int last_ip_id;       /* Most recently observed IP ID. */
    int expected_ip_id;   /* next_id expected for an incremental sequence. */
    int all_zero;         /* Nonzero while every observed IP ID is 0. */
    int incremental;      /* Nonzero while every IP ID follows the previous +1. */
    int ip_id_behavior;   /* ALMAP_OS_IPID_* after finalize. */
    int os_class;         /* ALMAP_OS_* after finalize. */
} AlmapOsFingerprint;

/* Zero a fingerprint (class unknown, no samples). */
void almap_os_init(AlmapOsFingerprint *fp);

/* Add one SYN+ACK sample to a host fingerprint. Safe under a caller's
 * mutex when several pool workers feed the same host. */
void almap_os_note(AlmapOsFingerprint *fp, const AlmapOsSample *sample);

/* Compute ip_id_behavior and os_class, returning os_class. */
int almap_os_finalize(AlmapOsFingerprint *fp);

/* Pure heuristic mapping. ttl/window/options are the raw SYN+ACK
 * values; ip_id_behavior is ALMAP_OS_IPID_*. Returns ALMAP_OS_*.
 * Returns unknown when no usable signal is present. */
int almap_os_classify(int ttl, int window, int options, int ip_id_behavior);

/* Stable text for a class (for diagnostics/tests). */
const char *almap_os_name(int os_class);

/* Step 31: classify an IP ID sequence. Returns ALMAP_OS_IPID_*.
 * Pure (no network) for unit tests. */
int almap_os_ipid_classify_seq(const int *ids, int count);

/* Step 31: short name for an IP ID behaviour code. */
const char *almap_os_ipid_name(int behavior);

/* Step 31: format option bits as e.g. "MSS+SACK+TS+WS" (empty when
 * no bits). Returns the string length. */
int almap_os_format_options(int bits, char *out, int cap);

/* Step 31: parse an IP+TCP packet (no socket) into result. Returns
 * 1 on success, 0 on malformed/wrong-protocol input. Pure. */
int almap_os_parse_tcp_packet(const unsigned char *pkt, int len,
                              AlmapProbeResult *out);

/* Step 31: build the DB-matchable probe signature string from 8
 * results (T1..T7,U1 in order). Returns the string length. */
int almap_os_build_probe_string(const AlmapProbeResult results[8],
                                char *out, int cap);

#ifdef __cplusplus
}
#endif

#endif /* ALMAP_OS_H */
