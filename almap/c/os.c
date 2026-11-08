#include <stdio.h>
#include <string.h>

#include "os.h"

/*
 * os.c - Step 31: minimal OS fingerprinting heuristics + T1-T7 helpers.
 *
 * The coarse classifier is the original Step 19 vote. Step 31 adds
 * IP ID sequence classification (zero/incremental/random/broken/
 * other), TCP options formatting, a pure IP+TCP packet parser, and
 * probe-string construction for DB matching. All Step 31 helpers
 * are pure (no network) so they are unit-testable with synthetic
 * packets.
 */

static int ttl_bucket(int ttl) {
    if (ttl <= 0) {
        return 0;
    }
    if (ttl <= 64) {
        return 64;
    }
    if (ttl <= 128) {
        return 128;
    }
    return 255;
}

int almap_os_classify(int ttl, int window, int options, int ip_id_behavior) {
    int bucket;
    int linux_votes = 0;
    int windows_votes = 0;
    int network_votes = 0;

    bucket = ttl_bucket(ttl);
    if (bucket == 0 && window <= 0 && options == 0
        && ip_id_behavior == ALMAP_OS_IPID_UNKNOWN) {
        return ALMAP_OS_UNKNOWN;
    }

    /* TTL: 64 is the common Unix/Linux initial value, 128 Windows,
     * 255 many routers/network devices. Three votes because a router
     * may decrement a value but rarely crosses a bucket boundary. */
    if (bucket == 64) {
        linux_votes += 3;
    } else if (bucket == 128) {
        windows_votes += 3;
    } else if (bucket == 255) {
        network_votes += 3;
    }

    /* TCP options: timestamps are the strongest Linux-ish signal.
     * MSS + SACK without timestamps is common on Windows. MSS-only or
     * no options at all is common on simple network devices. */
    if ((options & ALMAP_OS_OPT_TIMESTAMPS) != 0) {
        linux_votes += 2;
    }
    if ((options & ALMAP_OS_OPT_MSS) != 0
        && (options & ALMAP_OS_OPT_SACK) != 0
        && (options & ALMAP_OS_OPT_TIMESTAMPS) == 0) {
        windows_votes += 1;
    }
    if (options == 0 || options == ALMAP_OS_OPT_MSS) {
        network_votes += 1;
    }

    /* Receive window. The lists overlap on purpose (65535 and 64240
     * appear on several stacks); TTL/options decide the ties. */
    if (window == 5840 || window == 14600 || window == 29200
        || window == 64240 || window == 65160) {
        linux_votes += 1;
    } else if (window == 8192 || window == 16384 || window == 65535) {
        windows_votes += 1;
    } else if (window > 0 && window <= 4096) {
        network_votes += 1;
    }

    /* IP ID behaviour. Linux often sends zero IDs on SYN+ACK, Windows
     * often increments, random/broken/other are treated like other. */
    if (ip_id_behavior == ALMAP_OS_IPID_ZERO) {
        linux_votes += 1;
    } else if (ip_id_behavior == ALMAP_OS_IPID_INCREMENTAL) {
        windows_votes += 1;
    } else if (ip_id_behavior == ALMAP_OS_IPID_OTHER
               || ip_id_behavior == ALMAP_OS_IPID_RANDOM
               || ip_id_behavior == ALMAP_OS_IPID_BROKEN) {
        network_votes += 1;
    }

    if (linux_votes == 0 && windows_votes == 0 && network_votes == 0) {
        return ALMAP_OS_UNKNOWN;
    }
    if (linux_votes >= windows_votes && linux_votes >= network_votes) {
        return ALMAP_OS_LINUX;
    }
    if (windows_votes >= linux_votes && windows_votes >= network_votes) {
        return ALMAP_OS_WINDOWS;
    }
    return ALMAP_OS_NETWORK;
}

void almap_os_init(AlmapOsFingerprint *fp) {
    if (fp == NULL) {
        return;
    }
    memset(fp, 0, sizeof(*fp));
    fp->ip_id_behavior = ALMAP_OS_IPID_UNKNOWN;
    fp->os_class = ALMAP_OS_UNKNOWN;
}

void almap_os_note(AlmapOsFingerprint *fp, const AlmapOsSample *sample) {
    if (fp == NULL || sample == NULL) {
        return;
    }
    if (fp->samples == 0) {
        fp->ttl = sample->ttl;
        fp->window = sample->window;
        fp->options = sample->options;
        fp->first_ip_id = sample->ip_id;
        fp->all_zero = (sample->ip_id == 0);
        fp->incremental = 1;
    } else {
        if (sample->ip_id != fp->expected_ip_id) {
            fp->incremental = 0;
        }
        if (sample->ip_id != 0) {
            fp->all_zero = 0;
        }
    }
    fp->last_ip_id = sample->ip_id;
    fp->expected_ip_id = (sample->ip_id + 1) & 0xFFFF;
    fp->samples++;
}

int almap_os_finalize(AlmapOsFingerprint *fp) {
    if (fp == NULL) {
        return ALMAP_OS_UNKNOWN;
    }
    if (fp->samples <= 0) {
        fp->ip_id_behavior = ALMAP_OS_IPID_UNKNOWN;
        fp->os_class = ALMAP_OS_UNKNOWN;
        return fp->os_class;
    }
    if (fp->all_zero != 0) {
        fp->ip_id_behavior = ALMAP_OS_IPID_ZERO;
    } else if (fp->samples >= 2 && fp->incremental != 0) {
        fp->ip_id_behavior = ALMAP_OS_IPID_INCREMENTAL;
    } else {
        fp->ip_id_behavior = ALMAP_OS_IPID_OTHER;
    }
    fp->os_class = almap_os_classify(fp->ttl, fp->window, fp->options,
                                     fp->ip_id_behavior);
    return fp->os_class;
}

const char *almap_os_name(int os_class) {
    switch (os_class) {
    case ALMAP_OS_LINUX:
        return "linux-like";
    case ALMAP_OS_WINDOWS:
        return "windows-like";
    case ALMAP_OS_NETWORK:
        return "network-device";
    default:
        return "unknown";
    }
}

/* ---- Step 31 packet analysis helpers (pure, no network) ---- */

int almap_os_ipid_classify_seq(const int *ids, int count) {
    int i;
    int all_zero = 1;
    int incremental = 1;
    int has_dup = 0;
    int has_decrease = 0;

    if (ids == NULL || count <= 0) {
        return ALMAP_OS_IPID_UNKNOWN;
    }
    for (i = 0; i < count; i++) {
        if (ids[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    if (all_zero) {
        return ALMAP_OS_IPID_ZERO;
    }
    if (count == 1) {
        return ALMAP_OS_IPID_OTHER;
    }
    for (i = 1; i < count; i++) {
        int prev = ids[i - 1] & 0xFFFF;
        int cur = ids[i] & 0xFFFF;
        int expected = (prev + 1) & 0xFFFF;
        if (cur == prev) {
            has_dup = 1;
        }
        if (cur != expected) {
            incremental = 0;
        }
        /* "Decrease" ignoring wrap: cur is prev-1 .. prev-5 mod 65536
         * (a small backwards step) counts as broken rather than random. */
        if (cur == ((prev + 65535) & 0xFFFF) || cur == ((prev + 65534) & 0xFFFF)) {
            has_decrease = 1;
        }
    }
    if (incremental) {
        return ALMAP_OS_IPID_INCREMENTAL;
    }
    if (has_dup || has_decrease) {
        return ALMAP_OS_IPID_BROKEN;
    }
    /* Non-zero, non-sequential, no obvious breakage: random-ish. */
    return ALMAP_OS_IPID_RANDOM;
}

const char *almap_os_ipid_name(int behavior) {
    switch (behavior) {
    case ALMAP_OS_IPID_ZERO:
        return "ZERO";
    case ALMAP_OS_IPID_INCREMENTAL:
        return "INC";
    case ALMAP_OS_IPID_RANDOM:
        return "RAND";
    case ALMAP_OS_IPID_BROKEN:
        return "BRKN";
    case ALMAP_OS_IPID_OTHER:
        return "OTH";
    default:
        return "UNKNOWN";
    }
}

int almap_os_format_options(int bits, char *out, int cap) {
    const char *parts[4];
    int nparts = 0;
    int pos = 0;
    int i;

    if (out == NULL || cap < 1) {
        return 0;
    }
    out[0] = '\0';
    if ((bits & ALMAP_OS_OPT_MSS) != 0) {
        parts[nparts++] = "MSS";
    }
    if ((bits & ALMAP_OS_OPT_SACK) != 0) {
        parts[nparts++] = "SACK";
    }
    if ((bits & ALMAP_OS_OPT_TIMESTAMPS) != 0) {
        parts[nparts++] = "TS";
    }
    if ((bits & ALMAP_OS_OPT_WINDOWSCALE) != 0) {
        parts[nparts++] = "WS";
    }
    for (i = 0; i < nparts; i++) {
        const char *sep = (i == 0) ? "" : "+";
        for (const char *p = sep; *p; p++) {
            if (pos + 1 < cap) {
                out[pos++] = *p;
            }
        }
        for (const char *p = parts[i]; *p; p++) {
            if (pos + 1 < cap) {
                out[pos++] = *p;
            }
        }
    }
    out[pos] = '\0';
    return pos;
}

/* Internal forward used by the packet parser below. */
static int parse_options_bits(const unsigned char *opts, int len,
                              char *str_out, int str_cap) {
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
        } else if (kind == 3 && olen == 3) {
            bits |= ALMAP_OS_OPT_WINDOWSCALE;
        }
        i += olen;
    }
    if (str_out != NULL && str_cap > 0) {
        almap_os_format_options(bits, str_out, str_cap);
    }
    return bits;
}

int almap_os_parse_tcp_packet(const unsigned char *pkt, int len,
                              AlmapProbeResult *out) {
    size_t ihl;
    size_t doff;

    if (pkt == NULL || out == NULL || len < 40) {
        return 0;
    }
    if ((pkt[0] >> 4) != 4) {
        return 0;
    }
    ihl = (size_t)(pkt[0] & 0x0F) * 4u;
    if (ihl < 20 || (size_t)len < ihl + 20) {
        return 0;
    }
    if (pkt[9] != 6) { /* IPPROTO_TCP */
        return 0;
    }
    memset(out, 0, sizeof(*out));
    out->present = 1;
    out->ttl = (int)pkt[8];
    out->ip_id = ((int)pkt[4] << 8) | (int)pkt[5];
    out->tcp_flags = (int)pkt[ihl + 13];
    out->is_rst = ((out->tcp_flags & 0x04) != 0) ? 1 : 0;
    out->is_synack = ((out->tcp_flags & 0x02) != 0
                      && (out->tcp_flags & 0x10) != 0) ? 1 : 0;
    out->window = ((int)pkt[ihl + 14] << 8) | (int)pkt[ihl + 15];
    out->isn = ((unsigned int)pkt[ihl + 4] << 24)
        | ((unsigned int)pkt[ihl + 5] << 16)
        | ((unsigned int)pkt[ihl + 6] << 8)
        | (unsigned int)pkt[ihl + 7];
    doff = (size_t)(pkt[ihl + 12] >> 4) * 4u;
    out->options = 0;
    out->options_str[0] = '\0';
    if (doff >= 20 && ihl + doff <= (size_t)len) {
        out->options = parse_options_bits(&pkt[ihl + 20], (int)(doff - 20),
                                          out->options_str, sizeof(out->options_str));
    }
    return 1;
}

static const char *probe_code(const AlmapProbeResult *r) {
    if (r == NULL || r->present == 0) {
        return "NONE";
    }
    if (r->is_synack) {
        return "SYNACK";
    }
    if (r->is_rst) {
        return "RST";
    }
    if (r->icmp_type == 3 && r->icmp_code == 3) {
        return "UNREACH";
    }
    return "OTHER";
}

int almap_os_build_probe_string(const AlmapProbeResult results[8],
                                char *out, int cap) {
    static const char *names[8] = {"T1", "T2", "T3", "T4", "T5", "T6", "T7", "U1"};
    int pos = 0;
    int i;
    int ip_ids[8];
    int ip_count = 0;
    int behavior;

    if (results == NULL || out == NULL || cap < 1) {
        return 0;
    }
    out[0] = '\0';
    for (i = 0; i < 8; i++) {
        const char *code = probe_code(&results[i]);
        int n;
        if (i > 0 && pos + 1 < cap) {
            out[pos++] = ',';
        }
        n = snprintf(out + pos, (size_t)(cap - pos), "%s=%s",
                     names[i], code);
        if (n < 0) {
            break;
        }
        if (pos + n < cap) {
            pos += n;
        } else {
            pos = cap - 1;
            break;
        }
    }
    /* IP ID behaviour across TCP probes with a reply. */
    for (i = 0; i < 7; i++) {
        if (results[i].present) {
            ip_ids[ip_count++] = results[i].ip_id;
        }
    }
    behavior = almap_os_ipid_classify_seq(ip_ids, ip_count);
    {
        const char *bname = almap_os_ipid_name(behavior);
        int n;
        if (pos + 1 < cap) {
            out[pos++] = ',';
        }
        n = snprintf(out + pos, (size_t)(cap - pos), "ID=%s", bname);
        if (n > 0 && pos + n < cap) {
            pos += n;
        }
    }
    /* TCP options from T1 (the SYN+ACK sample). */
    if (results[0].present && results[0].options != 0) {
        char opts_s[64];
        int n;
        almap_os_format_options(results[0].options, opts_s, sizeof(opts_s));
        if (pos + 1 < cap) {
            out[pos++] = ',';
        }
        n = snprintf(out + pos, (size_t)(cap - pos), "OPTS=%s", opts_s);
        if (n > 0 && pos + n < cap) {
            pos += n;
        }
    }
    /* ISN category from T1 (exact ISN varies per run, so only the
     * zero/non-zero class is matchable). */
    if (results[0].present) {
        int n;
        if (pos + 1 < cap) {
            out[pos++] = ',';
        }
        n = snprintf(out + pos, (size_t)(cap - pos), "ISN=%s",
                     results[0].isn == 0 ? "ZERO" : "NONZERO");
        if (n > 0 && pos + n < cap) {
            pos += n;
        }
    }
    if (pos >= cap) {
        pos = cap - 1;
    }
    out[pos] = '\0';
    return pos;
}
