#ifndef ALMAP_OSDB_H
#define ALMAP_OSDB_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * osdb.h - Step 31: dynamic OS signature database (full Nmap DB).
 *
 * Storage lives in C (Goose has no heap). Entries are a malloc/realloc
 * dynamic array in insertion order with first-match-wins lookup.
 * The lookup is a fast linear scan in C (6000+ entries is still
 * sub-millisecond) with early window/options pruning.
 *
 * Each row is: OS_NAME|MIN_TTL|MAX_TTL|WINDOW_SIZE|TCP_OPTIONS_FLAG|PROBE
 * The 6th PROBE field (optional) is the T1-T7+U1 signature string
 * (e.g. "T1=SYNACK,T2=RST,...,ID=ZERO") matched exactly or as POSIX
 * ERE. Rows without it (5 fields) are wildcards for probe matching.
 */

/* Add one row. name is NUL-terminated (1..64 printable, no | " \ <>&).
 * min/max TTL are 0..255 (min <= max), window 0..65535 (0=wildcard),
 * opts is a mask of ALMAP_OS_OPT_* bits (0x01 MSS, 0x02 SACK,
 * 0x04 TIMESTAMPS, 0x08 WINDOWSCALE). Returns 1 on add, 0 on invalid
 * input/malloc failure. */
int almap_osdb_add(const char *name, int min_ttl, int max_ttl, int window,
                   int opts);

/* Step 31: same as add but with a probe signature pattern (may be
 * empty/NULL for wildcard). */
int almap_osdb_add2(const char *name, int min_ttl, int max_ttl, int window,
                    int opts, const char *probe);

/* First-match lookup: ttl must be >0 to match, window 0 matches any,
 * opts is a required subset (extra observed options allowed).
 * Returns the matched name owned by the database, NULL on no match. */
const char *almap_osdb_lookup(int ttl, int window, int opts);

/* Step 31: same filter plus probe-string match. An empty DB probe
 * or empty caller probe is a wildcard; otherwise the DB pattern is
 * tried as exact equality, then as POSIX ERE via sigdb's matcher. */
const char *almap_osdb_lookup_full(int ttl, int window, int opts,
                                   const char *probe_str);

/* Wrapper copying the matched name into name_out (cap bytes,
 * NUL-terminated). Returns the copied byte count, 0 on no match. */
int almap_osdb_lookup_into(int ttl, int window, int opts, char *name_out,
                           int name_cap);

/* Step 31: same as lookup_into but with probe-string filtering. */
int almap_osdb_lookup_into_full(int ttl, int window, int opts,
                                const char *probe_str, char *name_out,
                                int name_cap);

/* Number of stored entries. */
int almap_osdb_count(void);

/* Load os-signatures.db. Returns entries added, -1 when the file
 * cannot be opened. */
int almap_osdb_load_file(const char *path);

/* Release all heap memory and reset to empty. Returns 0. */
int almap_osdb_free(void);

#ifdef __cplusplus
}
#endif

#endif /* ALMAP_OSDB_H */
