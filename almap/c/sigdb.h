#ifndef ALMAP_SIGDB_H
#define ALMAP_SIGDB_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * sigdb.h - Step 29: dynamic service signature database (full Nmap DB).
 *
 * The database lives entirely in C (Goose has no heap). Entries are
 * stored in a malloc/realloc dynamic array in insertion order, with a
 * separate hash table that indexes entries by port for O(1) candidate
 * retrieval. Lookup merges the port-specific bucket and the "any"
 * bucket in insertion order so "first match wins" is preserved.
 *
 * Each REGEX pattern is compiled once at add time (regcomp with
 * REG_EXTENDED|REG_NOSUB) and cached for reuse; EXACT patterns use
 * strstr(). This is POSIX ERE, not PCRE. The Nmap importer translates
 * common PCRE to ERE before writing signatures.db.
 *
 * All storage is global and single-threaded: the sequential service
 * path loads once and probes ports sequentially. Call almap_sigdb_free()
 * to release all memory (also called by sigdb_new() on each fresh load).
 */

/* Legacy one-shot POSIX ERE matcher used by modules/sigdb.goose
 * (regex_match helper) and tests/test_sigdb_regex.c. Compiles on every
 * call. Returns 1 on match, 0 otherwise or on invalid pattern. */
int almap_sigdb_match_regex(const char *pattern, const char *text);

/*
 * Dynamic hash-table database (Step 29).
 *
 * type: "EXACT" or "REGEX" (case-sensitive). port: -1 for any,
 * 1..65535 otherwise. pattern and name are NUL-terminated strings
 * (non-empty, no embedded NUL by construction). Returns 1 when the
 * entry was added, 0 on invalid type/port/empty string or malloc
 * failure. Invalid ERE patterns are stored with regex_valid=0 (they
 * never match) so one bad line cannot abort a load.
 */
int almap_sigdb_add(const char *type, int port, const char *pattern,
                     const char *name);

/*
 * First-match lookup in insertion order, restricted to the bucket for
 * `port` plus the `any` bucket. When `type` is NULL or empty both
 * EXACT and REGEX entries are considered; "EXACT" or "REGEX" restricts
 * the search to that kind. `text` is the banner bytes as a C string.
 * Returns the matched service name owned by the database (NULL when
 * nothing matches). The pointer stays valid until almap_sigdb_free().
 */
const char *almap_sigdb_lookup(const char *type, int port,
                               const char *text);

/* Goose-friendly wrapper: copies the matched name into `name_out`
 * (cap bytes, NUL-terminated) and returns the copied byte count, or 0
 * when nothing matches. Truncates to cap-1 when the name is longer. */
int almap_sigdb_lookup_into(const char *type, int port, const char *text,
                            char *name_out, int name_cap);

/* Number of stored entries (0 when empty). */
int almap_sigdb_count(void);

/* Hash-table bucket count for this build (for collision/bench tests). */
int almap_sigdb_hash_table_size(void);

/* Port hash used by the table (exposed for collision unit tests). */
unsigned long almap_sigdb_port_hash(int port);

/* Load a signatures.db file (EXACT|port|pattern|name or
 * REGEX|port|posix_ere|name, blank lines and '#' comments skipped).
 * Returns the number of entries added, or -1 when the file cannot be
 * opened. The caller must have freed any previous database. */
int almap_sigdb_load_file(const char *path);

/* Release all heap memory and reset to empty. Returns 0. */
int almap_sigdb_free(void);

#ifdef __cplusplus
}
#endif

#endif /* ALMAP_SIGDB_H */
