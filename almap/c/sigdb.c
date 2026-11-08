#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "sigdb.h"

#include <regex.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * sigdb.c - Step 29: dynamic service signature DB with port hash table.
 *
 * Storage: a malloc/realloc array `g_entries` in insertion order
 * (O(N) array growth), plus `g_buckets`, a chaining hash table that
 * indexes entries by port. Each bucket holds the head index (or -1) of
 * a singly linked list (via next_port) in insertion order.
 * Lookup merges the port bucket and the "any" (-1) bucket by order,
 * so the first matching entry wins exactly as a linear scan would,
 * but candidates are O(bucket length) instead of O(total).
 *
 * REGEX patterns are compiled once per add (regcomp) and cached in
 * a heap regex_t; EXACT uses strstr(). The legacy
 * almap_sigdb_match_regex() below still compiles on every call for
 * one-shot checks and the C regex unit tests.
 */

#define ALMAP_SIGDB_KIND_EXACT 0
#define ALMAP_SIGDB_KIND_REGEX 1
#define ALMAP_SIGDB_TABLE_SIZE 16384
#define ALMAP_SIGDB_INIT_CAP 1024
#define ALMAP_SIGDB_MAX_PATTERN 8192
#define ALMAP_SIGDB_MAX_NAME 512

typedef struct {
    int kind;
    int port;
    char *pattern;
    char *name;
    regex_t *compiled;
    int regex_valid;
    int next_port;
    int order;
} AlmapSigEntry;

static AlmapSigEntry *g_entries = NULL;
static size_t g_count = 0;
static size_t g_cap = 0;
static int32_t *g_buckets = NULL;
static size_t g_order = 0;

int almap_sigdb_match_regex(const char *pattern, const char *text) {
    regex_t compiled;
    int rc;

    if (pattern == NULL || text == NULL || pattern[0] == '\0') {
        return 0;
    }

    rc = regcomp(&compiled, pattern, REG_EXTENDED | REG_NOSUB);
    if (rc != 0) {
        return 0;
    }

    rc = regexec(&compiled, text, 0, NULL, 0);
    regfree(&compiled);
    return rc == 0 ? 1 : 0;
}

/* Integer hash for port keys (multiplicative finalizer). -1 ("any")
 * maps through the same mixer so collisions are spread evenly. */
unsigned long almap_sigdb_port_hash(int port) {
    uint32_t x = (uint32_t)(port + 1) + 0x9e3779b9u;
    x ^= x >> 16;
    x *= 0x85ebca6bu;
    x ^= x >> 13;
    x *= 0xc2b2ae35u;
    x ^= x >> 16;
    return (unsigned long)x;
}

int almap_sigdb_hash_table_size(void) {
    return ALMAP_SIGDB_TABLE_SIZE;
}

static int ensure_buckets(void) {
    size_t i;

    if (g_buckets != NULL) {
        return 1;
    }
    g_buckets = (int32_t *)malloc(sizeof(int32_t) * ALMAP_SIGDB_TABLE_SIZE);
    if (g_buckets == NULL) {
        return 0;
    }
    for (i = 0; i < ALMAP_SIGDB_TABLE_SIZE; i++) {
        g_buckets[i] = -1;
    }
    return 1;
}

static int ensure_capacity(void) {
    AlmapSigEntry *grown;
    size_t want;

    if (g_count < g_cap) {
        return 1;
    }
    want = g_cap == 0 ? ALMAP_SIGDB_INIT_CAP : g_cap * 2;
    grown = (AlmapSigEntry *)realloc(g_entries, want * sizeof(AlmapSigEntry));
    if (grown == NULL) {
        return 0;
    }
    g_entries = grown;
    g_cap = want;
    return 1;
}

int almap_sigdb_free(void) {
    size_t i;

    if (g_entries != NULL) {
        for (i = 0; i < g_count; i++) {
            free(g_entries[i].pattern);
            free(g_entries[i].name);
            if (g_entries[i].regex_valid && g_entries[i].compiled != NULL) {
                regfree(g_entries[i].compiled);
                free(g_entries[i].compiled);
            }
        }
        free(g_entries);
    }
    free(g_buckets);
    g_entries = NULL;
    g_buckets = NULL;
    g_count = 0;
    g_cap = 0;
    g_order = 0;
    return 0;
}

int almap_sigdb_count(void) {
    return (int)g_count;
}

int almap_sigdb_add(const char *type, int port, const char *pattern,
                     const char *name) {
    int kind;
    size_t plen;
    size_t nlen;
    char *pat_copy;
    char *name_copy;
    AlmapSigEntry *e;
    size_t idx;
    size_t bucket;
    int32_t head;
    int32_t cur;

    if (type == NULL || pattern == NULL || name == NULL) {
        return 0;
    }
    if (strcmp(type, "EXACT") == 0) {
        kind = ALMAP_SIGDB_KIND_EXACT;
    } else if (strcmp(type, "REGEX") == 0) {
        kind = ALMAP_SIGDB_KIND_REGEX;
    } else {
        return 0;
    }
    if (port != -1 && (port < 1 || port > 65535)) {
        return 0;
    }
    plen = strlen(pattern);
    nlen = strlen(name);
    if (plen == 0 || plen > ALMAP_SIGDB_MAX_PATTERN) {
        return 0;
    }
    if (nlen == 0 || nlen > ALMAP_SIGDB_MAX_NAME) {
        return 0;
    }

    pat_copy = (char *)malloc(plen + 1);
    name_copy = (char *)malloc(nlen + 1);
    if (pat_copy == NULL || name_copy == NULL) {
        free(pat_copy);
        free(name_copy);
        return 0;
    }
    memcpy(pat_copy, pattern, plen + 1);
    memcpy(name_copy, name, nlen + 1);

    if (!ensure_buckets() || !ensure_capacity()) {
        free(pat_copy);
        free(name_copy);
        return 0;
    }

    idx = g_count;
    e = &g_entries[idx];
    e->kind = kind;
    e->port = port;
    e->pattern = pat_copy;
    e->name = name_copy;
    e->compiled = NULL;
    e->regex_valid = 0;
    e->next_port = -1;
    e->order = (int)g_order;
    if (kind == ALMAP_SIGDB_KIND_REGEX) {
        e->compiled = (regex_t *)malloc(sizeof(regex_t));
        if (e->compiled != NULL) {
            if (regcomp(e->compiled, pattern, REG_EXTENDED | REG_NOSUB) == 0) {
                e->regex_valid = 1;
            } else {
                free(e->compiled);
                e->compiled = NULL;
                e->regex_valid = 0;
            }
        }
    }

    /* Append to the port bucket chain in insertion order. */
    bucket = (size_t)(almap_sigdb_port_hash(port) % ALMAP_SIGDB_TABLE_SIZE);
    head = g_buckets[bucket];
    if (head < 0) {
        g_buckets[bucket] = (int32_t)idx;
    } else {
        cur = head;
        while (g_entries[cur].next_port >= 0) {
            cur = g_entries[cur].next_port;
        }
        g_entries[cur].next_port = (int32_t)idx;
    }

    g_count++;
    g_order++;
    return 1;
}

const char *almap_sigdb_lookup(const char *type, int port,
                               const char *text) {
    int want_kind = -1;
    int32_t head_a;
    int32_t head_b;
    int32_t a;
    int32_t b;
    size_t bucket_a;
    size_t bucket_b;

    if (text == NULL || g_count == 0 || g_buckets == NULL) {
        return NULL;
    }
    if (port != -1 && (port < 1 || port > 65535)) {
        return NULL;
    }
    if (type != NULL && type[0] != '\0') {
        if (strcmp(type, "EXACT") == 0) {
            want_kind = ALMAP_SIGDB_KIND_EXACT;
        } else if (strcmp(type, "REGEX") == 0) {
            want_kind = ALMAP_SIGDB_KIND_REGEX;
        } else {
            return NULL;
        }
    }

    bucket_a = (size_t)(almap_sigdb_port_hash(port) % ALMAP_SIGDB_TABLE_SIZE);
    bucket_b = (size_t)(almap_sigdb_port_hash(-1) % ALMAP_SIGDB_TABLE_SIZE);
    head_a = g_buckets[bucket_a];
    head_b = g_buckets[bucket_b];
    /* -1 lookups search only the "any" bucket. */
    if (port == -1) {
        head_a = head_b;
        head_b = -1;
    }
    a = head_a;
    b = head_b;

    /* Merge the two insertion-ordered chains by order. */
    while (a >= 0 || b >= 0) {
        int32_t pick;
        AlmapSigEntry *e;

        if (b < 0 || (a >= 0 && g_entries[a].order <= g_entries[b].order)) {
            pick = a;
            a = g_entries[a].next_port;
        } else {
            pick = b;
            b = g_entries[b].next_port;
        }
        e = &g_entries[pick];
        if (want_kind >= 0 && e->kind != want_kind) {
            continue;
        }
        if (e->kind == ALMAP_SIGDB_KIND_EXACT) {
            if (strstr(text, e->pattern) != NULL) {
                return e->name;
            }
        } else {
            if (e->regex_valid && e->compiled != NULL) {
                if (regexec(e->compiled, text, 0, NULL, 0) == 0) {
                    return e->name;
                }
            }
        }
    }
    return NULL;
}

int almap_sigdb_lookup_into(const char *type, int port, const char *text,
                            char *name_out, int name_cap) {
    const char *found;
    size_t len;
    size_t take;

    if (name_out == NULL || name_cap < 1) {
        return 0;
    }
    name_out[0] = '\0';
    found = almap_sigdb_lookup(type, port, text);
    if (found == NULL) {
        return 0;
    }
    len = strlen(found);
    take = len;
    if (take > (size_t)(name_cap - 1)) {
        take = (size_t)(name_cap - 1);
    }
    memcpy(name_out, found, take);
    name_out[take] = '\0';
    return (int)take;
}

/* Trim spaces/tabs/CR/LF from both ends in place. Returns a pointer into
 * the buffer (caller owns the buffer). */
static char *trim_inplace(char *s) {
    char *end;

    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') {
        s++;
    }
    if (*s == '\0') {
        return s;
    }
    end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end = '\0';
        end--;
    }
    return s;
}

static int parse_port_text(const char *s, int *out_port) {
    char *t = trim_inplace((char *)s);
    char *end = NULL;
    long v;

    if (strcmp(t, "any") == 0) {
        *out_port = -1;
        return 1;
    }
    if (t[0] == '\0' || t[0] == '-' || t[0] == '+') {
        return 0;
    }
    v = strtol(t, &end, 10);
    if (end == t || *end != '\0' || v < 1 || v > 65535) {
        return 0;
    }
    *out_port = (int)v;
    return 1;
}

int almap_sigdb_load_file(const char *path) {
    FILE *fp;
    char *line = NULL;
    size_t line_cap = 0;
    ssize_t line_len;
    int loaded = 0;

    if (path == NULL) {
        return -1;
    }
    fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }
    while ((line_len = getline(&line, &line_cap, fp)) >= 0) {
        char *t = trim_inplace(line);
        char *first_sep;
        char *second_sep;
        char *last_sep;
        char *kind;
        char *port_s;
        char *pattern;
        char *name;
        int port = 0;

        if (t[0] == '\0' || t[0] == '#') {
            continue;
        }
        /* Find first two separators and the last one (pattern may
         * contain '|', so the last '|' ends the pattern). */
        {
            char *p;
            int seen = 0;
            char *first = NULL;
            char *second = NULL;
            char *last = NULL;
            for (p = t; *p != '\0'; p++) {
                if (*p == '|') {
                    if (seen == 0) {
                        first = p;
                    } else if (seen == 1) {
                        second = p;
                    }
                    last = p;
                    seen++;
                }
            }
            if (first == NULL || second == NULL || last == NULL ||
                second == last) {
                continue;
            }
            first_sep = first;
            second_sep = second;
            last_sep = last;
        }
        (void)first_sep;
        /* Split by NULing the separators. */
        *first_sep = '\0';
        *second_sep = '\0';
        *last_sep = '\0';
        kind = trim_inplace(t);
        port_s = trim_inplace(first_sep + 1);
        pattern = trim_inplace(second_sep + 1);
        name = trim_inplace(last_sep + 1);

        if (strcmp(kind, "EXACT") != 0 && strcmp(kind, "REGEX") != 0) {
            continue;
        }
        if (!parse_port_text(port_s, &port)) {
            continue;
        }
        if (almap_sigdb_add(kind, port, pattern, name) == 1) {
            loaded++;
        }
    }
    free(line);
    fclose(fp);
    return loaded;
}
