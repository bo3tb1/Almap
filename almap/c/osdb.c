#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "osdb.h"
#include "os.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * osdb.c - Step 31: dynamic OS signature DB with probe strings.
 *
 * A malloc/realloc insertion-ordered array. Lookup is first-match
 * wins with O(N) scan in C, which is fast for the full 6000-entry
 * database (and correct for TTL ranges, which cannot be hashed by a
 * single key). Rows may carry a 6th PROBE field (T1-T7 signature)
 * matched exactly or as POSIX ERE. Storage is global/sequential.
 */

#define ALMAP_OSDB_INIT_CAP 1024
#define ALMAP_OSDB_MAX_NAME 64
#define ALMAP_OSDB_MAX_PROBE 2048

typedef struct {
    char *name;
    int min_ttl;
    int max_ttl;
    int window;
    int opts;
    char *probe;
} AlmapOsEntry;

/* Provided by c/sigdb.c (POSIX ERE matcher). */
int almap_sigdb_match_regex(const char *pattern, const char *text);

static AlmapOsEntry *g_os_entries = NULL;
static size_t g_os_count = 0;
static size_t g_os_cap = 0;

static int os_name_valid(const char *s) {
    size_t i;
    size_t len;

    if (s == NULL) {
        return 0;
    }
    len = strlen(s);
    if (len == 0 || len > ALMAP_OSDB_MAX_NAME) {
        return 0;
    }
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 32 || c > 126) {
            return 0;
        }
        if (c == '|' || c == '"' || c == '\\' || c == '<' || c == '>' ||
            c == '&') {
            return 0;
        }
    }
    return 1;
}

static int ensure_os_capacity(void) {
    AlmapOsEntry *grown;
    size_t want;

    if (g_os_count < g_os_cap) {
        return 1;
    }
    want = g_os_cap == 0 ? ALMAP_OSDB_INIT_CAP : g_os_cap * 2;
    grown = (AlmapOsEntry *)realloc(g_os_entries,
                                    want * sizeof(AlmapOsEntry));
    if (grown == NULL) {
        return 0;
    }
    g_os_entries = grown;
    g_os_cap = want;
    return 1;
}

int almap_osdb_free(void) {
    size_t i;

    if (g_os_entries != NULL) {
        for (i = 0; i < g_os_count; i++) {
            free(g_os_entries[i].name);
            free(g_os_entries[i].probe);
        }
        free(g_os_entries);
    }
    g_os_entries = NULL;
    g_os_count = 0;
    g_os_cap = 0;
    return 0;
}

int almap_osdb_count(void) {
    return (int)g_os_count;
}

int almap_osdb_add2(const char *name, int min_ttl, int max_ttl, int window,
                    int opts, const char *probe) {
    char *copy;
    char *probe_copy;
    size_t len;
    size_t plen;

    if (!os_name_valid(name)) {
        return 0;
    }
    if (min_ttl < 0 || min_ttl > 255 || max_ttl < 0 || max_ttl > 255 ||
        min_ttl > max_ttl) {
        return 0;
    }
    if (window < 0 || window > 65535) {
        return 0;
    }
    if (opts < 0 || (opts & ~0x0F) != 0) {
        return 0;
    }
    if (probe == NULL) {
        probe = "";
    }
    plen = strlen(probe);
    if (plen > ALMAP_OSDB_MAX_PROBE) {
        return 0;
    }
    len = strlen(name);
    copy = (char *)malloc(len + 1);
    probe_copy = (char *)malloc(plen + 1);
    if (copy == NULL || probe_copy == NULL) {
        free(copy);
        free(probe_copy);
        return 0;
    }
    memcpy(copy, name, len + 1);
    memcpy(probe_copy, probe, plen + 1);
    if (!ensure_os_capacity()) {
        free(copy);
        free(probe_copy);
        return 0;
    }
    g_os_entries[g_os_count].name = copy;
    g_os_entries[g_os_count].min_ttl = min_ttl;
    g_os_entries[g_os_count].max_ttl = max_ttl;
    g_os_entries[g_os_count].window = window;
    g_os_entries[g_os_count].opts = opts;
    g_os_entries[g_os_count].probe = probe_copy;
    g_os_count++;
    return 1;
}

int almap_osdb_add(const char *name, int min_ttl, int max_ttl, int window,
                   int opts) {
    return almap_osdb_add2(name, min_ttl, max_ttl, window, opts, "");
}

static int probe_matches(const char *pattern, const char *probe_str) {
    if (pattern == NULL || pattern[0] == '\0') {
        return 1;
    }
    if (probe_str == NULL || probe_str[0] == '\0') {
        return 1;
    }
    if (strcmp(pattern, probe_str) == 0) {
        return 1;
    }
    /* Exact miss: try POSIX ERE only when the pattern looks like one. */
    if (strpbrk(pattern, "*^$[]().+?") != NULL) {
        if (almap_sigdb_match_regex(pattern, probe_str) == 1) {
            return 1;
        }
    }
    return 0;
}

const char *almap_osdb_lookup(int ttl, int window, int opts) {
    return almap_osdb_lookup_full(ttl, window, opts, "");
}

const char *almap_osdb_lookup_full(int ttl, int window, int opts,
                                   const char *probe_str) {
    size_t i;

    if (ttl <= 0) {
        return NULL;
    }
    for (i = 0; i < g_os_count; i++) {
        AlmapOsEntry *e = &g_os_entries[i];

        if (ttl < e->min_ttl || ttl > e->max_ttl) {
            continue;
        }
        if (e->window != 0 && e->window != window) {
            continue;
        }
        if ((opts & e->opts) != e->opts) {
            continue;
        }
        if (!probe_matches(e->probe, probe_str)) {
            continue;
        }
        return e->name;
    }
    return NULL;
}

int almap_osdb_lookup_into(int ttl, int window, int opts, char *name_out,
                           int name_cap) {
    return almap_osdb_lookup_into_full(ttl, window, opts, "", name_out, name_cap);
}

int almap_osdb_lookup_into_full(int ttl, int window, int opts,
                                const char *probe_str, char *name_out,
                                int name_cap) {
    const char *found;
    size_t len;
    size_t take;

    if (name_out == NULL || name_cap < 1) {
        return 0;
    }
    name_out[0] = '\0';
    found = almap_osdb_lookup_full(ttl, window, opts, probe_str);
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

static char *trim_inplace_os(char *s) {
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

static int parse_int_os(const char *s, int *out) {
    char *t = trim_inplace_os((char *)s);
    char *end = NULL;
    long v;

    if (t[0] == '\0' || t[0] == '-' || t[0] == '+') {
        return 0;
    }
    v = strtol(t, &end, 10);
    if (end == t || *end != '\0') {
        return 0;
    }
    *out = (int)v;
    return 1;
}

static int parse_opts_os(const char *s, int *out_opts) {
    char *t = trim_inplace_os((char *)s);
    int mask = 0;
    char *saveptr = NULL;
    char *tok;

    if (t[0] == '\0') {
        *out_opts = 0;
        return 1;
    }
    tok = strtok_r(t, ",", &saveptr);
    if (tok == NULL) {
        return 0;
    }
    while (tok != NULL) {
        char *name = trim_inplace_os(tok);
        if (name[0] == '\0') {
            return 0;
        } else if (strcmp(name, "MSS") == 0) {
            mask |= ALMAP_OS_OPT_MSS;
        } else if (strcmp(name, "SACK") == 0) {
            mask |= ALMAP_OS_OPT_SACK;
        } else if (strcmp(name, "TS") == 0 || strcmp(name, "TIMESTAMPS") == 0) {
            mask |= ALMAP_OS_OPT_TIMESTAMPS;
        } else if (strcmp(name, "WS") == 0 || strcmp(name, "WINDOWSCALE") == 0) {
            mask |= ALMAP_OS_OPT_WINDOWSCALE;
        } else {
            return 0;
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }
    *out_opts = mask;
    return 1;
}

int almap_osdb_load_file(const char *path) {
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
        char *t = trim_inplace_os(line);
        char *fields[6];
        int nfields = 0;
        char *p = t;
        char *sep;
        int min_ttl = 0;
        int max_ttl = 0;
        int window = 0;
        int opts = 0;
        char *name = NULL;
        char *probe = NULL;

        if (t[0] == '\0' || t[0] == '#') {
            continue;
        }
        fields[0] = p;
        while ((sep = strchr(p, '|')) != NULL && nfields < 5) {
            *sep = '\0';
            fields[nfields + 1] = sep + 1;
            nfields++;
            p = sep + 1;
        }
        if (nfields != 4 && nfields != 5) {
            continue;
        }
        /* With 6 fields the probe field may itself contain '|' (ERE
         * alternation); anything beyond the first five separators is
         * part of the probe, which the loop above already joined by
         * keeping the remainder in fields[5]. */
        name = trim_inplace_os(fields[0]);
        if (!parse_int_os(fields[1], &min_ttl)) {
            continue;
        }
        if (!parse_int_os(fields[2], &max_ttl)) {
            continue;
        }
        if (!parse_int_os(fields[3], &window)) {
            continue;
        }
        if (!parse_opts_os(fields[4], &opts)) {
            continue;
        }
        if (nfields == 5) {
            probe = trim_inplace_os(fields[5]);
        } else {
            probe = "";
        }
        if (almap_osdb_add2(name, min_ttl, max_ttl, window, opts, probe) == 1) {
            loaded++;
        }
    }
    free(line);
    fclose(fp);
    return loaded;
}
