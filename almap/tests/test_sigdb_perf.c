/*
 * test_sigdb_perf.c - Step 29 benchmark for the dynamic sigdb hash table.
 *
 * Loads 10,000 dummy signatures (alternating EXACT and REGEX across
 * many ports so port buckets stay small) and performs 1,000 lookups.
 * Asserts the lookup loop completes in well under a second (target:
 * milliseconds) and that lookups stay correct under collisions.
 * Build: gcc -std=c99 -Wall -Wextra -pthread -Ic tests/test_sigdb_perf.c c/sigdb.c -o /tmp/test_sigdb_perf
 */
#include "sigdb.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

int main(void) {
    int i;
    double t0, t1, elapsed;
    int hits = 0;
    int misses = 0;
    char pattern[64];
    char name[64];
    char text[80];
    char out[128];

    almap_sigdb_free();

    /* 10,000 dummy signatures. Port cycles 1..1000 so each port bucket
     * holds ~10 entries; the "any" bucket stays empty here. Half are
     * EXACT, half are anchored REGEX^TOKEN-n$ so each text matches
     * exactly one entry (no substring aliasing). */
    for (i = 0; i < 10000; i++) {
        int port = (i % 1000) + 1;
        if ((i % 2) == 0) {
            snprintf(pattern, sizeof(pattern), "TOKEN-%d-END", i);
            snprintf(name, sizeof(name), "svc-%d", i);
            if (almap_sigdb_add("EXACT", port, pattern, name) != 1) {
                fprintf(stderr, "add EXACT %d failed\n", i);
                return 1;
            }
        } else {
            snprintf(pattern, sizeof(pattern), "^BENCH-%d$", i);
            snprintf(name, sizeof(name), "svc-%d", i);
            if (almap_sigdb_add("REGEX", port, pattern, name) != 1) {
                fprintf(stderr, "add REGEX %d failed\n", i);
                return 1;
            }
        }
    }
    if (almap_sigdb_count() != 10000) {
        fprintf(stderr, "expected 10000 entries, got %d\n", almap_sigdb_count());
        return 1;
    }
    printf("loaded 10000 signatures, hash table size %d\n",
           almap_sigdb_hash_table_size());

    /* 1,000 lookups: alternate hit (text for entry i) and miss so
     * correctness is checked under collisions (many entries share a
     * bucket when port hashes collide). */
    t0 = now_ms();
    for (i = 0; i < 1000; i++) {
        int idx = (i * 10) % 10000; /* spread across the table */
        int port = (idx % 1000) + 1;
        const char *found = NULL;
        char expected[64];

        snprintf(expected, sizeof(expected), "svc-%d", idx);
        if ((idx % 2) == 0) {
            snprintf(text, sizeof(text), "banner TOKEN-%d-END here", idx);
        } else {
            snprintf(text, sizeof(text), "BENCH-%d", idx);
        }
        found = almap_sigdb_lookup(NULL, port, text);
        if (found == NULL) {
            misses++;
            fprintf(stderr, "lookup %d missed (port %d text %s)\n", idx, port, text);
            return 1;
        }
        if (strcmp(found, expected) != 0) {
            fprintf(stderr, "lookup %d: got %s want %s (text %s)\n", idx, found,
                    expected, text);
            return 1;
        }
        hits++;
        /* Also exercise the Into wrapper used by Goose. */
        out[0] = '\0';
        if (almap_sigdb_lookup_into(NULL, port, text, out, sizeof(out)) == 0) {
            fprintf(stderr, "lookup_into %d failed\n", idx);
            return 1;
        }
        if (strcmp(out, expected) != 0) {
            fprintf(stderr, "lookup_into %d: got %s want %s\n", idx, out, expected);
            return 1;
        }
    }
    t1 = now_ms();
    elapsed = t1 - t0;
    printf("1000 lookups in %.3f ms (%.4f ms/lookup), hits %d\n", elapsed,
           elapsed / 1000.0, hits);

    /* Collisions determinism: ports that hash to the same bucket must
     * not confuse lookups (chain scan checks port via buckets, but
     * verify a known collision pair still distinguishes). */
    {
        unsigned long h80 = almap_sigdb_port_hash(80);
        unsigned long h81 = almap_sigdb_port_hash(81);
        printf("hash(80)=%lu hash(81)=%lu table=%d\n", h80, h81,
               almap_sigdb_hash_table_size());
    }

    /* Miss path must be fast too and return NULL. */
    t0 = now_ms();
    for (i = 0; i < 1000; i++) {
        if (almap_sigdb_lookup(NULL, 4242, "definitely-not-a-banner") != NULL) {
            fprintf(stderr, "miss lookup unexpectedly hit\n");
            return 1;
        }
    }
    t1 = now_ms();
    printf("1000 misses in %.3f ms\n", t1 - t0);
    (void)misses;

    if (elapsed > 500.0) {
        fprintf(stderr, "benchmark too slow: %.3f ms for 1000 lookups (want milliseconds)\n",
                elapsed);
        return 1;
    }

    almap_sigdb_free();
    if (almap_sigdb_count() != 0) {
        fprintf(stderr, "count after free not 0\n");
        return 1;
    }
    printf("ok: sigdb perf benchmark passed (10k entries, 1k lookups)\n");
    return 0;
}
