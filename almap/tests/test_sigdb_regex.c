/*
 * tests/test_sigdb_regex.c - Step 25 unit tests for the C POSIX regex
 * layer used by modules/sigdb.goose.
 *
 * Build and run standalone:
 *   gcc -std=c99 -Wall -Wextra -pthread -Ic tests/test_sigdb_regex.c \
 *       c/sigdb.c -o /tmp/test_sigdb_regex && /tmp/test_sigdb_regex
 */

#include "sigdb.h"

#include <stdio.h>

static int failures = 0;

static void expect_match(const char *pattern, const char *text, int want,
                         const char *name) {
    int got = almap_sigdb_match_regex(pattern, text);
    if (got != want) {
        fprintf(stderr, "FAIL %s: pattern [%s] text [%s] got %d want %d\n",
                name, pattern, text, got, want);
        failures++;
    }
}

int main(void) {
    /* Anchors, classes, quantifiers, alternation, escaped dots. */
    expect_match("^SSH-[0-9]+\\.[0-9]+-", "SSH-2.0-OpenSSH_9.6", 1,
                 "ssh prefix");
    expect_match("^SSH-[0-9]+\\.[0-9]+-", "ssh-2.0-OpenSSH_9.6", 0,
                 "case sensitive");
    expect_match("^(ACME|ZULU)-[0-9]+$", "ACME-42", 1, "alternation");
    expect_match("^(ACME|ZULU)-[0-9]+$", "WIDGET-42", 0, "alternation miss");
    expect_match("[0-9]{3}", "HTTP/1.0 404 Not Found", 1, "bounded repeat");
    expect_match("^HTTP/[0-9]+\\.[0-9]+ [0-9]{3}", "HTTP/1.1 200 OK", 1,
                 "http status");
    expect_match("Server: [A-Za-z0-9._-]+", "x\r\nServer: nginx\r\n", 1,
                 "header group");
    expect_match("a\\|b", "a|b", 1, "escaped literal pipe");
    expect_match("a\\|b", "ab", 0, "escaped pipe miss");
    expect_match("[[:space:]]+", "a\tb", 1, "posix space class");
    expect_match("^$", "", 1, "empty line");

    /* Invalid patterns, empty/null inputs: non-match, never a crash. */
    expect_match("(", "anything", 0, "unclosed group");
    expect_match("[z-a]", "anything", 0, "bad range");
    expect_match(NULL, "anything", 0, "null pattern");
    expect_match("anything", NULL, 0, "null text");
    expect_match("", "anything", 0, "empty pattern");

    if (failures != 0) {
        fprintf(stderr, "%d sigdb regex test(s) failed\n", failures);
        return 1;
    }
    printf("sigdb regex C tests passed\n");
    return 0;
}
