#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "http.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/time.h>
#endif

/*
 * http.c - Step 28: native HTTP server for the ALmap Web UI.
 *
 * Minimal HTTP/1.1 over POSIX sockets. Single-threaded, sequential.
 * No dependencies beyond libc/POSIX. Use only on networks you own or
 * have permission to scan.
 */

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static int find_header_end(const unsigned char *buf, int len) {
    int i;

    if (len < 4) {
        return -1;
    }
    for (i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' &&
            buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return i + 4;
        }
    }
    return -1;
}

static int has_content_length(const unsigned char *buf, int header_len,
                              long *out_len) {
    const char *needle = "Content-Length:";
    const int nlen = (int)strlen(needle);
    int i;
    int j;

    if (out_len != NULL) {
        *out_len = 0;
    }
    if (header_len < nlen) {
        return 0;
    }
    for (i = 0; i + nlen <= header_len; i++) {
        int match = 1;

        for (j = 0; j < nlen; j++) {
            char a = (char)buf[i + j];
            char b = needle[j];

            if (a != b) {
                /* First char case-insensitive start: also try
                 * lower-case "content-length:" by folding. */
                if (a >= 'A' && a <= 'Z') {
                    a = (char)(a - 'A' + 'a');
                }
                if (b >= 'A' && b <= 'Z') {
                    b = (char)(b - 'A' + 'a');
                }
                if (a != b) {
                    match = 0;
                    break;
                }
            }
        }
        if (match) {
            long val = 0;
            int k = i + nlen;
            int saw_digit = 0;

            while (k < header_len && (buf[k] == ' ' || buf[k] == '\t')) {
                k++;
            }
            while (k < header_len && buf[k] >= '0' && buf[k] <= '9') {
                val = val * 10 + (buf[k] - '0');
                saw_digit = 1;
                k++;
            }
            if (saw_digit) {
                if (out_len != NULL) {
                    *out_len = val;
                }
                return 1;
            }
            return 0;
        }
    }
    return 0;
}

int almap_http_listen(int port) {
    int fd;
    int opt = 1;
    struct sockaddr_in addr;

    if (port < 1 || port > 65535) {
        return -1;
    }
    /* A closed client must not kill the server. send() also uses
     * MSG_NOSIGNAL, but this covers any other write path. */
    signal(SIGPIPE, SIG_IGN);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
        close(fd);
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0); /* INADDR_ANY */
    addr.sin_port = htons((unsigned short)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 64) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int almap_http_accept(int listen_fd) {
    int client;

    if (listen_fd < 0) {
        return -1;
    }
    for (;;) {
        client = accept(listen_fd, NULL, NULL);
        if (client >= 0) {
            return client;
        }
        if (errno == EINTR) {
            continue;
        }
        return -1;
    }
}

int almap_http_read(int client_fd, unsigned char *buf, int cap) {
    int total = 0;
#ifdef __linux__
    struct timeval tv;
#endif

    if (client_fd < 0 || buf == NULL || cap < 2) {
        return -1;
    }
    buf[0] = '\0';
#ifdef __linux__
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    while (total < cap - 1) {
        ssize_t n;
        int header_end;
        long clen = 0;
        int have_cl;

        n = recv(client_fd, buf + total, (size_t)(cap - 1 - total), 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            return total > 0 ? total : -1;
        }
        if (n == 0) {
            break;
        }
        total += (int)n;
        buf[total] = '\0';

        header_end = find_header_end(buf, total);
        if (header_end < 0) {
            continue;
        }
        have_cl = has_content_length(buf, header_end, &clen);
        if (!have_cl) {
            /* GET and other header-only requests are complete. */
            break;
        }
        if ((long)header_end + clen <= (long)total) {
            break;
        }
        /* Body incomplete: keep reading until CL bytes arrive. */
    }
    if (total == 0) {
        return -1;
    }
    buf[total] = '\0';
    return total;
}

int almap_http_send(int client_fd, const unsigned char *buf, int len) {
    int sent = 0;

    if (client_fd < 0 || len < 0 || (len > 0 && buf == NULL)) {
        return -1;
    }
    while (sent < len) {
        ssize_t n = send(client_fd, buf + sent, (size_t)(len - sent),
                         MSG_NOSIGNAL);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        sent += (int)n;
    }
    return 0;
}

int almap_http_close(int fd) {
    if (fd < 0) {
        return -1;
    }
    return close(fd);
}

int almap_http_self_exe(unsigned char *buf, int cap) {
    ssize_t n;

    if (buf == NULL || cap < 2) {
        return -1;
    }
    n = readlink("/proc/self/exe", (char *)buf, (size_t)(cap - 1));
    if (n <= 0) {
        return -1;
    }
    buf[n] = '\0';
    return (int)n;
}

int almap_http_run_scan(const char *targets, const char *ports,
                        const char *scan_type, int fast, int os_flag,
                        int service_flag, int evasion_flag,
                        int discover_flag, int timeout_ms, int retries,
                        const char *script,
                        unsigned char *out, int cap, int *exit_code) {
    char exe_path[512];
    char timeout_buf[16];
    char retries_buf[16];
    const char *argv[26];
    int argc = 0;
    int pipefd[2];
    pid_t pid;
    int total = 0;
    int status = 0;

    if (exit_code != NULL) {
        *exit_code = -1;
    }
    if (out == NULL || cap < 2) {
        return -1;
    }
    out[0] = '\0';
    if (targets == NULL || targets[0] == '\0') {
        return -1;
    }
    if (!discover_flag && (ports == NULL || ports[0] == '\0')) {
        return -1;
    }
    if (almap_http_self_exe((unsigned char *)exe_path,
                            (int)sizeof(exe_path)) < 0) {
        return -1;
    }

    timeout_buf[0] = '\0';
    if (timeout_ms > 0) {
        snprintf(timeout_buf, sizeof(timeout_buf), "%d", timeout_ms);
    }
    retries_buf[0] = '\0';
    if (retries >= 0) {
        snprintf(retries_buf, sizeof(retries_buf), "%d", retries);
    }

    argv[argc++] = exe_path;
    argv[argc++] = "-t";
    argv[argc++] = targets;
    if (discover_flag) {
        argv[argc++] = "--discover";
    } else {
        argv[argc++] = "-p";
        argv[argc++] = ports;
        argv[argc++] = "--scan";
        if (scan_type != NULL && scan_type[0] != '\0') {
            argv[argc++] = scan_type;
        } else {
            argv[argc++] = "connect";
        }
        if (timeout_ms > 0) {
            argv[argc++] = "--timeout";
            argv[argc++] = timeout_buf;
        }
        if (retries >= 0) {
            argv[argc++] = "--retries";
            argv[argc++] = retries_buf;
        }
        if (fast) {
            argv[argc++] = "--fast";
        }
        if (os_flag) {
            argv[argc++] = "--os";
        }
        if (service_flag) {
            argv[argc++] = "--service";
        }
        if (evasion_flag) {
            argv[argc++] = "-f";
        }
        if (script != NULL && script[0] != '\0') {
            argv[argc++] = "--script";
            argv[argc++] = script;
        }
    }
    argv[argc++] = "--json";
    argv[argc] = NULL;

    if (pipe(pipefd) != 0) {
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        /* Child: stdout+stderr -> pipe. */
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) {
            _exit(127);
        }
        if (dup2(pipefd[1], STDERR_FILENO) < 0) {
            _exit(127);
        }
        close(pipefd[1]);
        execv(exe_path, (char *const *)argv);
        _exit(127);
    }
    /* Parent: capture until EOF, truncating at cap-1. */
    close(pipefd[1]);
    while (total < cap - 1) {
        ssize_t n = read(pipefd[0], out + total, (size_t)(cap - 1 - total));

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (n == 0) {
            break;
        }
        total += (int)n;
    }
    {
        unsigned char drain[4096];
        ssize_t n;

        do {
            n = read(pipefd[0], drain, sizeof(drain));
        } while (n > 0);
    }
    close(pipefd[0]);

    for (;;) {
        pid_t w = waitpid(pid, &status, 0);

        if (w == pid) {
            break;
        }
        if (w < 0 && errno != EINTR) {
            break;
        }
    }
    if (exit_code != NULL) {
        if (WIFEXITED(status)) {
            *exit_code = WEXITSTATUS(status);
        } else {
            *exit_code = -1;
        }
    }
    out[total] = '\0';
    return total;
}
