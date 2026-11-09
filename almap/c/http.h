#ifndef ALMAP_HTTP_H
#define ALMAP_HTTP_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * http.h - Step 28: native HTTP server for the ALmap Web UI.
 *
 * Dependency-free POSIX sockets. No mongoose/libmicrohttpd.
 * The C layer owns sockets, blocking accept/read/send, and child
 * process execution. Goose (modules/webui.goose) owns routing, HTML,
 * JSON parsing, validation, and response framing.
 *
 * almap_http_listen(port):
 *   Creates an AF_INET/SOCK_STREAM socket, sets SO_REUSEADDR, binds
 *   INADDR_ANY (0.0.0.0) on port (1..65535), and listens with backlog
 *   64. Returns the listening fd (>= 0) or -1 on failure.
 *
 * almap_http_accept(listen_fd):
 *   Blocks until a client connects. Retries on EINTR. Returns the
 *   client fd (>= 0) or -1 on failure.
 *
 * almap_http_read(client_fd, buf, cap):
 *   Reads one HTTP request into buf (NUL-terminated). Returns total
 *   bytes read (> 0) or -1 when no bytes arrive (timeout/EOF/error).
 *   Sets a 5s SO_RCVTIMEO. Reads until the header terminator
 *   (CRLFCRLF) plus Content-Length body bytes are present, or until
 *   timeout/EOF, up to cap-1 bytes. buf must hold at least cap bytes,
 *   cap >= 2.
 *
 * almap_http_send(client_fd, buf, len):
 *   Writes all len bytes (send loop with MSG_NOSIGNAL) so a closed
 *   client cannot kill the server with SIGPIPE. Returns 0 on success,
 *   -1 on failure. len may be 0 (no-op).
 *
 * almap_http_close(fd):
 *   Closes fd. Returns 0 on success, -1 on failure.
 *
 * almap_http_self_exe(buf, cap):
 *   Copies the current executable path (readlink /proc/self/exe) into
 *   buf NUL-terminated. Returns the path byte count (> 0) or -1 when
 *   unavailable. buf must hold cap bytes, cap >= 2.
 *
 * almap_http_run_scan(targets, ports, scan_type, fast, os_flag,
 *                     service_flag, evasion_flag, discover_flag,
 *                     timeout_ms, retries, script, out, cap, exit_code):
 *   Spawns the ALmap binary (self exe) as a child with --json and
 *   captures combined stdout+stderr into out NUL-terminated. Returns
 *   the output byte count (>= 0) or -1 on fork/exec/pipe failure.
 *   When exit_code is non-NULL it stores the child exit status
 *   (WEXITSTATUS when WIFEXITED, else -1). out must hold cap bytes,
 *   cap >= 2. Arguments are NUL-terminated C strings:
 *     targets    comma list (required, unless empty with discover)
 *     ports      ports string (required unless discover_flag)
 *     scan_type  "connect" | "syn" | "udp" (empty means "connect";
 *                ignored when discover_flag is set)
 *     fast, os_flag, service_flag, evasion_flag, discover_flag
 *                nonzero means add the corresponding flag
 *                (--fast, --os, --service, -f, --discover)
 *     timeout_ms  when > 0, passes --timeout <ms>
 *     retries    when >= 0, passes --retries <n> (fast engine timeout
 *                retries, CLI range 0..10)
 *     script     AlScript .so path; empty/NULL means no --script
 *
 * All functions are thread-unsafe only in that the server is
 * single-threaded by design (sequential request handling).
 *
 * Use only on networks you own or have permission to scan. The Web UI
 * spawns full ALmap scans with the server process privileges.
 */

int almap_http_listen(int port);
int almap_http_accept(int listen_fd);
int almap_http_read(int client_fd, unsigned char *buf, int cap);
int almap_http_send(int client_fd, const unsigned char *buf, int len);
int almap_http_close(int fd);
int almap_http_self_exe(unsigned char *buf, int cap);
int almap_http_run_scan(const char *targets, const char *ports,
                        const char *scan_type, int fast, int os_flag,
                        int service_flag, int evasion_flag,
                        int discover_flag, int timeout_ms, int retries,
                        const char *script,
                        unsigned char *out, int cap, int *exit_code);

#ifdef __cplusplus
}
#endif

#endif /* ALMAP_HTTP_H */
