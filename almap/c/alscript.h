#ifndef ALMAP_ALSCRIPT_H
#define ALMAP_ALSCRIPT_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * alscript.h - Step 22: AlScript dynamic plugin API.
 *
 * A plugin is a shared library (.so) built by the user with
 *   gcc -shared -fPIC -o my_script.so my_script.c
 * It must export a single-function entry point:
 *   int <ENTRY>(AlScriptContext *ctx);
 * The engine loads it with dlopen and reads the symbol with dlsym.
 *
 * AlScriptContext fields:
 * - target_ip: IPv4 as u32 with the first octet high (same form as
 *   Target.ip in Goose; e.g. 127.0.0.1 = 0x7F000001), host order.
 * - port: host-order TCP/UDP port 1..65535.
 * - timeout_ms: suggested network timeout (> 0); the plugin may use
 *   it for its own connect/read deadlines.
 * - output_buf / output_max: writable buffer; the plugin must never
 *   write past output_max - 1 bytes and must NUL-terminate. Output is
 *   arbitrary text (e.g. a banner); the engine copies it and escapes
 *   it for the chosen output format.
 *
 * The plugin return value is 0 on success (output_buf may be empty),
 * nonzero on plugin failure. The loader treats only the load/symbol
 * steps as hard failures (see ALSCRIPT_LOAD_* values).
 *
 * The engine runs the plugin only against ports the scan already
 * reported open. Plugins are untrusted native code: they run with the
 * full privileges of the ALmap process, in-process, with no sandbox.
 * Only load scripts you wrote or trust.
 *
 * Use only on networks you own or have permission to scan.
 */

/* Symbol every plugin must export. */
#define ALSCRIPT_ENTRY_SYMBOL "almap_script_run"

typedef struct {
    unsigned int target_ip;
    int port;
    int timeout_ms;
    char *output_buf;
    int output_max;
} AlScriptContext;

typedef int (*AlScriptRunFunc)(AlScriptContext *ctx);

/* almap_load_script(path, out_func):
 * Loads path with dlopen(RTLD_LAZY) and resolves
 * ALSCRIPT_ENTRY_SYMBOL with dlsym. On success stores the function in
 * *out_func and returns 1. On any failure (NULL path, missing file,
 * missing symbol, bad arguments) stores NULL in *out_func and returns
 * 0. The library handle is intentionally leaked (not dlclosed) so an
 * ALmap run can load a small number of scripts once and keep calling
 * them; the host process reclaims it on exit.
 */
int almap_load_script(const char *path, AlScriptRunFunc *out_func);

/* almap_script_file_ok(path): 1 when almap_load_script would succeed,
 * 0 otherwise. Used by the CLI for an early load check. */
int almap_script_file_ok(const char *path);

/* almap_script_run_file(path, target_ip, port, timeout_ms, out, out_cap):
 * One-shot helper: loads path, builds an AlScriptContext, invokes the
 * plugin, and copies up to out_cap - 1 bytes (NUL-terminated) into out.
 * target_ip is host-order u32 (first octet high). out must hold at
 * least out_cap bytes, out_cap >= 2. Returns the output byte count
 * (>= 0) when the plugin ran and returned 0, or -1 when the load /
 * symbol step fails or the plugin returns nonzero.
 */
int almap_script_run_file(const char *path, unsigned int target_ip, int port,
                          int timeout_ms, unsigned char *out, int out_cap);

/* almap_script_last_error(buf, cap): copies the most recent loader
 * dlerror string (or "unknown loader error") into buf, NUL-terminated.
 * Returns the number of bytes written (excluding NUL). */
int almap_script_last_error(char *buf, int cap);

#ifdef __cplusplus
}
#endif

#endif /* ALMAP_ALSCRIPT_H */
