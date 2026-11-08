#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "alscript.h"

#include <dlfcn.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/*
 * alscript.c - Step 22: dlopen/dlsym loader for AlScript plugins.
 * No heap/GC concerns beyond dlopen itself. Handles are not closed
 * (documented in the header) to keep call-once-per-plugin usage sane;
 * the short-lived scanner process exits after the scan.
 */

/* Step 24 fix: dlerror strings are only valid until the next dl*
 * call, so copy them into a static buffer instead of storing the
 * pointer. */
static char almap_dl_error_buf[512];
static const char *almap_dl_error = NULL;

static void almap_set_error(const char *msg) {
    if (msg == NULL) {
        msg = "unknown loader error";
    }
    (void)strncpy(almap_dl_error_buf, msg, sizeof(almap_dl_error_buf) - 1);
    almap_dl_error_buf[sizeof(almap_dl_error_buf) - 1] = '\0';
    almap_dl_error = almap_dl_error_buf;
}

int almap_load_script(const char *path, AlScriptRunFunc *out_func) {
    void *handle;
    AlScriptRunFunc func;
    const char *err;
    char *last_err;

    if (out_func == NULL) {
        return 0;
    }
    *out_func = NULL;
    if (path == NULL || path[0] == '\0') {
        almap_set_error("empty script path");
        return 0;
    }

    /* Clear prior dlerror so dlsym errors are unambiguous. */
    dlerror();
    handle = dlopen(path, RTLD_LAZY | RTLD_LOCAL);
    if (handle == NULL) {
        last_err = dlerror();
        almap_set_error((last_err != NULL) ? last_err : "dlopen failed");
        return 0;
    }

    dlerror();
    func = (AlScriptRunFunc)dlsym(handle, ALSCRIPT_ENTRY_SYMBOL);
    err = dlerror();
    if (err != NULL) {
        almap_set_error(err);
        return 0;
    }
    if (func == NULL) {
        almap_set_error("plugin lacks almap_script_run symbol");
        return 0;
    }
    *out_func = func;
    almap_dl_error = NULL;
    return 1;
}

int almap_script_file_ok(const char *path) {
    AlScriptRunFunc func;

    return almap_load_script(path, &func);
}

int almap_script_run_file(const char *path, unsigned int target_ip, int port,
                          int timeout_ms, unsigned char *out, int out_cap) {
    AlScriptRunFunc func;
    AlScriptContext ctx;
    int rc;
    size_t len;

    if (out == NULL || out_cap < 2) {
        return -1;
    }
    out[0] = '\0';
    if (port < 1 || port > 65535 || timeout_ms <= 0) {
        return -1;
    }
    if (almap_load_script(path, &func) != 1 || func == NULL) {
        return -1;
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.target_ip = target_ip;
    ctx.port = port;
    ctx.timeout_ms = timeout_ms;
    ctx.output_buf = (char *)out;
    ctx.output_max = out_cap;
    out[0] = '\0';

    rc = func(&ctx);
    if (rc != 0) {
        out[0] = '\0';
        return -1;
    }
    /* The plugin must have NUL-terminated; enforce and clamp anyway. */
    len = strnlen((char *)out, (size_t)out_cap);
    if (len >= (size_t)out_cap) {
        out[out_cap - 1] = '\0';
        len = (size_t)(out_cap - 1);
    }
    return (int)len;
}

int almap_script_last_error(char *buf, int cap) {
    const char *msg;

    if (buf == NULL || cap < 2) {
        return 0;
    }
    msg = (almap_dl_error != NULL) ? almap_dl_error : "unknown loader error";
    (void)strncpy(buf, msg, (size_t)(cap - 1));
    buf[cap - 1] = '\0';
    return (int)strlen(buf);
}
