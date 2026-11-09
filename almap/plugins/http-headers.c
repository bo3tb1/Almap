/* http-headers - dump the full HTTP response header block. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    const char *end;
    size_t n;
    int got;

    if (!ar_valid(ctx)) {
        return 1;
    }
    got = ar_http_get(ctx, "/", resp, sizeof(resp));
    if (got <= 0) {
        ar_out(ctx, "http-headers: no response");
        return 0;
    }
    end = strstr(resp, "\r\n\r\n");
    if (end == NULL) {
        end = strstr(resp, "\n\n");
        if (end == NULL) {
            end = resp + strlen(resp);
        } else {
            end += 2;
        }
    } else {
        end += 4;
    }
    n = (size_t)(end - resp);
    if (n >= sizeof(resp)) {
        n = sizeof(resp) - 1;
    }
    if (n >= (size_t)ctx->output_max) {
        n = (size_t)ctx->output_max - 1;
    }
    memcpy(ctx->output_buf, resp, n);
    ctx->output_buf[n] = '\0';
    return 0;
}
