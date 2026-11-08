namespace alscript;

// modules/alscript.goose - Step 22: AlScript C plugin loader.
// The C layer (c/alscript.c) owns dlopen/dlsym. Goose passes the
// script path as a NUL-terminated fixed buffer's first element
// (u8& crosses as uint8_t*, same verified form as the banner
// buffers) and a fixed u8[1024] output buffer the same way.

extern fn almap_script_file_ok(path: const u8&) -> i32;
extern fn almap_script_run_file(path: const u8&, target_ip: u32, port: i32, timeout_ms: i32, out: u8&, out_cap: i32) -> i32;
extern fn almap_script_last_error(buf: u8&, cap: i32) -> i32;

fn file_ok(path_buf: const u8&) -> bool {
    return almap_script_file_ok(path_buf) == 1;
}

// Runs the plugin against one open port. Returns the cleaned output
// length (>= 0) on plugin success, -1 on load/plugin failure.
// path_buf0/out_buf0 are first elements of fixed buffers; out is a
// writable slice over the output buffer (out.len is the capacity).
fn run_one(path_buf0: const u8&, target_ip: u32, port: i32, timeout_ms: i64, out: u8[:]) -> i64 {
    if out.len < 2 { return -1; }
    let n = almap_script_run_file(path_buf0, target_ip, port, timeout_ms as i32, out[0], out.len as i32);
    return n;
}

// Copies the last loader error into out. Returns the byte count.
fn last_error(out: u8[:]) -> i64 {
    if out.len < 2 { return 0; }
    return almap_script_last_error(out[0], out.len as i32);
}

// Pure: whether a plugin run with this length should emit script_out.
// Empty runs (length 0) and loader/plugin failures (-1) omit the
// field, matching the banner/service omission convention.
fn should_emit(out_len: i64) -> bool {
    return out_len > 0;
}
