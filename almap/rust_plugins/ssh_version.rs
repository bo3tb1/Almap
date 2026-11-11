/* ssh_version - read the SSH banner line and emit the protocol version. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => return 1,
    };
    // Read the first line (up to LF), matching the C banner read loop.
    let line = recv_line(&mut s, 1024);
    drop(s);
    if line.is_empty() {
        return 0;
    }
    // First line up to LF, trim trailing CR.
    let first = line.split('\n').next().unwrap_or("");
    let first = first.strip_suffix('\r').unwrap_or(first);
    // Control bytes (< 32) -> '.', then trim surrounding spaces/tabs.
    let mut version: String = first
        .chars()
        .map(|c| if (c as u32) < 32 { '.' } else { c })
        .collect();
    let trimmed = version.trim_matches(|c| c == ' ' || c == '\t').to_string();
    version = trimmed;
    // Only emit when it looks like an SSH identification string.
    if !version.starts_with("SSH-") {
        return 0;
    }
    set_out(ctx, &version);
    0
}
