/* ssh-version - read and report the exact SSH protocol banner. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let mut stream = match connect_ctx(ctx) {
        Some(s) => s,
        None => return 1,
    };
    let raw = recv_line(&mut stream, 1024);
    drop(stream);
    if raw.is_empty() {
        return 0;
    }
    let mut line = raw.split('\n').next().unwrap_or("");
    line = line.strip_suffix('\r').unwrap_or(line);
    let mut version: String = line
        .chars()
        .map(|c| if (c as u32) < 32 { '.' } else { c })
        .collect();
    version = version
        .trim_matches(|c| c == ' ' || c == '\t')
        .to_string();
    if version.starts_with("SSH-") {
        set_out(ctx, &version);
    }
    0
}
