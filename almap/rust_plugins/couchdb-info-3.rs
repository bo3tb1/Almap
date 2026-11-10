/* couchdb-info-3 - CouchDB server info probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/",
        "/_all_dbs",
        "/_stats",
    ];
    let needles = [
        "couchdb",
        "[",
        "couchdb",
    ];
    let mut out = String::new();
    let mut found = 0usize;

    if !valid(ctx) {
        return 1;
    }
    for (path, needle) in paths.iter().zip(needles.iter()) {
        let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let code = http_status(&resp);
        if code < 400 && contains_ci(http_body(&resp), needle) {
            if found == 0 {
                out.push_str("CouchDB: ");
            } else {
                out.push_str(", ");
            }
            out.push_str(&format!("{} [{}]", path, code));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "CouchDB: no matching paths");
    } else {
        set_out(ctx, &out);
    }
    0
}
