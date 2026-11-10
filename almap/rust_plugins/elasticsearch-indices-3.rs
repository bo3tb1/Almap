/* elasticsearch-indices-3 - Elasticsearch index enumeration probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/_cat/indices",
        "/_all/_settings",
        "/_cluster/state",
    ];
    let needles = [
        "index",
        "settings",
        "metadata",
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
                out.push_str("Elasticsearch indices: ");
            } else {
                out.push_str(", ");
            }
            out.push_str(&format!("{} [{}]", path, code));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "Elasticsearch indices: no matching paths");
    } else {
        set_out(ctx, &out);
    }
    0
}
