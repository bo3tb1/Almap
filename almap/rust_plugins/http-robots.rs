/* http-robots - parse robots.txt and probe disallowed paths. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut found = 0usize;
    let mut probes = 0usize;

    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/robots.txt", None, "", "", None, 8192) {
        Some(r) => r,
        None => {
            set_out(ctx, "robots.txt: not found");
            return 0;
        }
    };
    if resp.is_empty() || http_status(&resp) == 404 {
        set_out(ctx, "robots.txt: not found");
        return 0;
    }
    let body = http_body(&resp).to_string();
    let mut out = String::new();
    for raw in body.split('\n') {
        if probes >= 10 {
            break;
        }
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.len() > 10 && starts_ci(line, "Disallow:") {
            let value = line[9..].trim_matches(|c| c == ' ' || c == '\t');
            if !value.is_empty() && value.len() < 511 {
                let path = clean(value);
                if let Some(r) = http_request(ctx, "GET", &path, None, "", "", None, 8192) {
                    let code = http_status(&r);
                    if !r.is_empty() && code != 404 && code != 403 {
                        if found == 0 {
                            out.push_str("robots disallowed: ");
                        } else {
                            out.push_str(", ");
                        }
                        out.push_str(&format!("{} [{}]", path, code));
                        found += 1;
                    }
                }
                probes += 1;
            }
        }
    }
    if found == 0 {
        out.push_str("robots.txt: no accessible Disallow entries found");
    }
    set_out(ctx, &out);
    0
}
