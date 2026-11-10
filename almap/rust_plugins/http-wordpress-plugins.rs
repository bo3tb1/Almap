/* http-wordpress-plugins - detect common WordPress plugins */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let plugins = ["akismet", "contact-form-7", "woocommerce", "wordpress-seo",
                   "jetpack", "elementor", "wpforms-lite", "really-simple-ssl",
                   "litespeed-cache", "wordfence"];
    let mut out = String::new();
    let mut found = 0usize;
    for plugin in plugins.iter() {
        let path = format!("/wp-content/plugins/{}/readme.txt", plugin);
        if let Some(resp) = http_request(ctx, "GET", &path, None, "", "", None, 8192) {
            if http_status(&resp) == 200 && contains_ci(&resp, "stable tag") {
                if found == 0 { out.push_str("WordPress plugins: "); }
                else { out.push_str(", "); }
                out.push_str(plugin);
                found += 1;
            }
        }
    }
    if let Some(resp) = http_request(ctx, "GET", "/wp-content/plugins/", None, "", "", None, 8192) {
        if http_status(&resp) == 200 && contains_ci(&resp, "index of") {
            if found == 0 { out.push_str("WordPress plugins: "); }
            else { out.push_str(", "); }
            out.push_str("directory-listing");
            found += 1;
        }
    }
    if found == 0 { set_out(ctx, "WordPress plugins: none detected"); }
    else { set_out(ctx, &out); }
    0
}
