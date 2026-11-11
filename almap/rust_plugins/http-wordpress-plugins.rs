/* http-wordpress-plugins - detect common WordPress plugins. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let plugins = [
        "akismet", "contact-form-7", "woocommerce", "wordpress-seo",
        "jetpack", "elementor", "wpforms-lite", "really-simple-ssl",
        "litespeed-cache", "wordfence",
    ];
    let mut found = 0;

    if !valid(ctx) {
        return 1;
    }
    for plugin in plugins.iter() {
        let path = format!("/wp-content/plugins/{}/readme.txt", plugin);
        if let Some(resp) = http_request(ctx, "GET", &path, None, "", "", None, 8192) {
            if !resp.is_empty()
                && http_status(&resp) == 200
                && contains_ci(&resp, "stable tag")
            {
                let prefix = if found == 0 { "WordPress plugins: " } else { ", " };
                append_out(ctx, &format!("{}{}", prefix, plugin));
                found += 1;
            }
        }
    }
    if let Some(resp) = http_request(ctx, "GET", "/wp-content/plugins/", None, "", "", None, 8192) {
        if !resp.is_empty()
            && http_status(&resp) == 200
            && contains_ci(&resp, "index of")
        {
            let prefix = if found == 0 { "WordPress plugins: " } else { ", " };
            append_out(ctx, &format!("{}directory-listing", prefix));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "WordPress plugins: none detected");
    }
    0
}
