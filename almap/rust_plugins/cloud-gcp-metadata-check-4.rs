/* cloud-gcp-metadata-check-4 - GCP compute metadata root exposure */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(
        ctx,
        "GET",
        "/computeMetadata/v1/",
        Some("metadata.google.internal"),
        "Metadata-Flavor: Google\r\n",
        "",
        None,
        8192,
    ) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "cloud-gcp-metadata-check-4: no response from metadata endpoint");
            return 0;
        }
    };
    let code = http_status(&resp);
    let suffix = if code == 200 {
        " (metadata EXPOSED; verify)"
    } else {
        ""
    };
    set_out(
        ctx,
        &format!("cloud-gcp-metadata-check-4: GET /computeMetadata/v1/ [{}]{}", code, suffix),
    );
    0
}
