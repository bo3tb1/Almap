/* http-vuln-cve2014-3704 - CVE-2014-3704 Drupalgeddon check */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    fn parse_drupal(s: &str) -> Option<(i32, i32)> {
        let pos = s.find("Drupal ")?;
        let rest = &s[pos + 7..];
        let bytes = rest.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == 0 {
            return None;
        }
        let major: i32 = rest[..i].parse().ok()?;
        if bytes.get(i) != Some(&b'.') {
            return None;
        }
        let mut j = i + 1;
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        if j == i + 1 {
            return None;
        }
        let minor: i32 = rest[i + 1..j].parse().ok()?;
        Some((major, minor))
    }
    if let Some(resp) = http_request(ctx, "GET", "/CHANGELOG.txt", None, "", "", None, 8192) {
        if let Some((major, minor)) = parse_drupal(http_body(&resp)) {
            if major == 7 && minor < 32 {
                set_out(ctx, &format!(
                    "VULNERABLE: Drupal {}.{} (CVE-2014-3704 Drupalgeddon)",
                    major, minor));
                return 0;
            }
        }
    }
    if let Some(resp) = http_request(ctx, "POST", "/?q=node&destination=node", None, "\r\n",
        "name[0 or 1]=test&name[1]=test&form_id=user_login&op=Log+in",
        Some("application/x-www-form-urlencoded"), 8192) {
        let body = http_body(&resp);
        if http_status(&resp) == 500
            && (body.contains("PDOException") || body.contains("DatabaseException"))
        {
            set_out(ctx, "VULNERABLE: Drupal CVE-2014-3704 SQL injection signature");
            return 0;
        }
        if body.contains("Drupal") {
            set_out(ctx, "Drupal detected; CVE-2014-3704 not confirmed");
            return 0;
        }
    }
    set_out(ctx, "not vulnerable: Drupal CVE-2014-3704 not confirmed");
    0
}
