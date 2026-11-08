namespace output;

// modules/output.goose - Steps 16,19: result output only (text, JSON,
// table, and XML). No scanning, networking, or C interop.
// Step 16 adds the optional service field (text service="...",
// JSON "service", XML service="...", and a SERVICE table column that
// appears only with --service).
// Step 19 adds the optional OS field (text os="...", JSON "os",
// XML os="...", and a dedicated IP/PORT/STATE/SCAN/OS table shape for
// SYN scans with --os).
// Dependency-free: it must not import connect_scan or syn_scan
// (avoids import cycles).
// Text mode preserves Step 5 lines: ip:port state (banner variant
// appends banner="..." when non-empty).
// JSON mode streams a valid JSON array: begin prints "[", each
// emit prints one object, end prints "]". Comma placement is
// tracked by a caller-owned `first` bool threaded through emit
// (no global mutable state). Banner text is escaped with
// json_escape; IP/port/state/scan need no escaping.
// Table mode (Step 11) prints tab-separated header and rows
// without begin/end; banner text is the already-cleaned banner.
// XML mode (Step 14) streams one document: xml_begin_scan prints
// <almap><scan>, each result is one <result .../> element, and
// xml_end_scan prints </scan></almap>. Discovery uses
// xml_begin_discovery/<host .../>/xml_end_discovery. Attribute values
// that may contain arbitrary text (banners) go through xml_escape;
// IP/state/scan text is fixed-character data. The banner attribute is
// omitted entirely when the cleaned banner is empty.

fn begin(json: bool) {
    if json { print("["); }
}

fn after_emit(json: bool, first: bool) -> bool {
    if !json { return first; }
    return false;
}

fn emit_result(json: bool, first: bool, ip_text: const u8[:], port: i32, state: const u8[:], scan: const u8[:]) -> bool {
    if !json {
        print(ip_text, ":", port, " ", state);
        return after_emit(json, first);
    }
    if first {
        print("{\"ip\":\"", ip_text, "\",\"port\":", port, ",\"state\":\"", state, "\",\"scan\":\"", scan, "\"}");
        return after_emit(json, first);
    }
    print(",{\"ip\":\"", ip_text, "\",\"port\":", port, ",\"state\":\"", state, "\",\"scan\":\"", scan, "\"}");
    return after_emit(json, first);
}

fn emit_discovery(json: bool, first: bool, ip_text: const u8[:], up: bool) -> bool {
    if !json {
        let word = if up { "up" } else { "down" };
        print(ip_text, " ", word);
        return after_emit(json, first);
    }
    let word = if up { "true" } else { "false" };
    if first {
        print("{\"ip\":\"", ip_text, "\",\"up\":", word, "}");
        return after_emit(json, first);
    }
    print(",{\"ip\":\"", ip_text, "\",\"up\":", word, "}");
    return after_emit(json, first);
}

// Writes s escaped for inside JSON double quotes:
// " -> \", \ -> \\, bytes < 0x20 -> \u00XX (lowercase hex).
// Printable ASCII 0x20..0x7E passes through. Bytes >= 0x80 pass
// through unchanged (UTF-8 bytes preserved; escaping each byte
// as \u00XX would corrupt multibyte sequences).
fn json_escape(out: u8[>..]&, s: const u8[:]) {
    for b in s {
        if b == '"' {
            out.append("\\\"");
        } else if b == '\\' {
            out.append("\\\\");
        } else if b < 32 {
            out.append("\\u00");
            let hi = (b >> 4) & 15;
            let lo = b & 15;
            if hi < 10 { out.push(48 + hi); } else { out.push(87 + hi); }
            if lo < 10 { out.push(48 + lo); } else { out.push(87 + lo); }
        } else {
            out.push(b);
        }
    }
}

fn emit_result_banner(json: bool, first: bool, ip_text: const u8[:], port: i32, state: const u8[:], scan: const u8[:], banner: const u8[:]) -> bool {
    var esc: u8[>..] = [];
    if !json {
        if banner.len == 0 {
            print(ip_text, ":", port, " ", state);
            return after_emit(json, first);
        }
        print(ip_text, ":", port, " ", state, " banner=\"", banner, "\"");
        return after_emit(json, first);
    }
    if banner.len == 0 {
        return emit_result(json, first, ip_text, port, state, scan);
    }
    json_escape(esc, banner);
    if first {
        print("{\"ip\":\"", ip_text, "\",\"port\":", port, ",\"state\":\"", state, "\",\"scan\":\"", scan, "\",\"banner\":\"", esc, "\"}");
        return after_emit(json, first);
    }
    print(",{\"ip\":\"", ip_text, "\",\"port\":", port, ",\"state\":\"", state, "\",\"scan\":\"", scan, "\",\"banner\":\"", esc, "\"}");
    return after_emit(json, first);
}

// Step 16 service output. Text appends service="..." after state and
// before banner="..."; JSON adds an optional "service" field after
// "banner"; empty service is omitted from both. Values are the already
// cleaned service text from modules/service.goose.
fn emit_result_full(json: bool, first: bool, ip_text: const u8[:], port: i32, state: const u8[:], scan: const u8[:], banner: const u8[:], service: const u8[:]) -> bool {
    var line: u8[>..] = [];
    if !json {
        format(line, ip_text, ":", port, " ", state);
        if service.len > 0 { format(line, " service=\"", service, "\""); }
        if banner.len > 0 { format(line, " banner=\"", banner, "\""); }
        print(line);
        return after_emit(json, first);
    }
    if first {
        line.append("{");
    } else {
        line.append(",{");
    }
    format(line, "\"ip\":\"", ip_text, "\",\"port\":", port, ",\"state\":\"", state, "\",\"scan\":\"", scan, "\"");
    if banner.len > 0 {
        var esc: u8[>..] = [];
        json_escape(esc, banner);
        format(line, ",\"banner\":\"", esc, "\"");
    }
    if service.len > 0 {
        var esc: u8[>..] = [];
        json_escape(esc, service);
        format(line, ",\"service\":\"", esc, "\"");
    }
    line.append("}");
    print(line);
    return after_emit(json, first);
}

// Step 19: OS fingerprint result variants. The os value is one of the
// fixed labels from modules/os_fingerprint.goose, so no escaping is
// needed. Text appends os="..." after the state; JSON adds an "os"
// field after "scan"; table uses a dedicated five-column header with
// an OS column (SYN/OS mode never has banners or services); XML adds
// os="...".
fn emit_result_os(json: bool, first: bool, ip_text: const u8[:], port: i32, state: const u8[:], scan: const u8[:], os_name: const u8[:]) -> bool {
    if !json {
        var line: u8[>..] = [];
        format(line, ip_text, ":", port, " ", state, " os=\"", os_name, "\"");
        print(line);
        return after_emit(json, first);
    }
    if first {
        print("{\"ip\":\"", ip_text, "\",\"port\":", port, ",\"state\":\"", state, "\",\"scan\":\"", scan, "\",\"os\":\"", os_name, "\"}");
        return after_emit(json, first);
    }
    print(",{\"ip\":\"", ip_text, "\",\"port\":", port, ",\"state\":\"", state, "\",\"scan\":\"", scan, "\",\"os\":\"", os_name, "\"}");
    return after_emit(json, first);
}

fn table_header_os() -> const u8[:] {
    return "IP\tPORT\tSTATE\tSCAN\tOS";
}

fn emit_table_header_os() {
    print(table_header_os());
}

fn emit_table_row_os(ip_text: const u8[:], port: i32, state: const u8[:], scan: const u8[:], os_name: const u8[:]) {
    print(ip_text, "\t", port, "\t", state, "\t", scan, "\t", os_name);
}

fn xml_emit_scan_result_os(ip_text: const u8[:], port: i32, state: const u8[:], scan: const u8[:], os_name: const u8[:]) {
    print("<result ip=\"", ip_text, "\" port=\"", port, "\" state=\"", state, "\" scan=\"", scan, "\" os=\"", os_name, "\"/>");
}

// Step 22 AlScript result variants. script_out is arbitrary plugin
// text; JSON/XML escape it, text prints it raw after the state, and
// table uses a dedicated SCRIPT column. Empty output omits the
// field/attribute, matching banner/service.
fn emit_result_script(json: bool, first: bool, ip_text: const u8[:], port: i32, state: const u8[:], scan: const u8[:], script_out: const u8[:]) -> bool {
    var esc: u8[>..] = [];
    if !json {
        if script_out.len == 0 {
            print(ip_text, ":", port, " ", state);
            return after_emit(json, first);
        }
        print(ip_text, ":", port, " ", state, " script_out=\"", script_out, "\"");
        return after_emit(json, first);
    }
    if script_out.len == 0 {
        return emit_result(json, first, ip_text, port, state, scan);
    }
    json_escape(esc, script_out);
    if first {
        print("{\"ip\":\"", ip_text, "\",\"port\":", port, ",\"state\":\"", state, "\",\"scan\":\"", scan, "\",\"script_out\":\"", esc, "\"}");
        return after_emit(json, first);
    }
    print(",{\"ip\":\"", ip_text, "\",\"port\":", port, ",\"state\":\"", state, "\",\"scan\":\"", scan, "\",\"script_out\":\"", esc, "\"}");
    return after_emit(json, first);
}

fn table_header_script() -> const u8[:] {
    return "IP\tPORT\tSTATE\tSCAN\tSCRIPT";
}

fn emit_table_header_script() {
    print(table_header_script());
}

fn emit_table_row_script(ip_text: const u8[:], port: i32, state: const u8[:], scan: const u8[:], script_out: const u8[:]) {
    print(ip_text, "\t", port, "\t", state, "\t", scan, "\t", script_out);
}

fn xml_emit_scan_result_script(ip_text: const u8[:], port: i32, state: const u8[:], scan: const u8[:], script_out: const u8[:]) {
    if script_out.len == 0 {
        print("<result ip=\"", ip_text, "\" port=\"", port, "\" state=\"", state, "\" scan=\"", scan, "\"/>");
        return;
    }
    var esc: u8[>..] = [];
    xml_escape(esc, script_out);
    print("<result ip=\"", ip_text, "\" port=\"", port, "\" state=\"", state, "\" scan=\"", scan, "\" script_out=\"", esc, "\"/>");
}

fn end(json: bool) {
    if json { print("]"); }
}

// Pure header text for tables (single tabs between columns).
fn table_header(discovery: bool) -> const u8[:] {
    if discovery { return "IP\tUP"; }
    return "IP\tPORT\tSTATE\tSCAN\tBANNER";
}

fn emit_table_header(discovery: bool) {
    print(table_header(discovery));
}

fn emit_table_row(ip_text: const u8[:], port: i32, state: const u8[:], scan: const u8[:], banner: const u8[:]) {
    print(ip_text, "\t", port, "\t", state, "\t", scan, "\t", banner);
}

// Step 16: --service table header/rows add a SERVICE column before
// BANNER. The header stays the Step 11 five-column form when --service
// is not used, so existing table output is unchanged.
fn table_header_service() -> const u8[:] {
    return "IP\tPORT\tSTATE\tSCAN\tSERVICE\tBANNER";
}

fn emit_table_header_service() {
    print(table_header_service());
}

fn emit_table_row_service(ip_text: const u8[:], port: i32, state: const u8[:], scan: const u8[:], service: const u8[:], banner: const u8[:]) {
    print(ip_text, "\t", port, "\t", state, "\t", scan, "\t", service, "\t", banner);
}

fn emit_table_discovery_row(ip_text: const u8[:], up: bool) {
    let word = if up { "up" } else { "down" };
    print(ip_text, "\t", word);
}

// XML output (Step 14). Writes s escaped for an XML attribute value:
// & -> &amp;, < -> &lt;, > -> &gt;, " -> &quot;, ' -> &apos;.
// Bytes >= 0x80 pass through unchanged (UTF-8 bytes preserved).
fn xml_escape(out: u8[>..]&, s: const u8[:]) {
    for b in s {
        if b == '&' {
            out.append("&amp;");
        } else if b == '<' {
            out.append("&lt;");
        } else if b == '>' {
            out.append("&gt;");
        } else if b == '"' {
            out.append("&quot;");
        } else if b == '\'' {
            out.append("&apos;");
        } else {
            out.push(b);
        }
    }
}

fn xml_begin_scan() {
    print("<almap><scan>");
}

fn xml_end_scan() {
    print("</scan></almap>");
}

fn xml_begin_discovery() {
    print("<almap><discovery>");
}

fn xml_end_discovery() {
    print("</discovery></almap>");
}

fn xml_emit_scan_result(ip_text: const u8[:], port: i32, state: const u8[:], scan: const u8[:], banner: const u8[:]) {
    if banner.len == 0 {
        print("<result ip=\"", ip_text, "\" port=\"", port, "\" state=\"", state, "\" scan=\"", scan, "\"/>");
        return;
    }
    var esc: u8[>..] = [];
    xml_escape(esc, banner);
    print("<result ip=\"", ip_text, "\" port=\"", port, "\" state=\"", state, "\" scan=\"", scan, "\" banner=\"", esc, "\"/>");
}

// Step 16: XML result with both optional banner and service
// attributes. Empty attributes are omitted entirely.
fn xml_emit_scan_result_full(ip_text: const u8[:], port: i32, state: const u8[:], scan: const u8[:], banner: const u8[:], service: const u8[:]) {
    var line: u8[>..] = [];
    format(line, "<result ip=\"", ip_text, "\" port=\"", port, "\" state=\"", state, "\" scan=\"", scan, "\"");
    if banner.len > 0 {
        var esc: u8[>..] = [];
        xml_escape(esc, banner);
        format(line, " banner=\"", esc, "\"");
    }
    if service.len > 0 {
        var esc: u8[>..] = [];
        xml_escape(esc, service);
        format(line, " service=\"", esc, "\"");
    }
    line.append("/>");
    print(line);
}

fn xml_emit_discovery_host(ip_text: const u8[:], up: bool) {
    let word = if up { "true" } else { "false" };
    print("<host ip=\"", ip_text, "\" up=\"", word, "\"/>");
}
