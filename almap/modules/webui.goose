import std;
import modules.target;
import modules.output;
namespace webui;

// modules/webui.goose - Step 28: Web UI (Zenmap Killer).
// Lightweight HTTP server serving a single-page dark-mode frontend
// and a JSON API for scans. Dependency-free: raw HTML/CSS/JS embedded
// via Goose string construction, POSIX sockets via c/http.c.
//
// Routes (Goose owns routing; C owns sockets/child processes):
//   GET  /            -> index HTML page
//   GET  /api/status  -> {"status":"ok","version":"4.0.0",...}
//   POST /api/scan    -> JSON {targets,ports,scan_type,fast,os,
//                        service,evasion,discover,timeout}
//                        spawns the ALmap binary (self exe) with
//                        --json and returns its JSON result.
//   else              -> 404 JSON
//
// Scan request JSON (all keys optional except targets/ports):
//   "targets":   comma list, e.g. "127.0.0.1" (required)
//   "ports":     ports string, e.g. "80,443" (required unless discovery)
//   "scan_type": "connect" (default) | "syn" | "udp" | "discovery"
//   "fast":      bool --fast (connect only)
//   "os":        bool --os  (syn only)
//   "service":   bool --service (connect only)
//   "evasion":   bool -f/--fragment (syn/connect only)
//   "discover":  bool --discover (sets discovery when true)
//   "timeout":   int ms 1..60000 (default 1000)
//
// Validation mirrors the CLI in almap.goose: fast requires connect and
// cannot combine with service/evasion/os; os requires syn; service
// requires connect; evasion requires syn/connect; udp cannot combine
// with service; discovery cannot combine with ports. Targets/ports are
// checked with modules/target parsers before the child is spawned.
// Child failures return 500 with {"error":...,"exit_code":...}.
//
// C bindings: single client at a time (sequential). Fixed buffers
// use the verified first-element reference form (u8& crosses as
// uint8_t*); slices cross as {data,len} and do not match the C
// pointer signatures, so callers pass buf[0] with an explicit cap.

extern fn almap_http_listen(port: i32) -> i32;
extern fn almap_http_accept(listen_fd: i32) -> i32;
extern fn almap_http_read(client_fd: i32, buf: u8&, cap: i32) -> i32;
extern fn almap_http_send(client_fd: i32, buf: const u8&, len: i32) -> i32;
extern fn almap_http_close(fd: i32) -> i32;
extern fn almap_http_self_exe(buf: u8&, cap: i32) -> i32;
extern fn almap_http_run_scan(targets: const u8&, ports: const u8&, scan_type: const u8&, fast: i32, os_flag: i32, service_flag: i32, evasion_flag: i32, discover_flag: i32, timeout_ms: i32, script: const u8&, out: u8&, cap: i32, exit_code: i32&) -> i32;

fn version_string() -> const u8[:] {
    return "4.0.0";
}

fn default_port() -> i64 {
    return 8080;
}

fn valid_port(port: i64) -> bool {
    if port < 1 { return false; }
    if port > 65535 { return false; }
    return true;
}

fn parse_port(s: const u8[:]) -> i64, bool {
    let t = trim(s);
    if t.len == 0 { return 0, false; }
    if t[0] == '-' || t[0] == '+' { return 0, false; }
    let v, ok = parse_int(t);
    if !ok { return 0, false; }
    if v < 1 || v > 65535 { return 0, false; }
    return v, true;
}

fn is_ws(c: u8) -> bool {
    if c == ' ' || c == '\t' || c == '\n' || c == '\r' { return true; }
    return false;
}

fn starts_with(s: const u8[:], prefix: const u8[:]) -> bool {
    if prefix.len > s.len { return false; }
    var i: i64 = 0;
    while i < prefix.len {
        if s[i] != prefix[i] { return false; }
        i++;
    }
    return true;
}

fn find_substring(hay: const u8[:], needle: const u8[:]) -> i64 {
    if needle.len == 0 { return 0; }
    if needle.len > hay.len { return -1; }
    var i: i64 = 0;
    while i + needle.len <= hay.len {
        var j: i64 = 0;
        var ok = true;
        while j < needle.len {
            if hay[i + j] != needle[j] { ok = false; break; }
            j++;
        }
        if ok { return i; }
        i++;
    }
    return -1;
}

// Method/path routing helpers (pure, unit-tested).

fn is_status_request(method: const u8[:], path: const u8[:]) -> bool {
    if method != "GET" { return false; }
    if path == "/api/status" { return true; }
    if starts_with(path, "/api/status?") { return true; }
    return false;
}

fn is_scan_request(method: const u8[:], path: const u8[:]) -> bool {
    if method != "POST" { return false; }
    if path == "/api/scan" { return true; }
    if starts_with(path, "/api/scan?") { return true; }
    return false;
}

fn is_index_request(method: const u8[:], path: const u8[:]) -> bool {
    if method != "GET" { return false; }
    if path == "/" { return true; }
    if path == "/index.html" { return true; }
    return false;
}

fn parse_request_line(req: const u8[:], method_out: u8[>..]&, path_out: u8[>..]&) -> bool {
    let nl = position(req, '\n');
    if nl < 0 { return false; }
    let line = trim(req[..nl]);
    if line.len == 0 { return false; }
    let parts = split(line, ' ');
    if parts.len < 2 { return false; }
    method_out.append(parts[0]);
    path_out.append(parts[1]);
    return true;
}

fn extract_body(req: const u8[:]) -> const u8[:] {
    let idx = find_substring(req, "\r\n\r\n");
    if idx >= 0 { return req[idx + 4..]; }
    let idx2 = find_substring(req, "\n\n");
    if idx2 >= 0 { return req[idx2 + 2..]; }
    return "";
}

// Minimal JSON field helpers (pure). Values with escapes are
// rejected: targets/ports/scan_type never need escapes, so a backslash
// in the raw value means an escaped char we do not decode.

fn json_string(body: const u8[:], key: const u8[:], out: u8[>..]&) -> bool {
    var qkey: u8[>..] = [];
    qkey.push('"');
    qkey.append(key);
    qkey.push('"');
    let kpos = find_substring(body, qkey);
    if kpos < 0 { return false; }
    var i = kpos + qkey.len;
    while i < body.len && is_ws(body[i]) { i++; }
    if i >= body.len || body[i] != ':' { return false; }
    i++;
    while i < body.len && is_ws(body[i]) { i++; }
    if i >= body.len || body[i] != '"' { return false; }
    i++;
    var start = i;
    while i < body.len && body[i] != '"' {
        if body[i] == '\\' { return false; }
        i++;
    }
    if i >= body.len { return false; }
    out.append(body[start..i]);
    return true;
}

fn json_bool(body: const u8[:], key: const u8[:]) -> bool, bool {
    var qkey: u8[>..] = [];
    qkey.push('"');
    qkey.append(key);
    qkey.push('"');
    let kpos = find_substring(body, qkey);
    if kpos < 0 { return false, false; }
    var i = kpos + qkey.len;
    while i < body.len && is_ws(body[i]) { i++; }
    if i >= body.len || body[i] != ':' { return false, false; }
    i++;
    while i < body.len && is_ws(body[i]) { i++; }
    if i + 4 <= body.len && body[i..i + 4] == "true" { return true, true; }
    if i + 5 <= body.len && body[i..i + 5] == "false" { return false, true; }
    return false, false;
}

fn json_int(body: const u8[:], key: const u8[:]) -> i64, bool {
    var qkey: u8[>..] = [];
    qkey.push('"');
    qkey.append(key);
    qkey.push('"');
    let kpos = find_substring(body, qkey);
    if kpos < 0 { return 0, false; }
    var i = kpos + qkey.len;
    while i < body.len && is_ws(body[i]) { i++; }
    if i >= body.len || body[i] != ':' { return 0, false; }
    i++;
    while i < body.len && is_ws(body[i]) { i++; }
    var start = i;
    if i < body.len && (body[i] == '-' || body[i] == '+') { i++; }
    var digits: i64 = 0;
    while i < body.len && body[i] >= '0' && body[i] <= '9' { i++; digits++; }
    if digits == 0 { return 0, false; }
    let v, ok = parse_int(body[start..i]);
    if !ok { return 0, false; }
    return v, true;
}

fn is_valid_scan_type(s: const u8[:]) -> bool {
    if s == "connect" { return true; }
    if s == "syn" { return true; }
    if s == "udp" { return true; }
    if s == "discovery" { return true; }
    if s == "discover" { return true; }
    return false;
}

fn is_discovery_type(s: const u8[:]) -> bool {
    if s == "discovery" { return true; }
    if s == "discover" { return true; }
    return false;
}

fn copy_cstr(dst: u8[:], src: const u8[:]) -> bool {
    if src.len >= dst.len { return false; }
    var i: i64 = 0;
    while i < src.len {
        dst[i] = src[i];
        i++;
    }
    dst[src.len] = 0;
    return true;
}

fn status_text(code: i64) -> const u8[:] {
    if code == 200 { return "OK"; }
    if code == 400 { return "Bad Request"; }
    if code == 404 { return "Not Found"; }
    return "Internal Server Error";
}

fn status_json(out: u8[>..]&) {
    out.append("{\"status\":\"ok\",\"version\":\"");
    output::json_escape(out, version_string());
    out.append("\",\"service\":\"almap-web\"}");
}

fn error_json(out: u8[>..]&, message: const u8[:]) {
    out.append("{\"error\":\"");
    output::json_escape(out, message);
    out.append("\"}");
}

fn send_response(client: i32, code: i64, ctype: const u8[:], body: const u8[:]) {
    var hdr: u8[>..] = [];
    hdr.append("HTTP/1.1 ");
    format(hdr, code);
    hdr.append(" ");
    hdr.append(status_text(code));
    hdr.append("\r\nContent-Type: ");
    hdr.append(ctype);
    hdr.append("\r\nContent-Length: ");
    format(hdr, body.len);
    hdr.append("\r\nConnection: close\r\n\r\n");
    let _ = almap_http_send(client, hdr[0], hdr.len as i32);
    if body.len > 0 {
        let _ = almap_http_send(client, body[0], body.len as i32);
    }
}

fn index_html(out: u8[>..]&) {
    out.append("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>ALmap Web UI - Zenmap Killer</title>
        <style>
        :root{color-scheme:dark}
        *{box-sizing:border-box}
        body{margin:0;background:#0f1419;color:#e6edf3;font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;line-height:1.5}
        .container{max-width:920px;margin:0 auto;padding:28px 20px 40px}
        header{margin-bottom:18px}
        h1{margin:0 0 6px;font-size:30px;letter-spacing:.2px}
        .sub{color:#9aa7b4;margin:0 0 10px}
        .status{display:inline-block;padding:4px 10px;border:1px solid #30363d;border-radius:999px;background:#161c22;font-size:13px;color:#9aa7b4}
        .dot{color:#f0883e}
        .dot.on{color:#3fb950}
        .card{background:#161c22;border:1px solid #30363d;border-radius:12px;padding:18px;margin:14px 0}
        .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
        label{display:block;font-size:13px;color:#9aa7b4}
        label input,label select{width:100%;margin-top:6px;padding:9px 10px;border-radius:8px;border:1px solid #30363d;background:#0d1117;color:#e6edf3;font-size:14px}
        label input:focus,label select:focus{outline:none;border-color:#58a6ff}
        .flags{display:flex;flex-wrap:wrap;gap:16px;margin:14px 0}
        .flags label{display:flex;align-items:center;gap:7px;color:#e6edf3}
        .flags input{width:auto}
        button{background:#238636;color:#fff;border:0;border-radius:8px;padding:10px 18px;font-size:14px;font-weight:600;cursor:pointer}
        button:hover{background:#2ea043}
        button:disabled{opacity:.6;cursor:not-allowed}
        .hint{color:#8b949e;font-size:13px;margin:12px 0 0}
        h2{font-size:18px;margin:18px 0 8px}
        .terminal{background:#0b0e11;border:1px solid #30363d;border-radius:10px;padding:14px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;white-space:pre-wrap;word-break:break-word;min-height:260px;max-height:520px;overflow:auto}
        .ok{color:#7ee787}
        .err{color:#ffa198}
        @media (max-width:640px){.grid{grid-template-columns:1fr}}
        </style>
        </head>
        <body>
        <div class="container">
        <header>
        <h1>ALmap Web UI</h1>
        <p class="sub">High-performance Nmap alternative - async engine, evasion, C plugins, Regex DB, OS DB (Zenmap Killer)</p>
        <span class="status"><span id="dot" class="dot">&#9679;</span> <span id="statusText">connecting...</span></span>
        </header>
        <form id="scanForm" class="card">
        <div class="grid">
        <label>Targets<input id="targets" name="targets" value="127.0.0.1" placeholder="127.0.0.1, 192.168.1.0/24" autocomplete="off" required></label>
        <label>Ports<input id="ports" name="ports" value="80,443" placeholder="80,443 or 1-1024" autocomplete="off"></label>
        <label>Scan type<select id="scan_type" name="scan_type"><option value="connect">Connect</option><option value="syn">SYN</option><option value="udp">UDP</option><option value="discovery">Discovery</option></select></label>
        <label>Timeout (ms)<input id="timeout" name="timeout" type="number" value="1000" min="1" max="60000"></label>
        <label>AlScript (.so)<input id="script" name="script" placeholder="plugins/http_title.so (optional)" autocomplete="off" list="scripts"><datalist id="scripts"><option value="plugins/http_title.so"><option value="plugins/ftp_anon.so"><option value="plugins/ssh_version.so"><option value="plugins/http_methods.so"><option value="plugins/redis_info.so"><option value="plugins/sample_banner.so"></datalist></label>
        </div>
        <div class="flags">
        <label><input type="checkbox" id="fast" name="fast"> Fast (async engine)</label>
        <label><input type="checkbox" id="os" name="os"> OS fingerprinting</label>
        <label><input type="checkbox" id="service" name="service"> Service detection</label>
        <label><input type="checkbox" id="evasion" name="evasion"> Evasion</label>
        </div>
        <button id="runBtn" type="submit">Run scan</button>
        <p class="hint">Use only on networks you own or have permission to scan. SYN/UDP/OS need root or CAP_NET_RAW.</p>
        </form>
        <h2>Results</h2>
        <pre id="output" class="terminal">Ready.</pre>
        </div>
        <script>
        const out=document.getElementById('output');
        const btn=document.getElementById('runBtn');
        const dot=document.getElementById('dot');
        const st=document.getElementById('statusText');
        async function checkStatus(){try{const r=await fetch('/api/status');const j=await r.json();dot.classList.add('on');st.textContent='online - v'+(j.version||'')+' - '+r.status;}catch(e){st.textContent='offline';}}
        checkStatus();
        document.getElementById('scanForm').addEventListener('submit',async(e)=>{e.preventDefault();btn.disabled=true;out.textContent='Running...';const payload={targets:document.getElementById('targets').value.trim(),ports:document.getElementById('ports').value.trim(),scan_type:document.getElementById('scan_type').value,fast:document.getElementById('fast').checked,os:document.getElementById('os').checked,service:document.getElementById('service').checked,evasion:document.getElementById('evasion').checked,timeout:parseInt(document.getElementById('timeout').value,10)||1000,script:document.getElementById('script').value.trim()};if(payload.scan_type==='discovery'){payload.discover=true;}try{const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const t=await r.text();try{out.textContent=JSON.stringify(JSON.parse(t),null,2);}catch(_){out.textContent=(r.status>399?'Error '+r.status+': ':'')+t;}out.className='terminal '+(r.ok?'':'err');}catch(err){out.textContent='Request failed: '+err.message;out.className='terminal err';}btn.disabled=false;});
        </script>
        </body>
        </html>
        """);
}

fn handle_scan(client: i32, body: const u8[:]) {
    var targets: u8[>..] = [];
    var ports: u8[>..] = [];
    var scan_type: u8[>..] = [];
    var script_path: u8[>..] = [];
    let has_targets = json_string(body, "targets", targets);
    let has_ports = json_string(body, "ports", ports);
    let has_scan = json_string(body, "scan_type", scan_type);
    let has_script = json_string(body, "script", script_path);
    let fast_v, fast_found = json_bool(body, "fast");
    let os_v, os_found = json_bool(body, "os");
    let service_v, service_found = json_bool(body, "service");
    let evasion_v, evasion_found = json_bool(body, "evasion");
    let discover_v, discover_found = json_bool(body, "discover");
    let timeout_v, timeout_found = json_int(body, "timeout");
    var is_fast = false;
    var is_os = false;
    var is_service = false;
    var is_evasion = false;
    var discover = false;
    var timeout_ms: i64 = 1000;
    if fast_found && fast_v { is_fast = true; }
    if os_found && os_v { is_os = true; }
    if service_found && service_v { is_service = true; }
    if evasion_found && evasion_v { is_evasion = true; }
    if discover_found && discover_v { discover = true; }
    if timeout_found { timeout_ms = timeout_v; }
    if !has_scan || scan_type.len == 0 {
        scan_type.append("connect");
    }
    if is_discovery_type(scan_type) { discover = true; }
    if !has_targets || targets.len == 0 {
        var err: u8[>..] = [];
        error_json(err, "targets is required");
        send_response(client, 400, "application/json", err);
        return;
    }
    if !discover && (!has_ports || ports.len == 0) {
        var err: u8[>..] = [];
        error_json(err, "ports is required");
        send_response(client, 400, "application/json", err);
        return;
    }
    if !is_valid_scan_type(scan_type) {
        var err: u8[>..] = [];
        error_json(err, "invalid scan_type (expected connect, syn, udp, or discovery)");
        send_response(client, 400, "application/json", err);
        return;
    }
    if timeout_ms < 1 || timeout_ms > 60000 {
        var err: u8[>..] = [];
        error_json(err, "invalid timeout (expected 1..60000)");
        send_response(client, 400, "application/json", err);
        return;
    }
    let is_syn = scan_type == "syn";
    let is_udp = scan_type == "udp";
    if is_fast && (discover || !is_syn && scan_type != "connect") {
        var err: u8[>..] = [];
        error_json(err, "--fast requires connect scan");
        send_response(client, 400, "application/json", err);
        return;
    }
    if is_fast && (is_service || is_evasion || is_os) {
        var err: u8[>..] = [];
        error_json(err, "--fast cannot be combined with service, evasion, or os");
        send_response(client, 400, "application/json", err);
        return;
    }
    if is_os && !is_syn {
        var err: u8[>..] = [];
        error_json(err, "os requires syn scan");
        send_response(client, 400, "application/json", err);
        return;
    }
    if is_service && (discover || is_syn || is_udp) {
        var err: u8[>..] = [];
        error_json(err, "service requires connect scan");
        send_response(client, 400, "application/json", err);
        return;
    }
    if is_evasion && (discover || is_udp) {
        var err: u8[>..] = [];
        error_json(err, "evasion requires syn or connect scan");
        send_response(client, 400, "application/json", err);
        return;
    }
    var use_script = false;
    if has_script && script_path.len > 0 {
        use_script = true;
        if discover || is_udp {
            var err: u8[>..] = [];
            error_json(err, "script requires connect or syn scan");
            send_response(client, 400, "application/json", err);
            return;
        }
        if is_fast {
            var err: u8[>..] = [];
            error_json(err, "script cannot be combined with fast");
            send_response(client, 400, "application/json", err);
            return;
        }
        if is_service || is_os || is_evasion {
            var err: u8[>..] = [];
            error_json(err, "script cannot be combined with service, os, or evasion");
            send_response(client, 400, "application/json", err);
            return;
        }
        if script_path.len > 512 {
            var err: u8[>..] = [];
            error_json(err, "script path too long");
            send_response(client, 400, "application/json", err);
            return;
        }
    }
    let tl, tstatus = target::parse_mixed_target_list(targets);
    if tstatus != 0 {
        var err: u8[>..] = [];
        error_json(err, "invalid targets");
        send_response(client, 400, "application/json", err);
        return;
    }
    if !target::targets_allowed_mixed(tl) {
        var err: u8[>..] = [];
        error_json(err, "CIDR prefix too large; use /24 (IPv4) or /112 (IPv6) or smaller");
        send_response(client, 400, "application/json", err);
        return;
    }
    if !discover {
        let _prs, pok = target::parse_ports(ports);
        if !pok {
            var err: u8[>..] = [];
            error_json(err, "invalid ports");
            send_response(client, 400, "application/json", err);
            return;
        }
    }
    var targets_c: u8[1024] = [0; 1024];
    var ports_c: u8[512] = [0; 512];
    var scan_c: u8[32] = [0; 32];
    var script_c: u8[512] = [0; 512];
    if !copy_cstr(targets_c[..], targets) {
        var err: u8[>..] = [];
        error_json(err, "targets too long");
        send_response(client, 400, "application/json", err);
        return;
    }
    if !discover && !copy_cstr(ports_c[..], ports) {
        var err: u8[>..] = [];
        error_json(err, "ports too long");
        send_response(client, 400, "application/json", err);
        return;
    }
    if !copy_cstr(scan_c[..], scan_type) {
        var err: u8[>..] = [];
        error_json(err, "scan_type too long");
        send_response(client, 400, "application/json", err);
        return;
    }
    if use_script && !copy_cstr(script_c[..], script_path) {
        var err: u8[>..] = [];
        error_json(err, "script path too long");
        send_response(client, 400, "application/json", err);
        return;
    }
    var out_buf: u8[32768] = [0; 32768];
    var exit_buf: i32[1] = [0];
    let fast_i: i32 = if is_fast { 1 } else { 0 };
    let os_i: i32 = if is_os { 1 } else { 0 };
    let service_i: i32 = if is_service { 1 } else { 0 };
    let evasion_i: i32 = if is_evasion { 1 } else { 0 };
    let discover_i: i32 = if discover { 1 } else { 0 };
    let rc = almap_http_run_scan(targets_c[0], ports_c[0], scan_c[0], fast_i, os_i, service_i, evasion_i, discover_i, timeout_ms as i32, script_c[0], out_buf[0], out_buf.len as i32, exit_buf[0]);
    if rc < 0 {
        var err: u8[>..] = [];
        error_json(err, "failed to start scan");
        send_response(client, 500, "application/json", err);
        return;
    }
    let out_slice = out_buf[..rc as i64];
    if exit_buf[0] == 0 {
        if out_slice.len == 0 {
            send_response(client, 200, "application/json", "[]");
        } else {
            send_response(client, 200, "application/json", out_slice);
        }
        return;
    }
    var err2: u8[>..] = [];
    err2.append("{\"error\":\"");
    output::json_escape(err2, out_slice);
    err2.append("\",\"exit_code\":");
    format(err2, exit_buf[0]);
    err2.append("}");
    send_response(client, 500, "application/json", err2);
}

fn serve(port: i64) -> bool {
    if !valid_port(port) {
        print("error: invalid web port");
        return false;
    }
    let listen_fd = almap_http_listen(port as i32);
    if listen_fd < 0 {
        print("error: cannot listen on port ", port);
        return false;
    }
    print("ALmap Web UI listening on http://0.0.0.0:", port, "/ (Ctrl+C to stop)");
    loop {
        let client = almap_http_accept(listen_fd);
        if client < 0 { continue; }
        var req_buf: u8[8192] = [0; 8192];
        let n = almap_http_read(client, req_buf[0], req_buf.len as i32);
        if n <= 0 {
            almap_http_close(client);
            continue;
        }
        let req = req_buf[..n as i64];
        var method: u8[>..] = [];
        var path: u8[>..] = [];
        let ok = parse_request_line(req, method, path);
        if !ok {
            var err: u8[>..] = [];
            error_json(err, "bad request");
            send_response(client, 400, "application/json", err);
            almap_http_close(client);
            continue;
        }
        if is_status_request(method, path) {
            var body: u8[>..] = [];
            status_json(body);
            send_response(client, 200, "application/json", body);
        } else if is_scan_request(method, path) {
            handle_scan(client, extract_body(req));
        } else if is_index_request(method, path) {
            var body: u8[>..] = [];
            index_html(body);
            send_response(client, 200, "text/html; charset=utf-8", body);
        } else {
            var err: u8[>..] = [];
            error_json(err, "not found");
            send_response(client, 404, "application/json", err);
        }
        almap_http_close(client);
    }
}
