import modules.target;
import modules.output;
import modules.ratelimit;
import modules.service;
import modules.alscript;
import modules.sigdb;
namespace connect_scan;

// modules/connect_scan.goose - Step 16: TCP connect scan with CIDR
// expansion, sequential only (scan_connect) plus a C pthread pool
// (scan_connect_parallel), text, JSON, table, or XML output, optional
// banners, optional basic service detection, and per-port rate limiting.
// Service detection (--service, Step 16) only runs on the sequential
// path and only for open ports; the CLI forces sequential when it is
// enabled. No SYN scan, discovery, OS fingerprinting, NSE, evasion, or
// service databases.
// Uses C interop via extern fn (C is in c/net.c, listed in almap.build).
// No heap, no GC, no lifetime annotations.
// scan_connect iterates hosts (ascending) and ports (CLI order),
// emitting one result immediately (no storing all results).
// Returns false if the CIDR is rejected by target enumeration.

enum PortState { Open, Closed, Timeout, Error }

// C bindings: Goose name is the C symbol. Types: int -> i32,
// unsigned int -> u32. AF_INET=2, SOCK_STREAM=1, IPPROTO_TCP=6.
// Banner buffer: the suggested u8[>..]& builder param crosses as a
// gs_rref runtime struct, not a raw unsigned char * (verified by
// generated C), and a fixed u8[256] cannot be passed to it. The
// documented pointer form u8& crosses as uint8_t * and matches the
// required C signature exactly, so it is used here with a fixed
// u8[256] buffer passed as buf[0].
extern fn almap_sock_create(domain: i32, kind: i32, protocol: i32) -> i32;
extern fn almap_sock_connect_timeout(fd: i32, addr_be: u32, port: i32, timeout_ms: i32) -> i32;
extern fn almap_sock_close(fd: i32) -> i32;
extern fn almap_sock_grab_banner(addr_be: u32, port: i32, timeout_ms: i32, out: u8&, out_cap: i32) -> i32;
// Pool buffers: ports/states are fixed arrays passed by first-element
// references (const i32& / u8& cross as int32_t* / uint8_t*, verified
// by generated C). Slices cross as {data,len} structs and do not
// match the required C pointer signature.
extern fn almap_connect_scan_host(addr_be: u32, ports: const i32&, port_count: i32, timeout_ms: i32, workers: i32, rate_per_sec: i32, states_out: u8&) -> i32;

// Step 20: C epoll engine. hosts_be and states_out are flat arrays;
// states_out has host_count * port_count bytes in host -> port order.
// max_concurrent bounds in-flight sockets and rate_per_sec is a token
// bucket (0 = unlimited). Both pointers use the verified first-element
// reference form (const u32& / u8&) so Goose passes raw C pointers.
extern fn almap_async_connect_scan(hosts_be: const u32&, host_count: i32, ports: const i32&, port_count: i32, timeout_ms: i32, max_concurrent: i32, rate_per_sec: i32, states_out: u8&) -> i32;
extern fn almap_async_errno_state(err: i32) -> i32;

// Pure wrappers over the C state mapping and the fast-path batch
// limits; unit-tested without network access.
fn async_errno_to_state(err: i32) -> i32 {
    return almap_async_errno_state(err);
}

fn fast_max_concurrent(jobs: i64) -> i32 {
    if jobs <= 0 { return 1; }
    if jobs >= 10000 { return 10000; }
    return jobs as i32;
}

// Number of hosts per C call so host_count * port_count <= 65536
// (the fixed states_buf in scan_connect_fast) and host_count <= 1024.
fn fast_batch_hosts(port_count: i64) -> i64 {
    if port_count <= 0 { return 1; }
    let by_states = 65536 / port_count;
    if by_states < 1 { return 1; }
    if by_states < 1024 { return by_states; }
    return 1024;
}

fn state_from_code(code: i32) -> PortState {
    match code {
        0 => PortState.Open,
        1 => PortState.Closed,
        2 => PortState.Timeout,
        _ => PortState.Error,
    }
}

fn state_name(s: PortState) -> const u8[:] {
    match s {
        Open => "open",
        Closed => "closed",
        Timeout => "timeout",
        Error => "error",
    }
}

fn fmt_ip(out: u8[>..]&, ip: u32) {
    format(out, ((ip >> 24) & 255), ".", ((ip >> 16) & 255), ".", ((ip >> 8) & 255), ".", (ip & 255));
}

// Scan one port on one IPv4 target. ip_be is Target.ip (first octet
// high). port is host order 1..65535. timeout_ms is validated 1..60000
// at the CLI; cast to i32 for C is safe for that range.
fn scan_one(ip_be: u32, port: i32, timeout_ms: i64) -> PortState {
    let fd = almap_sock_create(2, 1, 6);
    if fd < 0 { return PortState.Error; }
    let tmo = timeout_ms as i32;
    let code = almap_sock_connect_timeout(fd, ip_be, port, tmo);
    almap_sock_close(fd);
    return state_from_code(code);
}

// Trims trailing CR/LF from s in place and replaces remaining
// control bytes (< 0x20) with '.'; returns the trimmed length.
// s must be a writable slice over the fixed banner buffer.
fn clean_banner(s: u8[:]) -> i64 {
    var end = s.len;
    while end > 0 && (s[end - 1] == '\r' || s[end - 1] == '\n') { end--; }
    for i in 0..end {
        if s[i] < 32 { s[i] = '.'; }
    }
    return end;
}

// Step 15: scans the whole target list in input order (targets, then
// hosts ascending, then ports in CLI order) inside one output document.
// Step 16: when service_mode is true, every open port is probed with
// modules/service.goose and the result is emitted as an optional
// service field; empty service text omits the text/JSON/XML field and
// leaves the table column empty.
fn scan_connect(targets: target::TargetList, ports: target::PortRanges, timeout_ms: i64, json: bool, banners: bool, rate_per_sec: i64, table: bool, xml: bool, service_mode: bool, db: sigdb::SigDB&) -> bool {
    var lim = ratelimit::limiter_new(rate_per_sec);
    if xml {
        output::xml_begin_scan();
    } else if table {
        if service_mode {
            output::emit_table_header_service();
        } else {
            output::emit_table_header(false);
        }
    } else {
        output::begin(json);
    }
    var first = true;
    for tgt in targets {
        let cnt, ok = target::usable_host_count(tgt);
        if !ok {
            if xml { output::xml_end_scan(); } else if !table { output::end(json); }
            return false;
        }
        var hi: i64 = 0;
    while hi < cnt {
        let ip, ok2 = target::host_at(tgt, hi);
        if !ok2 {
            if xml { output::xml_end_scan(); } else if !table { output::end(json); }
            return false;
        }
        for range in ports {
            var p: i32 = range.lo;
            while p <= range.hi {
                ratelimit::limiter_wait(lim);
                let state = scan_one(ip, p, timeout_ms);
                var ip_text: u8[>..] = [];
                fmt_ip(ip_text, ip);
                let sname = state_name(state);
                if service_mode {
                    var svc_buf: u8[64] = [0; 64];
                    var svc_len: i64 = 0;
                    var ban_buf: u8[256] = [0; 256];
                    var ban_len: i64 = 0;
                    if sname == "open" {
                        svc_len = service::detect(ip, p, timeout_ms, svc_buf[..], db);
                        if banners {
                            let tmo = timeout_ms as i32;
                            let n = almap_sock_grab_banner(ip, p, tmo, ban_buf[0], 256);
                            if n > 0 {
                                ban_len = clean_banner(ban_buf[..n]);
                            }
                        }
                    }
                    let svc_slice = svc_buf[..svc_len];
                    let ban_slice = ban_buf[..ban_len];
                    if xml {
                        output::xml_emit_scan_result_full(ip_text, p, sname, "connect", ban_slice, svc_slice);
                    } else if table {
                        output::emit_table_row_service(ip_text, p, sname, "connect", svc_slice, ban_slice);
                    } else {
                        first = output::emit_result_full(json, first, ip_text, p, sname, "connect", ban_slice, svc_slice);
                    }
                } else if xml {
                    if banners && sname == "open" {
                        var buf: u8[256] = [0; 256];
                        let tmo = timeout_ms as i32;
                        let n = almap_sock_grab_banner(ip, p, tmo, buf[0], 256);
                        if n > 0 {
                            let blen = clean_banner(buf[..n]);
                            let banner_slice = buf[..blen];
                            output::xml_emit_scan_result(ip_text, p, sname, "connect", banner_slice);
                        } else {
                            output::xml_emit_scan_result(ip_text, p, sname, "connect", "");
                        }
                    } else {
                        output::xml_emit_scan_result(ip_text, p, sname, "connect", "");
                    }
                } else if table {
                    if banners && sname == "open" {
                        var buf: u8[256] = [0; 256];
                        let tmo = timeout_ms as i32;
                        let n = almap_sock_grab_banner(ip, p, tmo, buf[0], 256);
                        if n > 0 {
                            let blen = clean_banner(buf[..n]);
                            let banner_slice = buf[..blen];
                            output::emit_table_row(ip_text, p, sname, "connect", banner_slice);
                        } else {
                            output::emit_table_row(ip_text, p, sname, "connect", "");
                        }
                    } else {
                        output::emit_table_row(ip_text, p, sname, "connect", "");
                    }
                } else if banners && sname == "open" {
                    var buf: u8[256] = [0; 256];
                    let tmo = timeout_ms as i32;
                    let n = almap_sock_grab_banner(ip, p, tmo, buf[0], 256);
                    if n > 0 {
                        let blen = clean_banner(buf[..n]);
                        let banner_slice = buf[..blen];
                        first = output::emit_result_banner(json, first, ip_text, p, sname, "connect", banner_slice);
                    } else {
                        first = output::emit_result_banner(json, first, ip_text, p, sname, "connect", "");
                    }
                } else {
                    first = output::emit_result(json, first, ip_text, p, sname, "connect");
                }
                p++;
            }
        }
        hi++;
        }
    }
    if xml {
        output::xml_end_scan();
    } else if !table {
        output::end(json);
    }
    return true;
}

// Step 18: limited IPv6 connect probe. The 16 address bytes are passed
// by first-element reference over a fixed u8[16], matching the C
// const unsigned char * parameter (same verified pointer form as the
// banner buffer). c/net6.c builds the sockaddr_in6 itself.
extern fn almap6_sock_connect_timeout(addr16: const u8&, port: i32, timeout_ms: i32) -> i32;

// IPv6 TCP connect probe for one port: 0 open, 1 closed, 2 timeout,
// 3 error. Only --scan connect (this file) and --discover (via
// discovery::tcp_ping6, which reuses this helper) use it.
fn scan_one6(t6: target::Target6, port: i32, timeout_ms: i64) -> PortState {
    var addr: u8[16] = [0; 16];
    addr[0] = (t6.g0 / 256) as u8;
    addr[1] = (t6.g0 % 256) as u8;
    addr[2] = (t6.g1 / 256) as u8;
    addr[3] = (t6.g1 % 256) as u8;
    addr[4] = (t6.g2 / 256) as u8;
    addr[5] = (t6.g2 % 256) as u8;
    addr[6] = (t6.g3 / 256) as u8;
    addr[7] = (t6.g3 % 256) as u8;
    addr[8] = (t6.g4 / 256) as u8;
    addr[9] = (t6.g4 % 256) as u8;
    addr[10] = (t6.g5 / 256) as u8;
    addr[11] = (t6.g5 % 256) as u8;
    addr[12] = (t6.g6 / 256) as u8;
    addr[13] = (t6.g6 % 256) as u8;
    addr[14] = (t6.g7 / 256) as u8;
    addr[15] = (t6.g7 % 256) as u8;
    let tmo = timeout_ms as i32;
    let code = almap6_sock_connect_timeout(addr[0], port, tmo);
    return state_from_code(code);
}

fn close_scan_doc(xml: bool, table: bool, json: bool) {
    if xml {
        output::xml_end_scan();
    } else if !table {
        output::end(json);
    }
}

// Step 18: connect scan over a mixed IPv4/IPv6 target list, in input
// order, hosts ascending, ports in CLI order, one output document.
// Banners and service detection are not supported for IPv6, so the CLI
// only takes this path when both are off; IPv4 entries emit the plain
// Step 5 fields (empty banner). Text and table bracket IPv6 as
// "[addr]:port"; JSON/XML use the plain address.
fn scan_connect_mixed(targets: target::MixedTargetList, ports: target::PortRanges, timeout_ms: i64, json: bool, rate_per_sec: i64, table: bool, xml: bool) -> bool {
    var lim = ratelimit::limiter_new(rate_per_sec);
    if xml {
        output::xml_begin_scan();
    } else if table {
        output::emit_table_header(false);
    } else {
        output::begin(json);
    }
    var first = true;
    for entry in targets {
        if entry.v6 {
            let cnt, ok = target::usable_host_count6(entry.t6);
            if !ok {
                close_scan_doc(xml, table, json);
                return false;
            }
            var hi: i64 = 0;
            while hi < cnt {
                let host6, ok2 = target::target6_host_at(entry.t6, hi);
                if !ok2 {
                    close_scan_doc(xml, table, json);
                    return false;
                }
                var plain: u8[>..] = [];
                target::format_ipv6(plain, host6);
                var brack: u8[>..] = [];
                target::format_ipv6_bracket(brack, host6);
                for range in ports {
                    var p: i32 = range.lo;
                    while p <= range.hi {
                        ratelimit::limiter_wait(lim);
                        let state = scan_one6(host6, p, timeout_ms);
                        let sname = state_name(state);
                        if xml {
                            output::xml_emit_scan_result(plain, p, sname, "connect", "");
                        } else if table {
                            output::emit_table_row(brack, p, sname, "connect", "");
                        } else if json {
                            first = output::emit_result(true, first, plain, p, sname, "connect");
                        } else {
                            first = output::emit_result(false, first, brack, p, sname, "connect");
                        }
                        p++;
                    }
                }
                hi++;
            }
        } else {
            let cnt, ok = target::usable_host_count(entry.t4);
            if !ok {
                close_scan_doc(xml, table, json);
                return false;
            }
            var hi: i64 = 0;
            while hi < cnt {
                let ip, ok2 = target::host_at(entry.t4, hi);
                if !ok2 {
                    close_scan_doc(xml, table, json);
                    return false;
                }
                var ip_text: u8[>..] = [];
                fmt_ip(ip_text, ip);
                for range in ports {
                    var p: i32 = range.lo;
                    while p <= range.hi {
                        ratelimit::limiter_wait(lim);
                        let state = scan_one(ip, p, timeout_ms);
                        let sname = state_name(state);
                        if xml {
                            output::xml_emit_scan_result(ip_text, p, sname, "connect", "");
                        } else if table {
                            output::emit_table_row(ip_text, p, sname, "connect", "");
                        } else {
                            first = output::emit_result(json, first, ip_text, p, sname, "connect");
                        }
                        p++;
                    }
                }
                hi++;
            }
        }
    }
    close_scan_doc(xml, table, json);
    return true;
}

// Expands ports into out (a slice over a fixed i32 array) in CLI
// order. Returns the port count, or 0,false when it exceeds out.len.
fn expand_ports(ports: target::PortRanges, out: i32[:]) -> i64, bool {
    var cnt: i64 = 0;
    for range in ports {
        var p: i32 = range.lo;
        while p <= range.hi {
            if cnt >= out.len { return 0, false; }
            out[cnt] = p;
            cnt++;
            p++;
        }
    }
    return cnt, true;
}

// Step 15: scans every target in input order with one C pool call per
// host. Banners are not supported on this path (the CLI keeps banners
// sequential). Step 11 adds table mode (empty banner column); Step 14
// adds XML (also with an empty banner).
fn scan_connect_parallel(targets: target::TargetList, ports: target::PortRanges, timeout_ms: i64, json: bool, workers: i64, rate_per_sec: i64, table: bool, xml: bool) -> bool {
    var flat: i32[65536] = [0; 65536];
    let pcount, pok = expand_ports(ports, flat[..]);
    if !pok {
        print("error: too many ports for worker pool (max 65535)");
        return false;
    }
    if xml {
        output::xml_begin_scan();
    } else if table {
        output::emit_table_header(false);
    } else {
        output::begin(json);
    }
    var first = true;
    for tgt in targets {
        let cnt, ok = target::usable_host_count(tgt);
        if !ok {
            if xml { output::xml_end_scan(); } else if !table { output::end(json); }
            return false;
        }
        var hi: i64 = 0;
        while hi < cnt {
        let ip, ok2 = target::host_at(tgt, hi);
        if !ok2 {
            if xml { output::xml_end_scan(); } else if !table { output::end(json); }
            return false;
        }
        var states_buf: u8[65536] = [0; 65536];
        let rc = almap_connect_scan_host(ip, flat[0], pcount as i32, timeout_ms as i32, workers as i32, rate_per_sec as i32, states_buf[0]);
        if rc != 0 {
            if xml { output::xml_end_scan(); } else if !table { output::end(json); }
            print("error: worker pool failed");
            return false;
        }
        var ip_text: u8[>..] = [];
        fmt_ip(ip_text, ip);
        for i in 0..pcount {
            let st = state_from_code(states_buf[i]);
            if xml {
                output::xml_emit_scan_result(ip_text, flat[i], state_name(st), "connect", "");
            } else if table {
                output::emit_table_row(ip_text, flat[i], state_name(st), "connect", "");
            } else {
                first = output::emit_result(json, first, ip_text, flat[i], state_name(st), "connect");
            }
        }
        hi++;
        }
    }
    if xml {
        output::xml_end_scan();
    } else if !table {
        output::end(json);
    }
    return true;
}

// Step 20: asynchronous IPv4 connect scan using the C epoll engine.
// Hosts are processed in input order and ascending within a CIDR; each
// batch fills states_buf in host -> port order, and results are emitted
// in that same order, so --fast preserves the deterministic ordering of
// the sequential and pthread-pool paths. Banners and service detection
// are rejected by the CLI (this engine scans connect results only), and
// IPv6 is rejected before this path runs.
fn scan_connect_fast(targets: target::TargetList, ports: target::PortRanges, timeout_ms: i64, json: bool, table: bool, xml: bool, rate_per_sec: i64) -> bool {
    var flat: i32[65536] = [0; 65536];
    let pcount, pok = expand_ports(ports, flat[..]);
    if !pok {
        print("error: too many ports for fast scanner (max 65535)");
        return false;
    }
    if xml {
        output::xml_begin_scan();
    } else if table {
        output::emit_table_header(false);
    } else {
        output::begin(json);
    }
    var first = true;
    let batch_hosts = fast_batch_hosts(pcount);
    for tgt in targets {
        let cnt, ok = target::usable_host_count(tgt);
        if !ok {
            if xml { output::xml_end_scan(); } else if !table { output::end(json); }
            return false;
        }
        var hi: i64 = 0;
        while hi < cnt {
            var hosts_buf: u32[1024] = [0; 1024];
            var states_buf: u8[65536] = [0; 65536];
            var bcount: i64 = 0;
            while bcount < batch_hosts && hi < cnt {
                let host, hok = target::host_at(tgt, hi);
                if !hok {
                    if xml { output::xml_end_scan(); } else if !table { output::end(json); }
                    return false;
                }
                hosts_buf[bcount] = host;
                bcount++;
                hi++;
            }
            let jobs = bcount * pcount;
            let rc = almap_async_connect_scan(hosts_buf[0], bcount as i32, flat[0], pcount as i32, timeout_ms as i32, fast_max_concurrent(jobs), rate_per_sec as i32, states_buf[0]);
            if rc != 0 {
                if xml { output::xml_end_scan(); } else if !table { output::end(json); }
                print("error: async connect engine failed");
                return false;
            }
            var j: i64 = 0;
            while j < jobs {
                let host_i = j / pcount;
                let ip = hosts_buf[host_i];
                var ip_text: u8[>..] = [];
                fmt_ip(ip_text, ip);
                var pj: i64 = 0;
                while pj < pcount {
                    let st = state_from_code(states_buf[j]);
                    if xml {
                        output::xml_emit_scan_result(ip_text, flat[pj], state_name(st), "connect", "");
                    } else if table {
                        output::emit_table_row(ip_text, flat[pj], state_name(st), "connect", "");
                    } else {
                        first = output::emit_result(json, first, ip_text, flat[pj], state_name(st), "connect");
                    }
                    pj++;
                    j++;
                }
            }
        }
    }
    if xml {
        output::xml_end_scan();
    } else if !table {
        output::end(json);
    }
    return true;
}

// Step 22: sequential connect scan with an AlScript plugin. Only open
// ports run the plugin; the cleaned plugin output is emitted as
// script_out (text/JSON/table/XML). script_path is a slice over the
// CLI's fixed NUL-terminated path buffer; re-slicing keeps the same
// backing bytes so script_path[0] is the C char* start. Banners and
// service detection are rejected by the CLI when --script is set.
fn scan_connect_script(targets: target::TargetList, ports: target::PortRanges, timeout_ms: i64, json: bool, rate_per_sec: i64, table: bool, xml: bool, script_path: const u8[:]) -> bool {
    var lim = ratelimit::limiter_new(rate_per_sec);
    if xml {
        output::xml_begin_scan();
    } else if table {
        output::emit_table_header_script();
    } else {
        output::begin(json);
    }
    var first = true;
    for tgt in targets {
        let cnt, ok = target::usable_host_count(tgt);
        if !ok {
            if xml { output::xml_end_scan(); } else if !table { output::end(json); }
            return false;
        }
        var hi: i64 = 0;
        while hi < cnt {
            let ip, ok2 = target::host_at(tgt, hi);
            if !ok2 {
                if xml { output::xml_end_scan(); } else if !table { output::end(json); }
                return false;
            }
            for range in ports {
                var p: i32 = range.lo;
                while p <= range.hi {
                    ratelimit::limiter_wait(lim);
                    let state = scan_one(ip, p, timeout_ms);
                    let sname = state_name(state);
                    var script_buf: u8[1024] = [0; 1024];
                    var script_len: i64 = 0;
                    if sname == "open" {
                        let n = alscript::run_one(script_path[0], ip, p, timeout_ms, script_buf[..]);
                        if n > 0 {
                            script_len = clean_banner(script_buf[..n]);
                        }
                    }
                    let script_slice = script_buf[..script_len];
                    var ip_text: u8[>..] = [];
                    fmt_ip(ip_text, ip);
                    if xml {
                        output::xml_emit_scan_result_script(ip_text, p, sname, "connect", script_slice);
                    } else if table {
                        output::emit_table_row_script(ip_text, p, sname, "connect", script_slice);
                    } else {
                        first = output::emit_result_script(json, first, ip_text, p, sname, "connect", script_slice);
                    }
                    p++;
                }
            }
            hi++;
        }
    }
    if xml {
        output::xml_end_scan();
    } else if !table {
        output::end(json);
    }
    return true;
}
