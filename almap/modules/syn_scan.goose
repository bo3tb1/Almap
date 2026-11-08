import modules.target;
import modules.connect_scan;
import modules.output;
import modules.ratelimit;
import modules.os_fingerprint;
import modules.evasion;
import modules.alscript;
namespace syn_scan;

// modules/syn_scan.goose - Steps 14,19: TCP SYN scan with text, JSON,
// table, or XML output, per-port rate limiting, and a bounded C
// pthread pool for the --workers > 1 path. Step 19 adds --os: matching
// SYN+ACKs feed a coarse per-host fingerprint classified in c/os.c.
// No host discovery, banner grabbing, NSE, evasion, or service
// detection. Uses C interop via extern fn (C is in c/raw.c,
// c/pool.c, and c/os.c, listed in almap.build). No heap, no GC, no
// lifetime annotations. Reuses connect_scan::PortState and state_name
// and state_from_code (Goose namespaces are public; qualified names
// work across modules once imported), so no enum is duplicated here.
// scan_syn (sequential) and scan_syn_parallel share only the pure
// byte mapping helper; the C pool reuses c/raw.c::almap_syn_probe.

extern fn almap_syn_can_raw() -> i32;
extern fn almap_local_ip_for(dst_be: u32) -> u32;
extern fn almap_syn_scan(src_be: u32, dst_be: u32, dst_port: i32, timeout_ms: i32) -> i32;
// Pool arrays: same verified pointer form as Step 10 (const i32& and
// u8& cross as int32_t* / uint8_t*); callers pass flat[0] and
// states_buf[0] over fixed i32[4096] / u8[4096] buffers. Slices
// cross as {data,len} structs and do not match this C signature.
extern fn almap_syn_scan_host(src_be: u32, dst_be: u32, ports: const i32&, port_count: i32, timeout_ms: i32, workers: i32, rate_per_sec: i32, states_out: u8&) -> i32;
// Step 19: same host scan plus a five-int fingerprint result:
// [os_class, ttl, window, option_bits, ip_id_behavior]. fp_out is a
// fixed i32[5] passed by first-element reference, the same verified
// pointer form used for the state buffer.
extern fn almap_syn_scan_host_os(src_be: u32, dst_be: u32, ports: const i32&, port_count: i32, timeout_ms: i32, workers: i32, rate_per_sec: i32, states_out: u8&, fp_out: i32&) -> i32;
// Step 21: evasion SYN probe. decoys is a fixed u32[5] passed by
// first-element reference; spoof_mac_bytes is a fixed u8[6] passed
// the same way. Both are ignored when their count/enabled flag is off.
extern fn almap_syn_probe_evasion(src_be: u32, dst_be: u32, dst_port: i32, timeout_ms: i32, fragment: i32, mtu: i32, decoys: const u32&, decoy_count: i32, spoof_mac_bytes: const u8&, spoof_mac_enabled: i32) -> i32;

fn can_raw() -> bool {
    almap_syn_can_raw() == 1
}

// Scan one port. src_be/dst_be are first-octet-high u32 (Target.ip
// form). C code 0..3 maps directly; 4 (permission) maps to Error
// via state_from_code, and the CLI pre-check should have caught it.
fn scan_one_syn(src_be: u32, dst_be: u32, port: i32, timeout_ms: i64) -> connect_scan::PortState {
    let tmo = timeout_ms as i32;
    let code = almap_syn_scan(src_be, dst_be, port, tmo);
    return connect_scan::state_from_code(code);
}

// Pure mapping for pool result bytes: 0..3 as before and 4
// (permission/raw unavailable) maps to Error through state_from_code.
fn state_name_from_byte(code: i32) -> const u8[:] {
    return connect_scan::state_name(connect_scan::state_from_code(code));
}

// Step 15: scans every target in input order (hosts ascending, ports in
// CLI order) inside one output document, sharing one rate limiter.
fn scan_syn(targets: target::TargetList, ports: target::PortRanges, timeout_ms: i64, json: bool, rate_per_sec: i64, table: bool, xml: bool) -> bool {
    var lim = ratelimit::limiter_new(rate_per_sec);
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
        let dst, ok2 = target::host_at(tgt, hi);
        if !ok2 {
            if xml { output::xml_end_scan(); } else if !table { output::end(json); }
            return false;
        }
        let src = almap_local_ip_for(dst);
        for range in ports {
            var p: i32 = range.lo;
            while p <= range.hi {
                ratelimit::limiter_wait(lim);
                let state = if src == 0 { connect_scan::PortState.Error } else { scan_one_syn(src, dst, p, timeout_ms) };
                var ip_text: u8[>..] = [];
                connect_scan::fmt_ip(ip_text, dst);
                if xml {
                    output::xml_emit_scan_result(ip_text, p, connect_scan::state_name(state), "syn", "");
                } else if table {
                    output::emit_table_row(ip_text, p, connect_scan::state_name(state), "syn", "");
                } else {
                    first = output::emit_result(json, first, ip_text, p, connect_scan::state_name(state), "syn");
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

// Parallel SYN scan (Step 12): one C pool call per host, then results
// emitted in deterministic host/port order. The C pool reuses the
// Step 10 bounded queue and shared rate limiter and calls
// c/raw.c::almap_syn_probe for each port, so packet building is not
// duplicated. If almap_local_ip_for() returns 0 for a host, every
// port is emitted as error without calling the pool (documented
// choice; the C function also maps src_be == 0 to error bytes).
// Step 15: same per-target loop; one C pool call per host, emitted in
// deterministic target/host/port order.
fn scan_syn_parallel(targets: target::TargetList, ports: target::PortRanges, timeout_ms: i64, json: bool, table: bool, workers: i64, rate_per_sec: i64, xml: bool) -> bool {
    var flat: i32[65536] = [0; 65536];
    let pcount, pok = connect_scan::expand_ports(ports, flat[..]);
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
        let dst, ok2 = target::host_at(tgt, hi);
        if !ok2 {
            if xml { output::xml_end_scan(); } else if !table { output::end(json); }
            return false;
        }
        var ip_text: u8[>..] = [];
        connect_scan::fmt_ip(ip_text, dst);
        let src = almap_local_ip_for(dst);
        if src == 0 {
            var i: i64 = 0;
            while i < pcount {
                let sname = state_name_from_byte(3);
                if xml {
                    output::xml_emit_scan_result(ip_text, flat[i], sname, "syn", "");
                } else if table {
                    output::emit_table_row(ip_text, flat[i], sname, "syn", "");
                } else {
                    first = output::emit_result(json, first, ip_text, flat[i], sname, "syn");
                }
                i++;
            }
        } else {
            var states_buf: u8[4096] = [0; 4096];
            let rc = almap_syn_scan_host(src, dst, flat[0], pcount as i32, timeout_ms as i32, workers as i32, rate_per_sec as i32, states_buf[0]);
            if rc != 0 {
                if xml { output::xml_end_scan(); } else if !table { output::end(json); }
                print("error: worker pool failed");
                return false;
            }
            var i: i64 = 0;
            while i < pcount {
                let sname = state_name_from_byte(states_buf[i]);
                if xml {
                    output::xml_emit_scan_result(ip_text, flat[i], sname, "syn", "");
                } else if table {
                    output::emit_table_row(ip_text, flat[i], sname, "syn", "");
                } else {
                    first = output::emit_result(json, first, ip_text, flat[i], sname, "syn");
                }
                i++;
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

// Step 19: SYN scan with --os. Uses the C host runner for both the
// parallel and the --workers 1 case, because the fingerprint must be
// aggregated over every SYN+ACK seen for one host before any row is
// emitted. Step 26 consults an external OsDB first, then falls back to
// the C class. Results are still deterministic: targets in input
// order, hosts ascending, ports in CLI order. Every row for a host
// carries that host's classification, or "unknown" when no SYN+ACK
// arrived (closed/timeout-only hosts cannot be fingerprinted).
fn scan_syn_os(targets: target::TargetList, ports: target::PortRanges, timeout_ms: i64, json: bool, table: bool, workers: i64, rate_per_sec: i64, xml: bool, db: os_fingerprint::OsDB&) -> bool {
    var flat: i32[65536] = [0; 65536];
    let pcount, pok = connect_scan::expand_ports(ports, flat[..]);
    if !pok {
        print("error: too many ports for worker pool (max 65535)");
        return false;
    }
    if xml {
        output::xml_begin_scan();
    } else if table {
        output::emit_table_header_os();
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
            let dst, ok2 = target::host_at(tgt, hi);
            if !ok2 {
                if xml { output::xml_end_scan(); } else if !table { output::end(json); }
                return false;
            }
            var ip_text: u8[>..] = [];
            connect_scan::fmt_ip(ip_text, dst);
            let src = almap_local_ip_for(dst);
            var states_buf: u8[4096] = [0; 4096];
            var fp: i32[5] = [0; 5];
            if src == 0 {
                var i: i64 = 0;
                while i < pcount {
                    states_buf[i] = 3;
                    i++;
                }
            } else {
                let rc = almap_syn_scan_host_os(src, dst, flat[0], pcount as i32, timeout_ms as i32, workers as i32, rate_per_sec as i32, states_buf[0], fp[0]);
                if rc != 0 {
                    if xml { output::xml_end_scan(); } else if !table { output::end(json); }
                    print("error: worker pool failed");
                    return false;
                }
            }
            // Step 31: after the SYN pool, run T1-T7+U1 (needs root)
            // for the probe-string-aware DB match. The T1 sample from
            // the pool is still the TTL/window/opts carrier; the extra
            // probes only add the signature column. No raw access or
            // no open/closed port means empty signature (old behavior).
            var probe_buf: u8[2048] = [0; 2048];
            var probe_len: i64 = 0;
            if src != 0 {
                var open_port: i32 = -1;
                var closed_port: i32 = -1;
                var pi: i64 = 0;
                while pi < pcount {
                    if states_buf[pi] == 0 && open_port < 0 { open_port = flat[pi]; }
                    if states_buf[pi] == 1 && closed_port < 0 { closed_port = flat[pi]; }
                    pi++;
                }
                if open_port > 0 || closed_port > 0 {
                    let pn = os_fingerprint::collect_probe_signature(src, dst, open_port, closed_port, timeout_ms, probe_buf[..]);
                    if pn >= 0 { probe_len = pn; }
                }
            }
            let os_name = if probe_len > 0 {
                os_fingerprint::classify_os_full(db, fp[1], fp[2], fp[3], fp[0], probe_buf[..probe_len])
            } else {
                os_fingerprint::classify_os(db, fp[1], fp[2], fp[3], fp[0])
            };
            var i: i64 = 0;
            while i < pcount {
                let sname = state_name_from_byte(states_buf[i]);
                if xml {
                    output::xml_emit_scan_result_os(ip_text, flat[i], sname, "syn", os_name);
                } else if table {
                    output::emit_table_row_os(ip_text, flat[i], sname, "syn", os_name);
                } else {
                    first = output::emit_result_os(json, first, ip_text, flat[i], sname, "syn", os_name);
                }
                i++;
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

// Step 21: sequential SYN scan with evasion. Decoys and MAC bytes are
// passed as fixed arrays; the u64 spoof MAC is unpacked to 6 bytes
// network order. Fragmentation/decoy/MTU/MAC only affect the raw
// packets in c/raw.c; output shape is unchanged.
fn scan_one_evasion(src_be: u32, dst_be: u32, port: i32, timeout_ms: i64, e: evasion::Evasion) -> connect_scan::PortState {
    var decoy_buf: u32[5] = [0; 5];
    decoy_buf[0] = e.decoy0;
    decoy_buf[1] = e.decoy1;
    decoy_buf[2] = e.decoy2;
    decoy_buf[3] = e.decoy3;
    decoy_buf[4] = e.decoy4;
    var mac_buf: u8[6] = [0; 6];
    mac_buf[0] = ((e.spoof_mac >> 40) & 255) as u8;
    mac_buf[1] = ((e.spoof_mac >> 32) & 255) as u8;
    mac_buf[2] = ((e.spoof_mac >> 24) & 255) as u8;
    mac_buf[3] = ((e.spoof_mac >> 16) & 255) as u8;
    mac_buf[4] = ((e.spoof_mac >> 8) & 255) as u8;
    mac_buf[5] = (e.spoof_mac & 255) as u8;
    let frag: i32 = if e.fragment { 1 } else { 0 };
    let mac_on: i32 = if e.spoof_mac_enabled { 1 } else { 0 };
    let code = almap_syn_probe_evasion(src_be, dst_be, port, timeout_ms as i32, frag, e.mtu as i32, decoy_buf[0], e.decoy_count as i32, mac_buf[0], mac_on);
    return connect_scan::state_from_code(code);
}

fn scan_syn_evasion(targets: target::TargetList, ports: target::PortRanges, timeout_ms: i64, json: bool, rate_per_sec: i64, table: bool, xml: bool, e: evasion::Evasion) -> bool {
    var lim = ratelimit::limiter_new(rate_per_sec);
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
            let dst, ok2 = target::host_at(tgt, hi);
            if !ok2 {
                if xml { output::xml_end_scan(); } else if !table { output::end(json); }
                return false;
            }
            let src = almap_local_ip_for(dst);
            for range in ports {
                var p: i32 = range.lo;
                while p <= range.hi {
                    ratelimit::limiter_wait(lim);
                    let state = if src == 0 { connect_scan::PortState.Error } else { scan_one_evasion(src, dst, p, timeout_ms, e) };
                    var ip_text: u8[>..] = [];
                    connect_scan::fmt_ip(ip_text, dst);
                    if xml {
                        output::xml_emit_scan_result(ip_text, p, connect_scan::state_name(state), "syn", "");
                    } else if table {
                        output::emit_table_row(ip_text, p, connect_scan::state_name(state), "syn", "");
                    } else {
                        first = output::emit_result(json, first, ip_text, p, connect_scan::state_name(state), "syn");
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

// Step 22: sequential SYN scan with an AlScript plugin. Only open
// ports run the plugin (the SYN probe completes a full connect in
// the plugin's own socket, so the script sees a real TCP state).
fn scan_syn_script(targets: target::TargetList, ports: target::PortRanges, timeout_ms: i64, json: bool, rate_per_sec: i64, table: bool, xml: bool, script_path: const u8[:]) -> bool {
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
            let dst, ok2 = target::host_at(tgt, hi);
            if !ok2 {
                if xml { output::xml_end_scan(); } else if !table { output::end(json); }
                return false;
            }
            let src = almap_local_ip_for(dst);
            for range in ports {
                var p: i32 = range.lo;
                while p <= range.hi {
                    ratelimit::limiter_wait(lim);
                    let state = if src == 0 { connect_scan::PortState.Error } else { scan_one_syn(src, dst, p, timeout_ms) };
                    let sname = connect_scan::state_name(state);
                    var script_buf: u8[1024] = [0; 1024];
                    var script_len: i64 = 0;
                    if sname == "open" {
                        let n = alscript::run_one(script_path[0], dst, p, timeout_ms, script_buf[..]);
                        if n > 0 {
                            script_len = connect_scan::clean_banner(script_buf[..n]);
                        }
                    }
                    let script_slice = script_buf[..script_len];
                    var ip_text: u8[>..] = [];
                    connect_scan::fmt_ip(ip_text, dst);
                    if xml {
                        output::xml_emit_scan_result_script(ip_text, p, sname, "syn", script_slice);
                    } else if table {
                        output::emit_table_row_script(ip_text, p, sname, "syn", script_slice);
                    } else {
                        first = output::emit_result_script(json, first, ip_text, p, sname, "syn", script_slice);
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
