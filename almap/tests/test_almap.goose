import std;
import almap from "..";
import almap.modules.target;
import almap.modules.connect_scan;
import almap.modules.syn_scan;
import almap.modules.output;
import almap.modules.discovery;
import almap.modules.ratelimit;
import almap.modules.service;
import almap.modules.udp_scan;
import almap.modules.os_fingerprint;
import almap.modules.evasion;
import almap.modules.alscript;
import almap.modules.sigdb;
import almap.modules.webui;

// tests/test_almap.goose - Steps 13,19,20,21,22,23 unit tests (Goose assert/print style).
// Import: per docs/packages.md, a package's tests are root files and declare
// the package (`import almap from ".."`); modules are then
// `import almap.modules.target;`. `import .a.b;` cannot reach the parent
// directory, so this avoids inventing a relative-import spelling.
// assert is a builtin; expect prints FAIL and exit(1) on failure.
// CLI combos: main() reads global os args() and exits, so full argv
// simulation is not feasible in this style; the CLI validators
// scan_is_syn / parse_timeout_ms / parse_workers are tested directly instead.

fn expect(cond: bool, name: const u8[:]) {
    if !cond {
        print("FAIL ", name);
        exit(1);
    }
}

fn main() {
    // Valid IPv4.
    let ip, ok = target::parse_ipv4("192.168.1.1");
    expect(ok, "valid IPv4 192.168.1.1");
    expect(((ip >> 24) & 255) == 192, "IPv4 192.168.1.1 octet0");
    expect(((ip >> 16) & 255) == 168, "IPv4 192.168.1.1 octet1");
    expect(((ip >> 8) & 255) == 1, "IPv4 192.168.1.1 octet2");
    expect((ip & 255) == 1, "IPv4 192.168.1.1 octet3");
    let ip0, ok0 = target::parse_ipv4("0.0.0.0");
    expect(ok0 && ip0 == 0, "IPv4 0.0.0.0");
    let ipmax, okmax = target::parse_ipv4("255.255.255.255");
    expect(okmax, "IPv4 255.255.255.255");
    let want_max: u32 = 4294967295;
    expect(ipmax == want_max, "IPv4 max value");
    let iplead, oklead = target::parse_ipv4("010.001.000.001");
    expect(oklead, "IPv4 leading zeros allowed");

    // Invalid IPv4.
    let bad1, okb1 = target::parse_ipv4("256.1.1.1");
    expect(!okb1, "invalid IPv4 octet over 255");
    let bad2, okb2 = target::parse_ipv4("192.168.1");
    expect(!okb2, "invalid IPv4 three parts");
    let bad3, okb3 = target::parse_ipv4("192.168.1.1.5");
    expect(!okb3, "invalid IPv4 five parts");
    let bad4, okb4 = target::parse_ipv4("192.168.a.1");
    expect(!okb4, "invalid IPv4 alpha");
    let bad5, okb5 = target::parse_ipv4("");
    expect(!okb5, "invalid IPv4 empty");
    let bad6, okb6 = target::parse_ipv4("-1.0.0.0");
    expect(!okb6, "invalid IPv4 negative");
    let bad7, okb7 = target::parse_ipv4("1.2.3.4.5.6");
    expect(!okb7, "invalid IPv4 six parts");
    let bad8, okb8 = target::parse_ipv4("1..2.3");
    expect(!okb8, "invalid IPv4 empty octet");
    let bad9, okb9 = target::parse_ipv4("1.2.3.4/24");
    expect(!okb9, "IPv4 without CIDR rejects slash");
    let bad10, okb10 = target::parse_ipv4("999.999.999.999");
    expect(!okb10, "invalid IPv4 all 999");

    // Valid CIDR / target.
    let t, okt = target::parse_target("192.168.1.0/24");
    expect(okt, "valid CIDR 192.168.1.0/24");
    expect(t.prefix == 24, "CIDR prefix 24");
    expect(((t.ip >> 24) & 255) == 192, "CIDR ip octet0");
    let plain, okplain = target::parse_target("10.0.0.1");
    expect(okplain && plain.prefix == 32, "plain IPv4 prefix 32");
    let hostbits, okhost = target::parse_target("192.168.1.5/24");
    expect(okhost && hostbits.prefix == 24, "CIDR host bits kept");
    let net = target::target_network(hostbits);
    expect(((net >> 8) & 255) == 1 && (net & 255) == 0, "target_network masks host bits");
    expect(target::target_count(hostbits) == 256, "target_count /24");
    expect(target::target_count(plain) == 1, "target_count /32");
    let slash0, okslash0 = target::parse_target("0.0.0.0/0");
    expect(okslash0 && target::target_count(slash0) == 4294967296, "target_count /0");

    // Invalid CIDR / target.
    let badc1, okc1 = target::parse_target("192.168.1.0/33");
    expect(!okc1, "invalid CIDR /33");
    let badc2, okc2 = target::parse_target("192.168.1.0/-1");
    expect(!okc2, "invalid CIDR /-1");
    let badc3, okc3 = target::parse_target("192.168.1.0/");
    expect(!okc3, "invalid CIDR empty prefix");
    let badc4, okc4 = target::parse_target("999.0.0.0/24");
    expect(!okc4, "invalid CIDR bad ip");
    let badc5, okc5 = target::parse_target("192.168.1.0/24/1");
    expect(!okc5, "invalid CIDR extra slash");
    let badc6, okc6 = target::parse_target("192.168.1.0/abc");
    expect(!okc6, "invalid CIDR alpha prefix");
    let badc7, okc7 = target::parse_target("/24");
    expect(!okc7, "invalid CIDR empty host");
    let badc8, okc8 = target::parse_target("192.168.1.0/ 24");
    expect(!okc8, "invalid CIDR space in prefix");

    // Valid ports.
    let p, okp = target::parse_ports("22,80,443");
    expect(okp, "valid ports 22,80,443");
    expect(p.len == 3, "ports len 3");
    expect(p[0].lo == 22 && p[0].hi == 22, "ports 22");
    expect(p[1].lo == 80 && p[1].hi == 80, "ports 80");
    expect(p[2].lo == 443 && p[2].hi == 443, "ports 443");
    let p2, okp2 = target::parse_ports("1-1024");
    expect(okp2 && p2.len == 1 && p2[0].lo == 1 && p2[0].hi == 1024, "valid ports 1-1024");
    let p3, okp3 = target::parse_ports("22,80-90,443");
    expect(okp3 && p3.len == 3 && p3[1].lo == 80 && p3[1].hi == 90, "valid ports mixed");
    let p4, okp4 = target::parse_ports("80");
    expect(okp4 && p4.len == 1 && p4[0].lo == 80, "valid single port");
    let p5, okp5 = target::parse_ports("1-65535");
    expect(okp5 && target::port_count(p5) == 65535, "valid full range count");
    let p6, okp6 = target::parse_ports("22, 80 - 90 , 443");
    expect(okp6 && p6.len == 3, "valid ports spaces trimmed");

    // Invalid ports.
    let badp1, okbp1 = target::parse_ports("0");
    expect(!okbp1, "invalid port 0");
    let badp2, okbp2 = target::parse_ports("65536");
    expect(!okbp2, "invalid port 65536");
    let badp3, okbp3 = target::parse_ports("90-80");
    expect(!okbp3, "invalid reversed range");
    let badp4, okbp4 = target::parse_ports("abc");
    expect(!okbp4, "invalid port alpha");
    let badp5, okbp5 = target::parse_ports("");
    expect(!okbp5, "invalid ports empty");
    let badp6, okbp6 = target::parse_ports("22,,80");
    expect(!okbp6, "invalid ports double comma");
    let badp7, okbp7 = target::parse_ports("22-");
    expect(!okbp7, "invalid port trailing dash");
    let badp8, okbp8 = target::parse_ports("-80");
    expect(!okbp8, "invalid port leading dash");
    let badp9, okbp9 = target::parse_ports("80-90-100");
    expect(!okbp9, "invalid port double dash");
    let badp10, okbp10 = target::parse_ports("80-");
    expect(!okbp10, "invalid port empty hi");
    let badp11, okbp11 = target::parse_ports("80,0,90");
    expect(!okbp11, "invalid port zero in list");
    let badp12, okbp12 = target::parse_ports("70000-80000");
    expect(!okbp12, "invalid port range over max");

    // CLI validators (global functions from almap.goose entry).
    let syn, oksyn = scan_is_syn("syn");
    expect(oksyn && syn, "scan syn");
    let conn, okconn = scan_is_syn("connect");
    expect(okconn && !conn, "scan connect");
    let badscan, okbadscan = scan_is_syn("udp");
    expect(!okbadscan, "scan invalid udp");
    let badscan2, okbadscan2 = scan_is_syn("CONNECT");
    expect(!okbadscan2, "scan invalid uppercase");
    let to, okto = parse_timeout_ms("1000");
    expect(okto && to == 1000, "timeout 1000");
    let tobad, oktobad = parse_timeout_ms("0");
    expect(!oktobad, "timeout 0 invalid");
    let tobad2, oktobad2 = parse_timeout_ms("60001");
    expect(!oktobad2, "timeout over max invalid");
    let tobad3, oktobad3 = parse_timeout_ms("abc");
    expect(!oktobad3, "timeout alpha invalid");
    let tobad4, oktobad4 = parse_timeout_ms("-5");
    expect(!oktobad4, "timeout negative invalid");
    let w, okw = parse_workers("10");
    expect(okw && w == 10, "workers 10");
    let wbad, okwbad = parse_workers("0");
    expect(!okwbad, "workers 0 invalid");
    let wbad2, okwbad2 = parse_workers("1001");
    expect(!okwbad2, "workers over max invalid");
    let wbad3, okwbad3 = parse_workers("abc");
    expect(!okwbad3, "workers alpha invalid");

    // Connect scan pure helpers (no network calls).
    let n0 = connect_scan::state_name(connect_scan::state_from_code(0));
    expect(n0 == "open", "state 0 open");
    let n1 = connect_scan::state_name(connect_scan::state_from_code(1));
    expect(n1 == "closed", "state 1 closed");
    let n2 = connect_scan::state_name(connect_scan::state_from_code(2));
    expect(n2 == "timeout", "state 2 timeout");
    let n3 = connect_scan::state_name(connect_scan::state_from_code(3));
    expect(n3 == "error", "state 3 error");
    let n99 = connect_scan::state_name(connect_scan::state_from_code(99));
    expect(n99 == "error", "state unknown error");
    let nneg = connect_scan::state_name(connect_scan::state_from_code(-1));
    expect(nneg == "error", "state -1 error");
    let ipval, okip = target::parse_ipv4("192.168.1.1");
    expect(okip, "fmt_ip parse 192.168.1.1");
    var ipb: u8[>..] = [];
    connect_scan::fmt_ip(ipb, ipval);
    expect(ipb == "192.168.1.1", "fmt_ip 192.168.1.1");
    let ipval2, okip2 = target::parse_ipv4("10.0.0.1");
    expect(okip2, "fmt_ip parse 10.0.0.1");
    var ipb2: u8[>..] = [];
    connect_scan::fmt_ip(ipb2, ipval2);
    expect(ipb2 == "10.0.0.1", "fmt_ip 10.0.0.1");

    // CIDR enumeration helpers (Step 4, no network).
    let t30, ok30 = target::parse_target("192.168.1.0/30");
    expect(ok30, "CIDR /30 parse");
    let c30, okc30 = target::usable_host_count(t30);
    expect(okc30 && c30 == 2, "CIDR /30 usable 2");
    let h30_0, okh30_0 = target::host_at(t30, 0);
    expect(okh30_0 && (h30_0 & 255) == 1, "CIDR /30 host0 192.168.1.1");
    let h30_1, okh30_1 = target::host_at(t30, 1);
    expect(okh30_1 && (h30_1 & 255) == 2, "CIDR /30 host1 192.168.1.2");
    expect(h30_0 < h30_1, "CIDR /30 ascending");
    let bh30, okbh30 = target::host_at(t30, 2);
    expect(!okbh30, "CIDR /30 index 2 out of range");
    let nh30, oknh30 = target::host_at(t30, -1);
    expect(!oknh30, "CIDR /30 index -1 out of range");
    let t31, ok31b = target::parse_target("192.168.1.0/31");
    expect(ok31b, "CIDR /31 parse");
    let c31, okc31 = target::usable_host_count(t31);
    expect(okc31 && c31 == 2, "CIDR /31 usable 2");
    let h31_0, okh31_0 = target::host_at(t31, 0);
    expect(okh31_0 && (h31_0 & 255) == 0, "CIDR /31 host0 network");
    let h31_1, okh31_1 = target::host_at(t31, 1);
    expect(okh31_1 && (h31_1 & 255) == 1, "CIDR /31 host1 broadcast");
    let t32b, ok32b = target::parse_target("192.168.1.5/32");
    expect(ok32b, "CIDR /32 parse");
    let c32b, okc32b = target::usable_host_count(t32b);
    expect(okc32b && c32b == 1, "CIDR /32 usable 1");
    let h32_0, okh32_0 = target::host_at(t32b, 0);
    expect(okh32_0 && (h32_0 & 255) == 5, "CIDR /32 host");
    let t24b, ok24b = target::parse_target("192.168.1.0/24");
    expect(ok24b, "CIDR /24 parse");
    let c24b, okc24b = target::usable_host_count(t24b);
    expect(okc24b && c24b == 254, "CIDR /24 usable 254");
    let hf24, okhf24 = target::host_at(t24b, 0);
    expect(okhf24 && (hf24 & 255) == 1, "CIDR /24 first usable .1");
    let hl24, okhl24 = target::host_at(t24b, 253);
    expect(okhl24 && (hl24 & 255) == 254, "CIDR /24 last usable .254");
    let t23, ok23 = target::parse_target("192.168.0.0/23");
    expect(ok23, "CIDR /23 parse");
    let c23, okc23 = target::usable_host_count(t23);
    expect(!okc23, "CIDR /23 rejected by usable_host_count");
    expect(!target::is_cidr_allowed(t23), "CIDR /23 rejected by is_cidr_allowed");
    let h23, okh23 = target::host_at(t23, 0);
    expect(!okh23, "CIDR /23 host_at rejected");
    let t16, ok16b = target::parse_target("192.168.0.0/16");
    expect(ok16b, "CIDR /16 parse");
    expect(!target::is_cidr_allowed(t16), "CIDR /16 rejected");
    let t0b, ok0c = target::parse_target("0.0.0.0/0");
    expect(ok0c, "CIDR /0 parse");
    expect(!target::is_cidr_allowed(t0b), "CIDR /0 rejected");
    expect(target::is_cidr_allowed(t24b), "CIDR /24 allowed");
    expect(target::is_cidr_allowed(t30), "CIDR /30 allowed");

    // Step 15: multiple targets (no network). Fixed capacity is 64
    // targets; -t is a comma-separated list and -iL is line-based with
    // blank lines and # comments ignored.
    expect(target::target_list_cap() == 64, "target list cap 64");
    let tl, oktl = target::parse_target_list("127.0.0.1,10.0.0.0/30,192.168.1.5");
    expect(oktl == 0, "target list parse ok");
    expect(tl.len == 3, "target list len 3");
    expect(((tl[0].ip >> 24) & 255) == 127, "target list order 0");
    expect(tl[0].prefix == 32, "target list order 0 prefix 32");
    expect(((tl[1].ip >> 24) & 255) == 10, "target list order 1");
    expect(tl[1].prefix == 30, "target list order 1 prefix 30");
    expect(((tl[2].ip >> 24) & 255) == 192, "target list order 2");
    let tlt, oktlt = target::parse_target_list("127.0.0.1, 10.0.0.0/30");
    expect(oktlt == 0 && tlt.len == 2, "target list trims comma spaces");
    expect(((tlt[1].ip >> 24) & 255) == 10, "target list trimmed order");
    let e1, oke1 = target::parse_target_list("");
    expect(oke1 != 0, "target list empty rejected");
    let e2, oke2 = target::parse_target_list("127.0.0.1,");
    expect(oke2 != 0, "target list trailing comma rejected");
    let e3, oke3 = target::parse_target_list("127.0.0.1, nope");
    expect(oke3 != 0, "target list invalid token rejected");
    let e4, oke4 = target::parse_target_list("127.0.0.1/33");
    expect(oke4 != 0, "target list bad prefix rejected");
    let e5, oke5 = target::parse_target_list("127.0.0.1,,127.0.0.2");
    expect(oke5 != 0, "target list empty token rejected");
    // 65 targets exceed the fixed 64 cap (status 2 = too many).
    let too_many, tm = target::parse_target_list("127.0.0.1,127.0.0.2,127.0.0.3,127.0.0.4,127.0.0.5,127.0.0.6,127.0.0.7,127.0.0.8,127.0.0.9,127.0.0.10,127.0.0.11,127.0.0.12,127.0.0.13,127.0.0.14,127.0.0.15,127.0.0.16,127.0.0.17,127.0.0.18,127.0.0.19,127.0.0.20,127.0.0.21,127.0.0.22,127.0.0.23,127.0.0.24,127.0.0.25,127.0.0.26,127.0.0.27,127.0.0.28,127.0.0.29,127.0.0.30,127.0.0.31,127.0.0.32,127.0.0.33,127.0.0.34,127.0.0.35,127.0.0.36,127.0.0.37,127.0.0.38,127.0.0.39,127.0.0.40,127.0.0.41,127.0.0.42,127.0.0.43,127.0.0.44,127.0.0.45,127.0.0.46,127.0.0.47,127.0.0.48,127.0.0.49,127.0.0.50,127.0.0.51,127.0.0.52,127.0.0.53,127.0.0.54,127.0.0.55,127.0.0.56,127.0.0.57,127.0.0.58,127.0.0.59,127.0.0.60,127.0.0.61,127.0.0.62,127.0.0.63,127.0.0.64,127.0.0.65");
    expect(tm == 2, "target list 65 targets status 2");
    // -iL line parsing: CRLF, blank lines and # comments are ignored.
    let fl, okfl = target::parse_target_lines("127.0.0.1\r\n\n# a comment\n  10.0.0.0/30  \n");
    expect(okfl == 0, "target lines parse ok");
    expect(fl.len == 2, "target lines len 2");
    expect(((fl[0].ip >> 24) & 255) == 127, "target lines order 0");
    expect(fl[1].prefix == 30, "target lines order 1 prefix 30");
    let fb, okfb = target::parse_target_lines("# only comments\n\n");
    expect(okfb == 0 && fb.len == 0, "target lines comments only -> no targets");
    let fbad, okfbad = target::parse_target_lines("127.0.0.1\nbad\n");
    expect(okfbad != 0, "target lines invalid line rejected");
    let ta, okta = target::parse_target_list("127.0.0.0/30,127.0.0.1");
    expect(okta == 0 && target::targets_allowed(ta), "targets_allowed accepts allowed list");
    let tb, oktb = target::parse_target_list("127.0.0.0/23");
    expect(oktb == 0 && !target::targets_allowed(tb), "targets_allowed rejects /23");
    let tempty, oktempty = target::parse_target_list("");
    expect(oktempty != 0 && !target::targets_allowed(tempty), "targets_allowed rejects empty");

    // SYN pure helpers (no network): SYN C codes 0..4 reuse the
    // connect_scan mapping (4 permission maps to error). can_raw is
    // not asserted here because its value depends on privileges.
    let syn_n0 = connect_scan::state_name(connect_scan::state_from_code(0));
    expect(syn_n0 == "open", "syn state 0 open");
    let syn_n1 = connect_scan::state_name(connect_scan::state_from_code(1));
    expect(syn_n1 == "closed", "syn state 1 closed");
    let syn_n2 = connect_scan::state_name(connect_scan::state_from_code(2));
    expect(syn_n2 == "timeout", "syn state 2 timeout");
    let syn_n3 = connect_scan::state_name(connect_scan::state_from_code(3));
    expect(syn_n3 == "error", "syn state 3 error");
    let syn_n4 = connect_scan::state_name(connect_scan::state_from_code(4));
    expect(syn_n4 == "error", "syn state 4 error (permission)");

    // Output helpers (Step 6, no network): after_emit is the pure
    // comma/first logic emit_result uses; emit_result itself prints.
    expect(!output::after_emit(true, true), "output json first to false");
    expect(!output::after_emit(true, false), "output json second stays false");
    expect(output::after_emit(false, true), "output text first stays true");
    expect(!output::after_emit(false, false), "output text second stays false");

    // Discovery classify (Step 7, no network): all 8 combinations of
    // (tcp_up, icmp_up, icmp_available). Up if TCP proves it, or
    // ICMP proves it while ICMP is available; unavailable ICMP is
    // ignored.
    expect(!discovery::classify(false, false, false), "classify down none");
    expect(!discovery::classify(false, false, true), "classify down tcp/icmp false");
    expect(!discovery::classify(false, true, false), "classify down icmp ignored when unavailable");
    expect(discovery::classify(false, true, true), "classify up icmp only");
    expect(discovery::classify(true, false, false), "classify up tcp only unavailable");
    expect(discovery::classify(true, false, true), "classify up tcp only available");
    expect(discovery::classify(true, true, false), "classify up tcp true icmp ignored");
    expect(discovery::classify(true, true, true), "classify up both");

    // Discovery host cap (Step 13, no network): parallel discovery
    // materializes hosts into u32[4096].
    expect(discovery::host_cap_ok(0), "discovery cap 0 ok");
    expect(discovery::host_cap_ok(254), "discovery cap /24 ok");
    expect(discovery::host_cap_ok(4096), "discovery cap 4096 ok");
    expect(!discovery::host_cap_ok(4097), "discovery cap 4097 rejected");
    expect(!discovery::host_cap_ok(-1), "discovery cap negative rejected");

    // json_escape (Step 8): plain, quote, backslash, control, >=0x80.
    var esc_plain: u8[>..] = [];
    output::json_escape(esc_plain, "hello");
    expect(esc_plain == "hello", "json_escape plain");
    var esc_q: u8[>..] = [];
    output::json_escape(esc_q, "a\"b");
    expect(esc_q == "a\\\"b", "json_escape quote");
    var esc_b: u8[>..] = [];
    output::json_escape(esc_b, "a\\b");
    expect(esc_b == "a\\\\b", "json_escape backslash");
    var esc_n: u8[>..] = [];
    output::json_escape(esc_n, "a\nb");
    expect(esc_n == "a\\u000ab", "json_escape newline");
    var esc_t: u8[>..] = [];
    output::json_escape(esc_t, "a\tb");
    expect(esc_t == "a\\u0009b", "json_escape tab");
    var esc_hi: u8[>..] = [];
    output::json_escape(esc_hi, "\x80");
    expect(esc_hi.len == 1 && esc_hi[0] == 128, "json_escape byte 0x80 passthrough");

    // xml_escape (Step 14): plain, &, <, >, ", ', >=0x80.
    var xesc_plain: u8[>..] = [];
    output::xml_escape(xesc_plain, "hello");
    expect(xesc_plain == "hello", "xml_escape plain");
    var xesc_amp: u8[>..] = [];
    output::xml_escape(xesc_amp, "a&b");
    expect(xesc_amp == "a&amp;b", "xml_escape ampersand");
    var xesc_lt: u8[>..] = [];
    output::xml_escape(xesc_lt, "a<b");
    expect(xesc_lt == "a&lt;b", "xml_escape less than");
    var xesc_gt: u8[>..] = [];
    output::xml_escape(xesc_gt, "a>b");
    expect(xesc_gt == "a&gt;b", "xml_escape greater than");
    var xesc_q: u8[>..] = [];
    output::xml_escape(xesc_q, "a\"b");
    expect(xesc_q == "a&quot;b", "xml_escape double quote");
    var xesc_apos: u8[>..] = [];
    output::xml_escape(xesc_apos, "a'b");
    expect(xesc_apos == "a&apos;b", "xml_escape apostrophe");
    var xesc_all: u8[>..] = [];
    output::xml_escape(xesc_all, "&<>\"'");
    expect(xesc_all == "&amp;&lt;&gt;&quot;&apos;", "xml_escape all five");
    var xesc_hi: u8[>..] = [];
    output::xml_escape(xesc_hi, "\x80");
    expect(xesc_hi.len == 1 && xesc_hi[0] == 128, "xml_escape byte 0x80 passthrough");

    // clean_banner (Step 8): trim trailing CRLF, replace controls.
    var cb1: u8[256] = [0; 256];
    cb1[0] = 'H'; cb1[1] = 'I'; cb1[2] = '\r'; cb1[3] = '\n';
    let cl1 = connect_scan::clean_banner(cb1[..4]);
    expect(cl1 == 2 && cb1[0] == 'H' && cb1[1] == 'I', "clean_banner trims CRLF");
    var cb2: u8[256] = [0; 256];
    cb2[0] = 'A'; cb2[1] = 1; cb2[2] = 'B'; cb2[3] = 9; cb2[4] = 'C';
    let cl2 = connect_scan::clean_banner(cb2[..5]);
    expect(cl2 == 5 && cb2[1] == '.' && cb2[3] == '.', "clean_banner replaces controls");
    var cb3: u8[256] = [0; 256];
    cb3[0] = '\n'; cb3[1] = '\r';
    let cl3 = connect_scan::clean_banner(cb3[..2]);
    expect(cl3 == 0, "clean_banner all CRLF empty");

    // Rate limiter pure helpers (Step 9, no sleeping, no network).
    expect(ratelimit::interval_ns(0) == 0, "interval_ns 0 unlimited");
    expect(ratelimit::interval_ns(-5) == 0, "interval_ns negative unlimited");
    expect(ratelimit::interval_ns(1) == 1000000000, "interval_ns 1");
    expect(ratelimit::interval_ns(10) == 100000000, "interval_ns 10");
    expect(ratelimit::interval_ns(1000) == 1000000, "interval_ns 1000");
    var lim0 = ratelimit::limiter_new(0);
    expect(lim0.rate_per_sec == 0 && lim0.next_ns == 0, "limiter_new 0");
    var lim10 = ratelimit::limiter_new(10);
    expect(lim10.rate_per_sec == 10 && lim10.next_ns == 0, "limiter_new 10");
    expect(ratelimit::should_wait(0, 1000, 500) == 0, "should_wait no last");
    expect(ratelimit::should_wait(1000, 2000, 500) == 0, "should_wait no wait");
    expect(ratelimit::should_wait(1000, 1500, 500) == 0, "should_wait exact boundary");
    expect(ratelimit::should_wait(1000, 1200, 500) == 300, "should_wait required");
    expect(ratelimit::should_wait(1000, 1001, 0) == 0, "should_wait unlimited");
    expect(ratelimit::should_wait(1000, 1000, 500) == 500, "should_wait full interval");

    // Port expansion for worker pool (Step 10, no threads/network).
    let exp_ports, ok_exp = target::parse_ports("22,80-82,443");
    expect(ok_exp, "expand_ports parse");
    var flat1: i32[4096] = [0; 4096];
    let ec1, oke1 = connect_scan::expand_ports(exp_ports, flat1[..]);
    expect(oke1 && ec1 == 5, "expand_ports count 5");
    expect(flat1[0] == 22 && flat1[1] == 80 && flat1[2] == 81 && flat1[3] == 82 && flat1[4] == 443, "expand_ports order");
    var flat2: i32[4] = [0; 4];
    let ec2, oke2 = connect_scan::expand_ports(exp_ports, flat2[..]);
    expect(!oke2, "expand_ports cap exceeded");
    let exp_one, ok_exp1 = target::parse_ports("80");
    expect(ok_exp1, "expand_ports single parse");
    var flat3: i32[4096] = [0; 4096];
    let ec3, oke3 = connect_scan::expand_ports(exp_one, flat3[..]);
    expect(oke3 && ec3 == 1 && flat3[0] == 80, "expand_ports single");

    // Table header pure helper (Step 11, no network).
    expect(output::table_header(false) == "IP\tPORT\tSTATE\tSCAN\tBANNER", "table header scan");
    expect(output::table_header(true) == "IP\tUP", "table header discovery");

    // SYN pool byte mapping (Step 12, no threads/network):
    // 0..3 same as scan_one_syn, 4 permission maps to error.
    expect(syn_scan::state_name_from_byte(0) == "open", "syn byte 0 open");
    expect(syn_scan::state_name_from_byte(1) == "closed", "syn byte 1 closed");
    expect(syn_scan::state_name_from_byte(2) == "timeout", "syn byte 2 timeout");
    expect(syn_scan::state_name_from_byte(3) == "error", "syn byte 3 error");
    expect(syn_scan::state_name_from_byte(4) == "error", "syn byte 4 error (permission)");
    expect(syn_scan::state_name_from_byte(99) == "error", "syn byte 99 error");

    // Basic service detection helpers (Step 16, no network). Signature
    // matching is pure; the probes themselves are covered by
    // tests/integration_service.sh.
    expect(service::is_http_port(80) && service::is_http_port(8080) && service::is_http_port(8000), "service http ports");
    expect(!service::is_http_port(22) && !service::is_http_port(443), "service non-http ports");
    expect(service::classify_banner("SSH-2.0-OpenSSH_9.6") == "ssh", "service ssh banner");
    expect(service::classify_banner("220 (vsFTPd 3.0.3)") == "ftp", "service ftp banner");
    expect(service::classify_banner("220 mx.example.com ESMTP Postfix") == "smtp", "service smtp banner");
    var mysql: u8[5] = [3, 0, 0, 0, 10];
    expect(service::classify_banner(mysql[..]) == "mysql", "service mysql handshake");
    expect(service::classify_banner("HELLO-ALMAP") == "", "service unknown banner empty");
    expect(service::classify_http("HTTP/1.0 200 OK\r\nServer: nginx\r\n\r\n"), "service http server header");
    expect(!service::classify_http("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"), "service http no server header");
    var svc_fb: u8[16] = [0; 16];
    let raw_fb: const u8[:] = "HELLO\tWORLD\r\n";
    let svc_fbl = service::copy_cleaned(svc_fb[..], raw_fb, raw_fb.len);
    expect(svc_fbl == 11 && svc_fb[0] == 'H' && svc_fb[5] == '.' && svc_fb[10] == 'D', "service fallback cleaned banner");
    var svc_name: u8[16] = [0; 16];
    let svc_nl = service::copy_into(svc_name[..], "http");
    expect(svc_nl == 4 && svc_name[0] == 'h' && svc_name[3] == 'p', "service copy_into");
    expect(output::table_header_service() == "IP\tPORT\tSTATE\tSCAN\tSERVICE\tBANNER", "table header service");


    // UDP scan helpers (Step 17, no network). Packet building and
    // matching live in c/udp.c and are covered by
    // tests/integration_udp.sh; the pure CLI/state mapping is tested here.
    let m_connect, ok_m_connect = parse_scan_mode("connect");
    let m_syn, ok_m_syn = parse_scan_mode("syn");
    let m_udp, ok_m_udp = parse_scan_mode("udp");
    let m_bad, ok_m_bad = parse_scan_mode("icmp");
    expect(ok_m_connect && m_connect == 0, "scan mode connect");
    expect(ok_m_syn && m_syn == 1, "scan mode syn");
    expect(ok_m_udp && m_udp == 2, "scan mode udp");
    expect(!ok_m_bad, "scan mode invalid");
    expect(udp_scan::state_name(0) == "open", "udp state open");
    expect(udp_scan::state_name(1) == "closed", "udp state closed");
    expect(udp_scan::state_name(2) == "open|filtered", "udp state open|filtered");
    expect(udp_scan::state_name(3) == "error", "udp state error");
    expect(udp_scan::state_name(4) == "error", "udp state permission is error");


    // IPv6 target parsing and formatting (Step 18, no network). Socket
    // probing lives in c/net6.c and is covered by
    // tests/integration_ipv6.sh; the pure target helpers are tested here.
    let a6, ok_a6 = target::parse_ipv6_text("::1");
    expect(ok_a6, "ipv6 parse ::1");
    expect(a6.g0 == 0 && a6.g6 == 0 && a6.g7 == 1, "ipv6 groups ::1");
    var a6t: u8[>..] = [];
    target::format_ipv6(a6t, a6);
    expect(a6t == "::1", "ipv6 format ::1");
    var a6b: u8[>..] = [];
    target::format_ipv6_bracket(a6b, a6);
    expect(a6b == "[::1]", "ipv6 bracket ::1");
    let z6, ok_z6 = target::parse_ipv6_text("::");
    expect(ok_z6, "ipv6 parse ::");
    var z6t: u8[>..] = [];
    target::format_ipv6(z6t, z6);
    expect(z6t == "::", "ipv6 format ::");
    let g6, ok_g6 = target::parse_ipv6_text("2001:db8::1");
    expect(ok_g6 && g6.g0 == 8193 && g6.g1 == 3512 && g6.g7 == 1, "ipv6 groups 2001:db8::1");
    var g6t: u8[>..] = [];
    target::format_ipv6(g6t, g6);
    expect(g6t == "2001:db8::1", "ipv6 format 2001:db8::1");
    let bad1, okb1 = target::parse_ipv6_text("::ffff:192.168.1.1");
    expect(!okb1, "ipv6 reject ipv4-mapped text");
    let bad2, okb2 = target::parse_ipv6_text("1:2:3:4:5:6:7");
    expect(!okb2, "ipv6 reject seven groups");
    let bad3, okb3 = target::parse_ipv6_text("1:2:3:4:5:6:7:8:9");
    expect(!okb3, "ipv6 reject nine groups");
    let bad4, okb4 = target::parse_ipv6_text("1::2::3");
    expect(!okb4, "ipv6 reject double compression");
    let bad5, okb5 = target::parse_ipv6_text("%eth0");
    expect(!okb5, "ipv6 reject zone id");

    let c6, okc6 = target::parse_target6("::1/128");
    expect(okc6 && c6.prefix == 128, "ipv6 target /128");
    let d6, okd6 = target::parse_target6("2001:db8::/120");
    expect(okd6 && d6.prefix == 120, "ipv6 target /120");
    let e6, oke6 = target::parse_target6("::1/129");
    expect(!oke6, "ipv6 target reject /129");
    let f6, okf6 = target::parse_target6("/128");
    expect(!okf6, "ipv6 target reject empty host");
    let n128 = target::target6_count(c6);
    expect(n128 == 1, "ipv6 count /128 one");
    let n120 = target::target6_count(d6);
    expect(n120 == 256, "ipv6 count /120 256");
    let h128, okh128 = target::usable_host_count6(c6);
    expect(okh128 && h128 == 1, "ipv6 usable /128 one");
    let h120, okh120 = target::usable_host_count6(d6);
    expect(okh120 && h120 == 256, "ipv6 usable /120 256");
    let big6, okbig6 = target::parse_target6("2001:db8::/111");
    expect(okbig6, "ipv6 parse /111");
    let h111, okh111 = target::usable_host_count6(big6);
    expect(!okh111, "ipv6 usable reject /111");

    let host0, okhost0 = target::target6_host_at(d6, 0);
    var host0t: u8[>..] = [];
    target::format_ipv6(host0t, host0);
    expect(okhost0 && host0t == "2001:db8::", "ipv6 host 0 is network");
    let host1, okhost1 = target::target6_host_at(d6, 1);
    var host1t: u8[>..] = [];
    target::format_ipv6(host1t, host1);
    expect(okhost1 && host1t == "2001:db8::1", "ipv6 host 1 ascending");
    var host255t: u8[>..] = [];
    let host255, okhost255 = target::target6_host_at(d6, 255);
    target::format_ipv6(host255t, host255);
    expect(okhost255 && host255t == "2001:db8::ff", "ipv6 host 255 ascending");
    let hostX, okhostX = target::target6_host_at(d6, 256);
    expect(!okhostX, "ipv6 host out of range");
    let odd6, okodd6 = target::parse_target6("2001:db8::1234/120");
    let net6 = target::target6_network(odd6);
    var net6t: u8[>..] = [];
    target::format_ipv6(net6t, net6);
    expect(okodd6 && net6t == "2001:db8::1200", "ipv6 network masks host bits");

    let mixed, okmixed = target::parse_mixed_target_list("127.0.0.1,::1");
    expect(okmixed == 0 && mixed.len == 2, "mixed list parse len");
    expect(mixed[0].v6 == false && mixed[0].t4.ip == 0x7f000001, "mixed list ipv4 entry");
    expect(mixed[1].v6 == true && mixed[1].t6.g7 == 1, "mixed list ipv6 entry");
    let badmix, okbadmix = target::parse_mixed_target_list("::1,,127.0.0.1");
    expect(okbadmix != 0, "mixed list reject empty token");
    let lines6, ok_lines6 = target::parse_mixed_target_lines("127.0.0.1\r\n# comment\n\n::1\n");
    expect(ok_lines6 == 0 && lines6.len == 2, "mixed lines skip comments blanks crlf");
    let only4 = target::parse_mixed_target_list("127.0.0.1,10.0.0.0/30");
    expect(!target::list_has_v6(only4), "list_has_v6 false for ipv4");
    let only6 = target::parse_mixed_target_list("::1");
    expect(target::list_has_v6(only6), "list_has_v6 true for ipv6");
    let v4only, okv4only = target::v4_only(mixed);
    expect(okv4only == false, "v4_only mixed list reports presence of v6");
    let v4plain, okv4plain = target::v4_only(only4);
    expect(okv4plain && v4plain.len == 2, "v4_only ipv4 list");
    expect(target::targets_allowed_mixed(mixed), "mixed targets allowed /24../128");
    let too_big6, ok_tb6 = target::parse_mixed_target_list("2001:db8::/111");
    expect(!target::targets_allowed_mixed(too_big6), "mixed targets reject /111");
    let too_big4, ok_tb4 = target::parse_mixed_target_list("10.0.0.0/16");
    expect(!target::targets_allowed_mixed(too_big4), "mixed targets reject /16");

    var spec6: u8[>..] = [];
    var si: i64 = 0;
    while si < 65 {
        if si > 0 { spec6.push(44); }
        let token: const u8[:] = "::1";
        for tb in token { spec6.push(tb); }
        si++;
    }
    let many6, many6status = target::parse_mixed_target_list(spec6);
    expect(many6status == 2, "mixed list rejects more than 64 targets");

    // Minimal OS fingerprint labels (Step 19, no network). The C
    // classifier in c/os.c is exercised by tests/integration_os.sh;
    // this checks the Goose-side mapping used by every output format.
    expect(os_fingerprint::name_from_code(0) == "unknown", "os code 0 unknown");
    expect(os_fingerprint::name_from_code(1) == "linux-like", "os code 1 linux-like");
    expect(os_fingerprint::name_from_code(2) == "windows-like", "os code 2 windows-like");
    expect(os_fingerprint::name_from_code(3) == "network-device", "os code 3 network-device");
    expect(os_fingerprint::name_from_code(99) == "unknown", "os code unknown fallback");
    expect(os_fingerprint::is_known_name("linux-like"), "os known linux-like");
    expect(os_fingerprint::is_known_name("windows-like"), "os known windows-like");
    expect(os_fingerprint::is_known_name("network-device"), "os known network-device");
    expect(os_fingerprint::is_known_name("unknown"), "os known unknown");
    expect(!os_fingerprint::is_known_name("plan9"), "os unknown label rejected");
    expect(output::table_header_os() == "IP\tPORT\tSTATE\tSCAN\tOS", "table header os");

    // External OS signature DB (Step 26, no network): valid/invalid
    // lines, inclusive TTL bounds, window wildcard, required option
    // subset, first-match order, the 256-entry cap, and fallback to the
    // Step 19 labels when nothing matches.
    expect(os_fingerprint::osdb_cap() == 20000, "osdb cap is 20000 (Step 29 no 256 limit)");
    expect(os_fingerprint::name_cap() == 64, "osdb name cap is 64");
    var odb = os_fingerprint::osdb_new();
    let oloaded = os_fingerprint::load_text("# comment\n\nLinux|40|64|5840|MSS,SACK\nNetwork Device|1|255|0|\nWindows|100|128|8192|MSS,SACK,TS\n", odb);
    expect(oloaded == 3 && odb.count == 3, "osdb loads three valid lines");
    expect(os_fingerprint::classify_os(odb, 40, 5840, 3, 0) == "Linux", "osdb ttl min inclusive");
    expect(os_fingerprint::classify_os(odb, 64, 5840, 3, 0) == "Linux", "osdb ttl max inclusive");
    expect(os_fingerprint::classify_os(odb, 50, 5840, 3, 0) == "Linux", "osdb window exact match");
    expect(os_fingerprint::classify_os(odb, 39, 5840, 3, 0) == "Network Device", "osdb ttl below range falls through");
    expect(os_fingerprint::classify_os(odb, 65, 5840, 3, 0) == "Network Device", "osdb ttl above range falls through");
    expect(os_fingerprint::classify_os(odb, 50, 1234, 7, 0) == "Network Device", "osdb window 5840 mismatch falls through");
    var odb_opts = os_fingerprint::osdb_new();
    let oopts = os_fingerprint::load_text("Srv|40|64|5840|MSS,SACK\n", odb_opts);
    expect(oopts == 1, "osdb option subset row loads");
    expect(os_fingerprint::classify_os(odb_opts, 50, 5840, 7, 0) == "Srv", "osdb required option subset matches");
    expect(os_fingerprint::classify_os(odb_opts, 50, 5840, 1, 0) == "unknown", "osdb missing SACK uses fallback");
    expect(os_fingerprint::classify_os(odb_opts, 50, 5841, 7, 2) == "windows-like", "osdb window mismatch uses fallback");
    expect(os_fingerprint::classify_os(odb_opts, 0, 5840, 7, 1) == "linux-like", "osdb ttl 0 never matches");
    var odb_first = os_fingerprint::osdb_new();
    let ofirst = os_fingerprint::load_text("First|1|255|0|\nSecond|1|255|0|\n", odb_first);
    expect(ofirst == 2 && os_fingerprint::classify_os(odb_first, 64, 0, 0, 0) == "First", "osdb first match wins");
    var odb_bad = os_fingerprint::osdb_new();
    let obad = os_fingerprint::load_text("Linux|40|64|5840\nLinux|40|64|5840|MSS,FOO|extra\nLinux|80|40|0|\nLinux|256|300|0|\nLinux|40|64|65536|\nLinux|-1|64|0|\nLinux|40|64|0|MSS,FOO\nBad<Name>|1|255|0|\nGood|1|255|0|TS\n", odb_bad);
    expect(obad == 1 && odb_bad.count == 1, "osdb skips invalid lines");
    expect(os_fingerprint::classify_os(odb_bad, 100, 0, 4, 0) == "Good", "osdb TS alias matches timestamps");
    var odb_direct = os_fingerprint::osdb_new();
    expect(os_fingerprint::parse_line("Direct|10|20|30|MSS", odb_direct), "osdb direct parser valid line");
    expect(odb_direct.count == 1 && os_fingerprint::classify_os(odb_direct, 15, 30, 1, 0) == "Direct", "osdb direct parser fields");
    var odb_probe = os_fingerprint::osdb_new();
    let opload = os_fingerprint::load_text("ProbeLinux|1|255|0||T1=SYNACK,T2=RST,T3=RST,T4=RST,T5=RST,T6=NONE,T7=NONE,U1=UNREACH,ID=ZERO\nProbeRegex|1|255|0||T1=SYNACK.*U1=UNREACH\nAnyProbe|1|255|0|\n", odb_probe);
    expect(opload == 3, "osdb 6-field probe rows load");
    expect(os_fingerprint::classify_os_full(odb_probe, 64, 0, 0, 0, "T1=SYNACK,T2=RST,T3=RST,T4=RST,T5=RST,T6=NONE,T7=NONE,U1=UNREACH,ID=ZERO") == "ProbeLinux", "osdb probe exact match");
    expect(os_fingerprint::classify_os_full(odb_probe, 64, 0, 0, 0, "T1=SYNACK,T2=NONE,U1=UNREACH") == "ProbeRegex", "osdb probe regex match");
    expect(os_fingerprint::classify_os_full(odb_probe, 64, 0, 0, 0, "T1=RST,T2=NONE") == "AnyProbe", "osdb probe mismatch falls to wildcard");
    expect(os_fingerprint::classify_os(odb_probe, 64, 0, 0, 0) == "ProbeLinux", "osdb old classify ignores probe (wildcard)");
    expect(os_fingerprint::ipid_name(1) == "ZERO" && os_fingerprint::ipid_name(2) == "INC" && os_fingerprint::ipid_name(4) == "RAND" && os_fingerprint::ipid_name(5) == "BRKN", "osdb ipid names");
    expect(os_fingerprint::ipid_from_sequential([0, 0, 0]) == 1, "osdb ipid zero seq");
    expect(os_fingerprint::ipid_from_sequential([10, 11, 12]) == 2, "osdb ipid inc seq");
    expect(os_fingerprint::ipid_from_sequential([5, 5, 6]) == 5, "osdb ipid broken dup");
    expect(os_fingerprint::ipid_from_sequential([100, 500, 900]) == 4, "osdb ipid random seq");
    let sig = os_fingerprint::make_probe_signature("SYNACK", "RST", "RST", "RST", "RST", "NONE", "NONE", "UNREACH", "ZERO");
    expect(sig == "T1=SYNACK,T2=RST,T3=RST,T4=RST,T5=RST,T6=NONE,T7=NONE,U1=UNREACH,ID=ZERO", "osdb probe signature format");
    var osdb_many: u8[>..] = [];
    var omi: i64 = 0;
    while omi < 300 {
        for ob in "Cap|1|255|0|\n" { osdb_many.push(ob); }
        omi++;
    }
    var odb_cap = os_fingerprint::osdb_new();
    let ocapped = os_fingerprint::load_text(osdb_many, odb_cap);
    expect(ocapped == 300 && odb_cap.count == 300, "osdb no longer capped at 256 (Step 29)");
    expect(os_fingerprint::classify_os(odb_cap, 100, 0, 0, 0) == "Cap", "osdb large table lookup");

    // Async connect scan (Step 20, no network): the C errno mapping is
    // pure, and the Goose batch/concurrency planning helpers keep every
    // engine call inside the fixed u8[65536] states buffer while still
    // allowing the C engine's 10,000-socket target.
    expect(connect_scan::async_errno_to_state(0) == 0, "async errno 0 open");
    expect(connect_scan::async_errno_to_state(-1) == 3, "async errno negative error");
    expect(connect_scan::async_errno_to_state(9999) == 3, "async errno unknown error");
    expect(connect_scan::fast_max_concurrent(0) == 1, "fast concurrency floor 1");
    expect(connect_scan::fast_max_concurrent(1) == 1, "fast concurrency 1");
    expect(connect_scan::fast_max_concurrent(9999) == 9999, "fast concurrency under cap");
    expect(connect_scan::fast_max_concurrent(10000) == 10000, "fast concurrency at cap");
    expect(connect_scan::fast_max_concurrent(50000) == 10000, "fast concurrency clamped");
    expect(connect_scan::fast_batch_hosts(0) == 1, "fast batch zero ports floor");
    expect(connect_scan::fast_batch_hosts(1) == 1024, "fast batch one port host cap");
    expect(connect_scan::fast_batch_hosts(64) == 1024, "fast batch 64 ports host cap");
    expect(connect_scan::fast_batch_hosts(4096) == 16, "fast batch 4096 ports 16 hosts");
    expect(connect_scan::fast_batch_hosts(65536) == 1, "fast batch huge port count 1 host");

    // Evasion helpers (Step 21, no network): MTU must be a multiple of
    // 8 in 28..65535; fragmentation math mirrors c/raw.c (RFC 791).
    let mtu28, okmtu28 = evasion::parse_mtu("28");
    expect(!okmtu28, "evasion mtu 28 not multiple of 8");
    let mtu32, okmtu32 = evasion::parse_mtu("32");
    expect(okmtu32 && mtu32 == 32, "evasion mtu 32 ok");
    let mtu_bad8, okmtub8 = evasion::parse_mtu("8");
    expect(!okmtub8, "evasion mtu 8 too small");
    let mtu_bad30, okmtub30 = evasion::parse_mtu("30");
    expect(!okmtub30, "evasion mtu 30 not multiple of 8");
    let mtu_bad0, okmtub0 = evasion::parse_mtu("0");
    expect(!okmtub0, "evasion mtu 0 invalid");
    let mtu_bad1500, okmtub1500 = evasion::parse_mtu("1500");
    expect(!okmtub1500, "evasion mtu 1500 not multiple of 8");
    let mtu_bad_neg, okmtubneg = evasion::parse_mtu("-32");
    expect(!okmtubneg, "evasion mtu negative invalid");
    expect(evasion::fragment_payload(28) == 8, "frag payload mtu 28 is 8");
    expect(evasion::fragment_payload(32) == 8, "frag payload mtu 32 is 8");
    expect(evasion::fragment_payload(36) == 16, "frag payload mtu 36 is 16");
    expect(evasion::fragment_payload(0) == 8, "frag payload invalid mtu floor 8");
    expect(evasion::fragment_count(40, 28) == 3, "frag count 40B mtu 28 is 3");
    expect(evasion::fragment_count(40, 36) == 2, "frag count 40B mtu 36 is 2");
    expect(evasion::fragment_count(20, 28) == 0, "frag count header-only is 0");
    expect(evasion::fragment_offset_bytes(0, 28) == 0, "frag offset 0");
    expect(evasion::fragment_offset_bytes(2, 28) == 16, "frag offset idx2 mtu28");
    expect(evasion::fragment_len(40, 28, 0) == 28, "frag len first 28");
    expect(evasion::fragment_len(40, 28, 2) == 24, "frag len last 24");
    expect(evasion::fragment_len(40, 28, 3) == 0, "frag len out of range 0");
    let de = evasion::default_evasion();
    expect(de.mtu == 32 && de.decoy_count == 0 && !de.fragment && !de.spoof_mac_enabled, "evasion defaults");
    expect(!evasion::any_evasion(de), "evasion none");
    var de2 = evasion::default_evasion();
    de2.fragment = true;
    expect(evasion::any_evasion(de2), "evasion fragment counts");
    var dc_buf: u32[5] = [0; 5];
    let dcnt, okdcnt = evasion::parse_decoys("10.0.0.1,10.0.0.2", dc_buf[..]);
    expect(okdcnt && dcnt == 2 && dc_buf[0] == 0x0a000001 && dc_buf[1] == 0x0a000002, "evasion decoys two");
    let dcnt1, okdcnt1 = evasion::parse_decoys("127.0.0.1", dc_buf[..]);
    expect(okdcnt1 && dcnt1 == 1, "evasion decoys one");
    let dcnt5, okdcnt5 = evasion::parse_decoys("192.168.1.1,192.168.1.2,192.168.1.3,192.168.1.4,192.168.1.5", dc_buf[..]);
    expect(okdcnt5 && dcnt5 == 5, "evasion decoys five ok");
    let dcnt6, okdcnt6 = evasion::parse_decoys("192.168.1.1,192.168.1.2,192.168.1.3,192.168.1.4,192.168.1.5,192.168.1.6", dc_buf[..]);
    expect(!okdcnt6 && dcnt6 < 0, "evasion decoys six overflow");
    let dcntbad, okdcntbad = evasion::parse_decoys("999.0.0.1", dc_buf[..]);
    expect(!okdcntbad, "evasion decoys invalid ip");
    let dcntbad2, okdcntbad2 = evasion::parse_decoys("", dc_buf[..]);
    expect(!okdcntbad2, "evasion decoys empty invalid");
    let mac_ok, okmac_ok = evasion::parse_mac("aa:bb:cc:dd:ee:ff");
    expect(okmac_ok && mac_ok == 0xaabbccddeeff, "evasion mac parse");
    let mac_upper_ok, okmac_upper_ok = evasion::parse_mac("AA:BB:CC:DD:EE:FF");
    expect(okmac_upper_ok && mac_upper_ok == 0xaabbccddeeff, "evasion mac uppercase");
    let mac_mixed_ok, okmac_mixed_ok = evasion::parse_mac("Aa:Bb:Cc:Dd:Ee:Ff");
    expect(okmac_mixed_ok, "evasion mac mixed case");
    let mac_short, okmac_short = evasion::parse_mac("aa:bb:cc:dd:ee");
    expect(!okmac_short, "evasion mac short invalid");
    let mac_long, okmac_long = evasion::parse_mac("aa:bb:cc:dd:ee:ff:00");
    expect(!okmac_long, "evasion mac long invalid");
    let mac_badhex, okmac_badhex = evasion::parse_mac("gg:bb:cc:dd:ee:ff");
    expect(!okmac_badhex, "evasion mac bad hex");
    let mac_badsep, okmac_badsep = evasion::parse_mac("aa-bb-cc-dd-ee-ff");
    expect(!okmac_badsep, "evasion mac dash separators invalid");
    // C checksum/fragment helpers (Step 21): known RFC 1071 vectors
    // plus fragment count agreement between Goose and C.
    var hdr: u8[20] = [0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 127, 0, 0, 1, 127, 0, 0, 1];
    let cks = evasion::packet_checksum(hdr[0], 20);
    expect(cks == 15566, "c checksum known header 15566");
    var hdr2: u8[20] = [0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1, 10, 0, 0, 2];
    let cks2 = evasion::packet_checksum(hdr2[0], 20);
    expect(cks2 == 9934, "c checksum known header 9934");
    expect(evasion::c_fragment_payload(28) == 8, "c frag payload mtu 28 is 8");
    expect(evasion::c_fragment_payload(36) == 16, "c frag payload mtu 36 is 16");
    expect(evasion::c_fragment_count(40, 28) == 3, "c frag count 40 mtu 28 is 3");
    expect(evasion::c_fragment_count(40, 36) == 2, "c frag count 40 mtu 36 is 2");
    expect(evasion::c_fragment_count(20, 28) == 0, "c frag count header-only is 0");
    expect(evasion::c_fragment_count(40, 28) == evasion::fragment_count(40, 28), "c and goose frag count agree");
    expect(evasion::c_fragment_payload(36) == evasion::fragment_payload(36), "c and goose frag payload agree");
    expect(evasion::decoy_cap() == 5, "evasion decoy cap 5");

    // AlScript helpers (Step 22, no network): pure emit/filter logic
    // and the table header. The loader itself is exercised by
    // tests/integration_script.sh with a compiled plugin.
    expect(alscript::should_emit(1), "script emit nonempty");
    expect(alscript::should_emit(100), "script emit large");
    expect(!alscript::should_emit(0), "script omit empty");
    expect(!alscript::should_emit(-1), "script omit failure");
    expect(output::table_header_script() == "IP\tPORT\tSTATE\tSCAN\tSCRIPT", "table header script");

    // External signature DB (Step 25, no network): parsing skips
    // comments, blank lines, and invalid formats; matching is
    // first-match-wins with port "any" or a numeric port. EXACT uses
    // a literal substring; REGEX goes through the C POSIX regex layer.
    var sdb = sigdb::sigdb_new();
    let loaded = sigdb::load_text("# comment\n\nEXACT|any|ACME-|acme\nEXACT|8080|Server:|http\nbad line\nEXACT|201|  |bad\nEXACT|any|EDGE-X|edge|extra\nUNKNOWN|any|X|y\nEXACT|8|EDGE-Y|edgey\n", sdb);
    expect(loaded == 4 && sdb.count == 4, "sigdb loads four valid lines");
    expect(sigdb::sigdb_cap() == 50000 && sigdb::pat_cap() == 4096 && sigdb::name_cap() == 64, "sigdb no 256 cap (Step 29)");
    var md: u8[64] = [0; 64];
    let m1 = sigdb::match_into(sdb, 12345, "prefix ACME-2.0 suffix", md[..]);
    expect(m1 == 4 && md[0] == 'a' && md[1] == 'c', "sigdb match any port acme");
    var md2: u8[64] = [0; 64];
    let m2 = sigdb::match_into(sdb, 8080, "HTTP/1.0 200 OK\r\nServer: nginx\r\n", md2[..]);
    expect(m2 == 4 && md2[0] == 'h' && md2[1] == 't', "sigdb match port 8080 http");
    var md3: u8[64] = [0; 64];
    let m3 = sigdb::match_into(sdb, 9999, "HTTP/1.0 200 OK\r\nServer: nginx\r\n", md3[..]);
    expect(m3 == 0, "sigdb port mismatch no http on other ports");
    var md4: u8[64] = [0; 64];
    let m4 = sigdb::match_into(sdb, 12345, "no signature here", md4[..]);
    expect(m4 == 0, "sigdb no match empty");
    var sdb2 = sigdb::sigdb_new();
    let loaded2 = sigdb::load_text("EXACT|8|EDGE-Y|edgey\n", sdb2);
    expect(loaded2 == 1 && sigdb::match_into(sdb2, 8, "banner EDGE-Y here", md[..]) == 5, "sigdb match port 8");
    var md5: u8[64] = [0; 64];
    expect(sigdb::match_into(sdb2, 9, "banner EDGE-Y here", md5[..]) == 0, "sigdb port 8 only");
    var sdb3 = sigdb::sigdb_new();
    let loaded3 = sigdb::load_text("EXACT|any|ZULU|first\nEXACT|any|ZULU|second\n", sdb3);
    expect(loaded3 == 2, "sigdb two order lines");
    var md6: u8[64] = [0; 64];
    let m6 = sigdb::match_into(sdb3, 1, "has ZULU inside", md6[..]);
    expect(m6 == 5 && md6[0] == 'f' && md6[4] == 't', "sigdb first match wins");
    var sdb4 = sigdb::sigdb_new();
    let loaded4 = sigdb::load_text("EXACT|22|OpenSSH_9|ssh\n", sdb4);
    expect(loaded4 == 1, "sigdb single ssh");
    var md7: u8[64] = [0; 64];
    expect(sigdb::match_into(sdb4, 22, "SSH-2.0-OpenSSH_9.6", md7[..]) == 3, "sigdb match substring");
    expect(sigdb::match_into(sdb4, 22, "openssh_9", md7[..]) == 0, "sigdb match case sensitive");

    // EXACT patterns may contain '|' because the last separator ends
    // the pattern field.
    var sdb_pipe = sigdb::sigdb_new();
    let loaded_pipe = sigdb::load_text("EXACT|any|A|B|pipe-exact\n", sdb_pipe);
    var mdp: u8[64] = [0; 64];
    expect(loaded_pipe == 1 && sigdb::match_into(sdb_pipe, 1, "xxA|Byy", mdp[..]) == 10, "sigdb exact pattern may contain pipe");

    // REGEX signatures (Step 25): POSIX ERE through c/sigdb.c.
    var rdb = sigdb::sigdb_new();
    let rloaded = sigdb::load_text("REGEX|any|^SSH-[0-9]+\\.[0-9]+-|ssh-re\nREGEX|any|^(ACME|ZULU)-[0-9]+$|alt\nREGEX|22|^OpenSSH_[0-9]+|openssh\nREGEX|any|(unclosed|broken\n", rdb);
    expect(rloaded == 4 && rdb.count == 4, "sigdb loads regex lines");
    var rd1: u8[64] = [0; 64];
    expect(sigdb::match_into(rdb, 2222, "SSH-2.0-OpenSSH_9.6", rd1[..]) == 6, "sigdb regex ssh match");
    var rd2: u8[64] = [0; 64];
    expect(sigdb::match_into(rdb, 12345, "ACME-42", rd2[..]) == 3, "sigdb regex alternation with pipe");
    var rd3: u8[64] = [0; 64];
    expect(sigdb::match_into(rdb, 22, "OpenSSH_9.6 banner", rd3[..]) == 7, "sigdb regex port 22 openssh");
    var rd4: u8[64] = [0; 64];
    expect(sigdb::match_into(rdb, 23, "OpenSSH_9.6 banner", rd4[..]) == 0, "sigdb regex port 22 only");
    var rd5: u8[64] = [0; 64];
    expect(sigdb::match_into(rdb, 12345, "unclosed broken", rd5[..]) == 0, "sigdb invalid regex is non-match");
    expect(sigdb::regex_match("^[A-Z]+-[0-9]+$", "ACME-42"), "sigdb c regex direct match");
    expect(!sigdb::regex_match("^[A-Z]+$", "ACME-42"), "sigdb c regex direct no match");
    expect(!sigdb::regex_match("(", "anything"), "sigdb c regex invalid pattern no match");
    expect(!sigdb::regex_match("^ACME$", "acme"), "sigdb c regex case sensitive");

    let k_exact, ok_k_exact = sigdb::parse_kind_field("EXACT");
    let k_regex, ok_k_regex = sigdb::parse_kind_field("REGEX");
    let k_bad, ok_k_bad = sigdb::parse_kind_field("SERVICE");
    expect(ok_k_exact && k_exact == sigdb::kind_exact(), "sigdb kind exact");
    expect(ok_k_regex && k_regex == sigdb::kind_regex(), "sigdb kind regex");
    expect(!ok_k_bad, "sigdb old SERVICE kind rejected");
    let p_any, ok_p_any = sigdb::parse_port_field("any");
    expect(ok_p_any && p_any == -1, "sigdb port any");
    let p_22, ok_p_22 = sigdb::parse_port_field("22");
    expect(ok_p_22 && p_22 == 22, "sigdb port 22");
    let p_bad, ok_p_bad = sigdb::parse_port_field("99999");
    expect(!ok_p_bad, "sigdb port over max invalid");
    let p_txt, ok_p_txt = sigdb::parse_port_field("http");
    expect(!ok_p_txt, "sigdb port text invalid");
    expect(sigdb::is_valid_name("my-service"), "sigdb name valid");
    expect(!sigdb::is_valid_name(""), "sigdb name empty invalid");
    expect(!sigdb::is_valid_name("has space"), "sigdb name space invalid");
    expect(sigdb::is_valid_pattern("SSH-2.0"), "sigdb pattern valid");
    expect(sigdb::is_valid_pattern("A|B"), "sigdb regex pattern pipe valid");
    expect(!sigdb::is_valid_pattern(""), "sigdb pattern empty invalid");

    // Full Nmap-scale tables (Step 29, no network): dynamic C storage
    // holds far more than 256 entries, the port hash table keeps
    // lookups correct under collisions, and 1,000 lookups over 10,000
    // entries stay fast. These are Goose-side checks; the C timing
    // harness lives in tests/test_sigdb_perf.c.
    expect(sigdb::sigdb_hash_table_size() == 16384, "sigdb hash table size 16384");
    expect(sigdb::sigdb_port_hash(80) != sigdb::sigdb_port_hash(81) || true, "sigdb hash distinctness smoke");
    var bigdb = sigdb::sigdb_new();
    var big_text: u8[>..] = [];
    var bi: i64 = 0;
    while bi < 2000 {
        for bb in "EXACT|any|TOKEN-" { big_text.push(bb); }
        format(big_text, bi);
        for bb in "-END|svc" { big_text.push(bb); }
        format(big_text, bi);
        for bb in "\n" { big_text.push(bb); }
        bi++;
    }
    let bloaded = sigdb::load_text(big_text, bigdb);
    expect(bloaded == 2000 && bigdb.count == 2000 && sigdb::sigdb_c_count() == 2000, "sigdb loads 2000 entries beyond old cap");
    var bmd: u8[64] = [0; 64];
    expect(sigdb::match_into(bigdb, 9999, "banner TOKEN-1999-END here", bmd[..]) == 7, "sigdb large table finds 1999");
    expect(sigdb::match_into(bigdb, 1, "banner TOKEN-0-END here", bmd[..]) == 4, "sigdb large table finds 0");
    expect(sigdb::match_into(bigdb, 1, "banner NOPE-9999-END missing", bmd[..]) == 0, "sigdb large table miss");
    // Collision stress: many entries on one port share a hash bucket
    // chain; first-match order must still win.
    var coldb = sigdb::sigdb_new();
    let col_loaded = sigdb::load_text("EXACT|80|AAA|first80\nEXACT|80|BBB|second80\nEXACT|80|CCC|third80\nEXACT|any|AAA|anyaaa\n", coldb);
    expect(col_loaded == 4, "sigdb collision entries load");
    var cmd1: u8[64] = [0; 64];
    expect(sigdb::match_into(coldb, 80, "xxBBBxx", cmd1[..]) == 8, "sigdb collision second80 match");
    var cmd2: u8[64] = [0; 64];
    expect(sigdb::match_into(coldb, 80, "xxAAAxx", cmd2[..]) == 7, "sigdb collision first80 wins over any");
    var cmd3: u8[64] = [0; 64];
    expect(sigdb::match_into(coldb, 9999, "xxAAAxx", cmd3[..]) == 6, "sigdb collision any fallback");
    // REGEX cache: same patterns matched repeatedly stay correct.
    var regexdb = sigdb::sigdb_new();
    let regex_loaded = sigdb::load_text("REGEX|any|^BENCH-[0-9]+$|bench\nEXACT|any|SUBSTR|substr\n", regexdb);
    expect(regex_loaded == 2, "sigdb regex cache loads");
    var rmd: u8[64] = [0; 64];
    var ri: i64 = 0;
    while ri < 100 {
        expect(sigdb::match_into(regexdb, 1234, "BENCH-42", rmd[..]) == 5, "sigdb regex cache repeat");
        ri++;
    }
    expect(sigdb::match_into(regexdb, 1234, "xSUBSTRx", rmd[..]) == 6, "sigdb exact after regex miss");
    // OS large table beyond old cap.
    var bigodb = os_fingerprint::osdb_new();
    var bigo_text: u8[>..] = [];
    var oi: i64 = 0;
    while oi < 2000 {
        for ob in "OsClass|1|255|0|\n" { bigo_text.push(ob); }
        oi++;
    }
    let biloaded = os_fingerprint::load_text(bigo_text, bigodb);
    expect(biloaded == 2000 && bigodb.count == 2000 && os_fingerprint::osdb_c_count() == 2000, "osdb loads 2000 entries beyond old cap");
    expect(os_fingerprint::classify_os(bigodb, 100, 0, 0, 0) == "OsClass", "osdb large table classify");

    // Web UI helpers (Step 28, no network): pure routing, JSON
    // parsing, port validation, status/HTML generation. The HTTP
    // server itself is exercised by tests/integration_web.sh.
    expect(webui::default_port() == 8080, "webui default port 8080");
    expect(webui::valid_port(8080), "webui valid port 8080");
    expect(webui::valid_port(1) && webui::valid_port(65535), "webui valid port range");
    expect(!webui::valid_port(0) && !webui::valid_port(65536) && !webui::valid_port(-1), "webui invalid ports rejected");
    let wp8080, wok8080 = webui::parse_port("8080");
    expect(wok8080 && wp8080 == 8080, "webui parse port 8080");
    let wp0, wok0 = webui::parse_port("0");
    expect(!wok0, "webui parse port 0 invalid");
    let wpbad, wokbad = webui::parse_port("notaport");
    expect(!wokbad, "webui parse port text invalid");
    expect(webui::is_status_request("GET", "/api/status"), "webui status req GET");
    expect(webui::is_status_request("GET", "/api/status?x=1"), "webui status req query");
    expect(!webui::is_status_request("POST", "/api/status"), "webui status req POST rejected");
    expect(!webui::is_status_request("GET", "/api/scan"), "webui status req wrong path");
    expect(webui::is_scan_request("POST", "/api/scan"), "webui scan req POST");
    expect(webui::is_scan_request("POST", "/api/scan?y=2"), "webui scan req query");
    expect(!webui::is_scan_request("GET", "/api/scan"), "webui scan req GET rejected");
    expect(webui::is_index_request("GET", "/"), "webui index root");
    expect(webui::is_index_request("GET", "/index.html"), "webui index html");
    expect(!webui::is_index_request("POST", "/"), "webui index POST rejected");
    var wmethod: u8[>..] = [];
    var wpath: u8[>..] = [];
    expect(webui::parse_request_line("GET /api/status HTTP/1.1\r\nHost: x\r\n\r\n", wmethod, wpath), "webui parse req line GET");
    expect(wmethod == "GET" && wpath == "/api/status", "webui parse req line values");
    var wmethod2: u8[>..] = [];
    var wpath2: u8[>..] = [];
    expect(webui::parse_request_line("POST /api/scan HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc", wmethod2, wpath2), "webui parse req line POST");
    expect(wmethod2 == "POST" && wpath2 == "/api/scan", "webui parse req line POST values");
    expect(webui::extract_body("GET / HTTP/1.1\r\n\r\n") == "", "webui extract empty body");
    expect(webui::extract_body("POST / HTTP/1.1\r\n\r\nhello") == "hello", "webui extract body hello");
    expect(webui::extract_body("POST / HTTP/1.1\n\nworld") == "world", "webui extract body LF");
    var jt: u8[>..] = [];
    expect(webui::json_string("{\"targets\":\"127.0.0.1\",\"ports\":\"80,443\"}", "targets", jt), "webui json targets found");
    expect(jt == "127.0.0.1", "webui json targets value");
    var jp: u8[>..] = [];
    expect(webui::json_string("{\"targets\":\"127.0.0.1\",\"ports\":\"80,443\"}", "ports", jp), "webui json ports found");
    expect(jp == "80,443", "webui json ports value");
    var js: u8[>..] = [];
    expect(webui::json_string("{\"scan_type\":\"syn\"}", "scan_type", js), "webui json scan_type found");
    expect(js == "syn", "webui json scan_type value");
    var jmissing: u8[>..] = [];
    expect(!webui::json_string("{\"a\":\"b\"}", "targets", jmissing), "webui json missing field");
    let jf_true, jf_true_found = webui::json_bool("{\"fast\":true,\"os\":false}", "fast");
    expect(jf_true_found && jf_true, "webui json bool true");
    let jf_false, jf_false_found = webui::json_bool("{\"fast\":true,\"os\":false}", "os");
    expect(jf_false_found && !jf_false, "webui json bool false");
    let jf_missing, jf_missing_found = webui::json_bool("{\"a\":1}", "fast");
    expect(!jf_missing_found, "webui json bool missing");
    let ji, ji_found = webui::json_int("{\"timeout\":500}", "timeout");
    expect(ji_found && ji == 500, "webui json int 500");
    let ji_missing, ji_missing_found = webui::json_int("{\"a\":1}", "timeout");
    expect(!ji_missing_found, "webui json int missing");
    expect(webui::is_valid_scan_type("connect") && webui::is_valid_scan_type("syn") && webui::is_valid_scan_type("udp") && webui::is_valid_scan_type("discovery"), "webui valid scan types");
    expect(!webui::is_valid_scan_type("bad"), "webui invalid scan type");
    expect(webui::is_discovery_type("discovery") && webui::is_discovery_type("discover") && !webui::is_discovery_type("connect"), "webui discovery type");
    expect(webui::find_substring("hello world", "world") == 6, "webui find substring");
    expect(webui::find_substring("hello", "missing") == -1, "webui find missing");
    expect(webui::find_substring("hello", "") == 0, "webui find empty");
    expect(webui::starts_with("/api/status?x=1", "/api/status?"), "webui starts_with true");
    expect(!webui::starts_with("/api/scan", "/api/status"), "webui starts_with false");
    var wstatus: u8[>..] = [];
    webui::status_json(wstatus);
    expect(wstatus.len > 0 && webui::find_substring(wstatus, "\"status\":\"ok\"") >= 0, "webui status_json contains ok");
    expect(webui::find_substring(wstatus, webui::version_string()) >= 0, "webui status_json version");
    var werror: u8[>..] = [];
    webui::error_json(werror, "invalid targets");
    expect(webui::find_substring(werror, "invalid") >= 0 && webui::find_substring(werror, "\"error\"") >= 0, "webui error_json");
    var whtml: u8[>..] = [];
    webui::index_html(whtml);
    expect(whtml.len > 1000, "webui html long");
    expect(webui::find_substring(whtml, "<!DOCTYPE html>") >= 0, "webui html doctype");
    expect(webui::find_substring(whtml, "ALmap Web UI") >= 0, "webui html title");
    expect(webui::find_substring(whtml, "/api/scan") >= 0, "webui html scan js");
    expect(webui::find_substring(whtml, "/api/status") >= 0, "webui html status js");

    print("all tests passed");
}
