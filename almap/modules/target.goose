import std;
namespace target;

// modules/target.goose - Step 2: target/port parsing only.
// No heap, no GC, no lifetime annotations.
// Errors are trailing bools after the value (Goose parse_int idiom):
//   let v, ok = parse_target(s); if !ok { ... }
// Fixed-capacity PortRanges avoids heap and expands to many ports;
// Step 3 can iterate ranges. Behaviors (assumptions, correct if wrong):
// - IPv4 octets are decimal, 0..255; leading zeros allowed; signed
//   and empty octets rejected; exactly 4 octets; surround whitespace trimmed.
// - CIDR: host/prefix, prefix 0..32; plain IPv4 gets prefix 32; host bits
//   are kept as written (use target_network to mask); extra '/' rejected.
// - Ports: 1..65535 inclusive (port 0 rejected); lo <= hi; spaces around
//   commas/dashes trimmed; at most 64 ranges.

struct Target { ip: u32, prefix: u8 }
struct PortRange { lo: u16, hi: u16 }
type PortRanges = PortRange[..64];

fn parse_octet(part: const u8[:]) -> u32, bool {
    if part.len == 0 { return 0, false; }
    if part[0] == '-' || part[0] == '+' { return 0, false; }
    let v, ok = parse_int(part);
    if !ok { return 0, false; }
    if v < 0 || v > 255 { return 0, false; }
    return v as u32, true;
}

fn parse_ipv4(s: const u8[:]) -> u32, bool {
    let t = trim(s);
    if t.len == 0 { return 0, false; }
    let parts = split(t, '.');
    if parts.len != 4 { return 0, false; }
    let o0, ok0 = parse_octet(parts[0]);
    if !ok0 { return 0, false; }
    let o1, ok1 = parse_octet(parts[1]);
    if !ok1 { return 0, false; }
    let o2, ok2 = parse_octet(parts[2]);
    if !ok2 { return 0, false; }
    let o3, ok3 = parse_octet(parts[3]);
    if !ok3 { return 0, false; }
    let ip = (o0 << 24) | (o1 << 16) | (o2 << 8) | o3;
    return ip, true;
}

fn parse_target(s: const u8[:]) -> Target, bool {
    let t = trim(s);
    if t.len == 0 { return Target { ip: 0, prefix: 0 }, false; }
    let slash = position(t, '/');
    if slash < 0 {
        let ip, ok = parse_ipv4(t);
        if !ok { return Target { ip: 0, prefix: 0 }, false; }
        return Target { ip: ip, prefix: 32 }, true;
    }
    let host = t[..slash];
    let pre = t[slash + 1..];
    let ip, ok = parse_ipv4(host);
    if !ok { return Target { ip: 0, prefix: 0 }, false; }
    let p, ok2 = parse_int(pre);
    if !ok2 { return Target { ip: 0, prefix: 0 }, false; }
    if p < 0 || p > 32 { return Target { ip: 0, prefix: 0 }, false; }
    return Target { ip: ip, prefix: p as u8 }, true;
}

fn parse_port_number(part: const u8[:]) -> u16, bool {
    let t = trim(part);
    if t.len == 0 { return 0, false; }
    if t[0] == '-' || t[0] == '+' { return 0, false; }
    let v, ok = parse_int(t);
    if !ok { return 0, false; }
    if v < 1 || v > 65535 { return 0, false; }
    return v as u16, true;
}

fn parse_ports(s: const u8[:]) -> PortRanges, bool {
    var ranges: PortRanges = [];
    let t = trim(s);
    if t.len == 0 { return ranges, false; }
    let parts = split(t, ',');
    if parts.len == 0 { return ranges, false; }
    if parts.len > ranges.cap { return ranges, false; }
    for part in parts {
        let p = trim(part);
        if p.len == 0 { return ranges, false; }
        let dash = position(p, '-');
        if dash < 0 {
            let n, ok = parse_port_number(p);
            if !ok { return ranges, false; }
            ranges.push(PortRange { lo: n, hi: n });
        } else {
            let lo_s = trim(p[..dash]);
            let hi_s = trim(p[dash + 1..]);
            let lo, ok1 = parse_port_number(lo_s);
            if !ok1 { return ranges, false; }
            let hi, ok2 = parse_port_number(hi_s);
            if !ok2 { return ranges, false; }
            if lo > hi { return ranges, false; }
            ranges.push(PortRange { lo: lo, hi: hi });
        }
    }
    return ranges, true;
}

// Network address: host bits masked off. prefix 0 -> 0, >=32 -> ip.
fn target_network(t: Target) -> u32 {
    if t.prefix == 0 { return 0; }
    if t.prefix >= 32 { return t.ip; }
    let shift: u32 = 32 - t.prefix;
    return (t.ip >> shift) << shift;
}

// Number of addresses in the CIDR block: 1 << (32 - prefix).
// prefix 0 -> 4294967296 needs u64.
fn target_count(t: Target) -> u64 {
    if t.prefix >= 32 { return 1; }
    let bits: u64 = 32 - t.prefix;
    let one: u64 = 1;
    return one << bits;
}

// Total port count across all ranges (e.g. 1-1024 -> 1024).
fn port_count(p: PortRanges) -> i64 {
    var n: i64 = 0;
    for r in p {
        let lo: i64 = r.lo;
        let hi: i64 = r.hi;
        n += hi - lo + 1;
    }
    return n;
}

// Step 4: CIDR enumeration helpers. No heap: callers compute one host
// at a time from target_network + target_count, in ascending order.
// Usable hosts: /31 and /32 use all addresses; prefixes below /31
// (i.e. 24..30 in the allowed range) exclude network and broadcast.
// Limits for this step: prefix must be >= 24 (/0 and anything below
// /24 rejected), and total addresses must be <= 65536 (defensive;
// /24 already limits to 256 total, 254 usable).

fn usable_host_count(t: Target) -> i64, bool {
    if t.prefix < 24 { return 0, false; }
    let total = target_count(t);
    if total > 65536 { return 0, false; }
    if t.prefix >= 31 { return total as i64, true; }
    return (total as i64) - 2, true;
}

fn host_at(t: Target, idx: i64) -> u32, bool {
    let cnt, ok = usable_host_count(t);
    if !ok { return 0, false; }
    if idx < 0 || idx >= cnt { return 0, false; }
    let net = target_network(t);
    let off: i64 = if t.prefix >= 31 { idx } else { idx + 1 };
    return net + (off as u32), true;
}

// Step 15: multiple targets. A fixed-capacity list (no heap, no GC);
// at most 64 targets, in input order. The CLI turns -t's comma list
// or -iL's file lines into a TargetList and validates each Target
// separately with is_cidr_allowed (so the per-target /24.., 65536
// address limits are unchanged).
type TargetList = Target[..64];

fn target_list_cap() -> i64 {
    var empty: TargetList = [];
    return empty.cap;
}

// Parses a comma-separated target list ("a,b,c"). Tokens are trimmed;
// empty tokens are invalid. Status: 0 ok, 1 invalid token, 2 too many
// (more tokens than the fixed cap, checked before allocation grows).
fn parse_target_list(s: const u8[:]) -> TargetList, i64 {
    var out: TargetList = [];
    let t = trim(s);
    if t.len == 0 { return out, 1; }
    let parts = split(t, ',');
    if parts.len > out.cap { return out, 2; }
    for part in parts {
        let p = trim(part);
        let tgt, ok = parse_target(p);
        if !ok { return out, 1; }
        out.push(tgt);
    }
    return out, 0;
}

// Parses -iL file text: one target per line; lines are trimmed, blank
// lines and lines whose first non-space character is '#' are ignored
// (trailing \r from CRLF files is stripped too). Status: 0 ok,
// 1 invalid line, 2 too many targets.
fn parse_target_lines(data: const u8[:]) -> TargetList, i64 {
    var out: TargetList = [];
    let lines = split(data, '\n');
    for line in lines {
        var l = trim(line);
        if l.len > 0 && l[l.len - 1] == '\r' { l = l[..l.len - 1]; }
        if l.len == 0 { continue; }
        if l[0] == '#' { continue; }
        let tgt, ok = parse_target(l);
        if !ok { return out, 1; }
        if out.len >= out.cap { return out, 2; }
        out.push(tgt);
    }
    return out, 0;
}

// True when every target in the list is allowed by the per-target
// limits (non-empty, /24../32, at most 65536 addresses each).
fn targets_allowed(list: TargetList) -> bool {
    if list.len == 0 { return false; }
    for t in list {
        if !is_cidr_allowed(t) { return false; }
    }
    return true;
}

// CLI boundary for Step 4: true only for /24../32 within host limits.
fn is_cidr_allowed(t: Target) -> bool {
    let cnt, ok = usable_host_count(t);
    if !ok { return false; }
    if cnt < 1 { return false; }
    if cnt > 65536 { return false; }
    return true;
}

// Step 18: limited IPv6 support.
//
// A separate fixed Target6 representation (no heap, no GC) holds the
// eight 16-bit groups and a prefix length 0..128. Plain addresses get
// prefix 128. For this step IPv6 is supported only by --scan connect and
// --discover; SYN, UDP, service detection, and banners over IPv6 are
// rejected by the CLI.
//
// Limits mirror the IPv4 ones: the prefix must be /112.. /128 so a
// single target has at most 65536 hosts. No network/broadcast exclusion
// (IPv6 has none); /128 scans its single address.
//
// -t and -iL accept IPv4, IPv6, or a mixed comma/line list. TargetEntry
// keeps the family per entry and MixedTargetList preserves input order.

struct Target6 {
    g0: u16, g1: u16, g2: u16, g3: u16,
    g4: u16, g5: u16, g6: u16, g7: u16,
    prefix: u8,
}

struct TargetEntry {
    v6: bool,
    t4: Target,
    t6: Target6,
}

type MixedTargetList = TargetEntry[..64];

fn target6_from_groups(g: u16[8], prefix: u8) -> Target6 {
    return Target6 { g0: g[0], g1: g[1], g2: g[2], g3: g[3], g4: g[4], g5: g[5], g6: g[6], g7: g[7], prefix: prefix };
}

fn target6_zero() -> Target6 {
    var zeros: u16[8] = [0; 8];
    return target6_from_groups(zeros, 0);
}

fn mixed_list_cap() -> i64 {
    var empty: MixedTargetList = [];
    return empty.cap;
}

fn is_hex_digit(b: u8) -> bool {
    if b >= '0' && b <= '9' { return true; }
    if b >= 'a' && b <= 'f' { return true; }
    if b >= 'A' && b <= 'F' { return true; }
    return false;
}

fn hex_value(b: u8) -> u16 {
    if b >= '0' && b <= '9' { return b - 48; }
    if b >= 'a' && b <= 'f' { return b - 87; }
    return b - 55;
}

// Parses text that must be a plain IPv6 address (no prefix). Handles
// "::" compression at most once, 1..4 hex digits per group, and rejects
// embedded IPv4 ("1.2.3.4" in a group), zone ids ("%eth0"), and any
// other syntax. Returns the Target6 with prefix 128.
fn parse_ipv6_text(t: const u8[:]) -> Target6, bool {
    let text = trim(t);
    if text.len == 0 || text.len > 45 { return target6_zero(), false; }
    for b in text {
        if b == '.' || b == '%' { return target6_zero(), false; }
    }
    var groups: u16[8] = [0; 8];
    var ng: i64 = 0;
    var compress_at: i64 = -1;
    var i: i64 = 0;
    if text.len >= 2 && text[0] == ':' && text[1] == ':' {
        compress_at = 0;
        i = 2;
    } else if text[0] == ':' {
        return target6_zero(), false;
    }
    while i < text.len {
        let start = i;
        var val: u16 = 0;
        while i < text.len && is_hex_digit(text[i]) {
            if i - start >= 4 { return target6_zero(), false; }
            val = val * 16 + hex_value(text[i]);
            i++;
        }
        if i == start { return target6_zero(), false; }
        if ng >= 8 { return target6_zero(), false; }
        groups[ng] = val;
        ng++;
        if i >= text.len { break; }
        if text[i] != ':' { return target6_zero(), false; }
        if i + 1 < text.len && text[i + 1] == ':' {
            if compress_at >= 0 { return target6_zero(), false; }
            compress_at = ng;
            i += 2;
            if i >= text.len { break; }
        } else {
            i += 1;
            if i >= text.len { return target6_zero(), false; }
        }
    }
    var out_groups: u16[8] = [0; 8];
    if compress_at < 0 {
        if ng != 8 { return target6_zero(), false; }
        for k in 0..8 { out_groups[k] = groups[k]; }
    } else {
        let zeros = 8 - ng;
        if zeros < 1 { return target6_zero(), false; }
        var k: i64 = 0;
        for j in 0..8 {
            if j >= compress_at && j < compress_at + zeros {
                out_groups[j] = 0;
            } else {
                out_groups[j] = groups[k];
                k++;
            }
        }
    }
    return target6_from_groups(out_groups, 128), true;
}

// Parses an IPv6 target: plain address (prefix 128) or address/prefix
// with prefix 0..128. The address part must parse with parse_ipv6_text.
fn parse_target6(s: const u8[:]) -> Target6, bool {
    let text = trim(s);
    if text.len == 0 { return target6_zero(), false; }
    let slash = position(text, '/');
    if slash < 0 {
        let t6, ok = parse_ipv6_text(text);
        if !ok { return target6_zero(), false; }
        return t6, true;
    }
    let host = text[..slash];
    let pre = text[slash + 1..];
    if host.len == 0 || pre.len == 0 { return target6_zero(), false; }
    let t6, ok = parse_ipv6_text(host);
    if !ok { return target6_zero(), false; }
    let p, ok2 = parse_int(pre);
    if !ok2 { return target6_zero(), false; }
    if p < 0 || p > 128 { return target6_zero(), false; }
    var out = t6;
    out.prefix = p as u8;
    return out, true;
}

// Parses one -t/-iL token: ':' or '/' style picks IPv6, otherwise the
// existing IPv4 parser. Whitespace is trimmed like the IPv4 path.
fn parse_mixed_target(s: const u8[:]) -> TargetEntry, bool {
    let t = trim(s);
    if t.len == 0 { return TargetEntry { v6: false, t4: Target { ip: 0, prefix: 0 }, t6: target6_zero() }, false; }
    if position(t, ':') >= 0 {
        let t6, ok = parse_target6(t);
        if !ok { return TargetEntry { v6: false, t4: Target { ip: 0, prefix: 0 }, t6: target6_zero() }, false; }
        return TargetEntry { v6: true, t4: Target { ip: 0, prefix: 0 }, t6: t6 }, true;
    }
    let t4, ok4 = parse_target(t);
    if !ok4 { return TargetEntry { v6: false, t4: Target { ip: 0, prefix: 0 }, t6: target6_zero() }, false; }
    return TargetEntry { v6: false, t4: t4, t6: target6_zero() }, true;
}

// Step 18: comma-separated mixed IPv4/IPv6 target list. Status is the
// same shape as parse_target_list: 0 ok, 1 invalid token, 2 too many.
fn parse_mixed_target_list(s: const u8[:]) -> MixedTargetList, i64 {
    var out: MixedTargetList = [];
    let t = trim(s);
    if t.len == 0 { return out, 1; }
    let parts = split(t, ',');
    if parts.len > out.cap { return out, 2; }
    for part in parts {
        let p = trim(part);
        let entry, ok = parse_mixed_target(p);
        if !ok { return out, 1; }
        out.push(entry);
    }
    return out, 0;
}

// Step 18: -iL file text with mixed IPv4/IPv6 lines. Blank lines and
// lines starting with '#' are ignored; CRLF line ends are tolerated.
fn parse_mixed_target_lines(data: const u8[:]) -> MixedTargetList, i64 {
    var out: MixedTargetList = [];
    let lines = split(data, '\n');
    for line in lines {
        var l = trim(line);
        if l.len > 0 && l[l.len - 1] == '\r' { l = l[..l.len - 1]; }
        if l.len == 0 { continue; }
        if l[0] == '#' { continue; }
        let entry, ok = parse_mixed_target(l);
        if !ok { return out, 1; }
        if out.len >= out.cap { return out, 2; }
        out.push(entry);
    }
    return out, 0;
}

fn list_has_v6(list: MixedTargetList) -> bool {
    for e in list {
        if e.v6 { return true; }
    }
    return false;
}

// Extracts the IPv4 entries of a mixed list in input order. Returns
// false when the list contains any IPv6 entry (the CLI family checks
// reject those modes first).
fn v4_only(list: MixedTargetList) -> TargetList, bool {
    var out: TargetList = [];
    for e in list {
        if e.v6 { return out, false; }
        out.push(e.t4);
    }
    return out, true;
}

fn target6_count(t: Target6) -> u64 {
    if t.prefix >= 128 { return 1; }
    let bits: u64 = (128 - (t.prefix as i64)) as u64;
    let one: u64 = 1;
    return one << bits;
}

// Step 18 limits: prefix /112../128, at most 65536 addresses per
// target. /128 scans exactly one address.
fn usable_host_count6(t: Target6) -> i64, bool {
    if t.prefix < 112 { return 0, false; }
    if t.prefix > 128 { return 0, false; }
    let total = target6_count(t);
    if total < 1 || total > 65536 { return 0, false; }
    return total as i64, true;
}

fn target6_is_cidr_allowed(t: Target6) -> bool {
    let cnt, ok = usable_host_count6(t);
    if !ok { return false; }
    if cnt < 1 { return false; }
    if cnt > 65536 { return false; }
    return true;
}

fn group_mask(rem: i64) -> u16 {
    var m: u16 = 0;
    var k: i64 = 0;
    while k < rem { m = m * 2 + 1; k++; }
    while k < 16 { m = m * 2; k++; }
    return m;
}

// Network address: host bits masked off (prefix>=128 keeps the address).
fn target6_network(t: Target6) -> Target6 {
    var g: u16[8] = [0; 8];
    g[0] = t.g0; g[1] = t.g1; g[2] = t.g2; g[3] = t.g3;
    g[4] = t.g4; g[5] = t.g5; g[6] = t.g6; g[7] = t.g7;
    var i: i64 = 0;
    while i < 8 {
        let start: i64 = i * 16;
        if start >= t.prefix {
            g[i] = 0;
        } else if start + 16 > t.prefix {
            let rem: i64 = t.prefix - start;
            g[i] = g[i] & group_mask(rem);
        }
        i++;
    }
    return target6_from_groups(g, t.prefix);
}

// Host idx (ascending, zero-based) inside a /112../128 target. Because
// the prefix is at least /112, host bits live in the last group only and
// idx < 65536 cannot overflow it.
fn target6_host_at(t: Target6, idx: i64) -> Target6, bool {
    let cnt, ok = usable_host_count6(t);
    if !ok { return target6_zero(), false; }
    if idx < 0 || idx >= cnt { return target6_zero(), false; }
    let net = target6_network(t);
    var out = net;
    out.g7 = net.g7 + (idx as u16);
    return out, true;
}

fn targets_allowed_mixed(list: MixedTargetList) -> bool {
    if list.len == 0 { return false; }
    for e in list {
        if e.v6 {
            if !target6_is_cidr_allowed(e.t6) { return false; }
        } else {
            if !is_cidr_allowed(e.t4) { return false; }
        }
    }
    return true;
}

fn push_hex_digit(out: u8[>..]&, d: u16) {
    if d < 10 { out.push((48 + d) as u8); } else { out.push((87 + d) as u8); }
}

fn push_hex_group(out: u8[>..]&, v: u16) {
    var started = false;
    var pow: u16 = 4096;
    while pow > 0 {
        let d = (v / pow) % 16;
        if d != 0 || started || pow == 1 {
            push_hex_digit(out, d);
            started = true;
        }
        if pow == 1 { break; }
        pow = pow / 16;
    }
}

// Step 18: canonical-ish text form. Lowercase hex groups without leading
// zeros; the longest run of two or more zero groups becomes "::" (the
// first such run wins on ties). JSON/XML use this plain form.
fn format_ipv6(out: u8[>..]&, t: Target6) {
    var g: u16[8] = [0; 8];
    g[0] = t.g0; g[1] = t.g1; g[2] = t.g2; g[3] = t.g3;
    g[4] = t.g4; g[5] = t.g5; g[6] = t.g6; g[7] = t.g7;
    var best_start: i64 = -1;
    var best_len: i64 = 0;
    var i: i64 = 0;
    while i < 8 {
        if g[i] == 0 {
            var j = i;
            while j < 8 && g[j] == 0 { j++; }
            let run = j - i;
            if run >= 2 && run > best_len {
                best_len = run;
                best_start = i;
            }
            i = j;
        } else {
            i++;
        }
    }
    var idx: i64 = 0;
    var need_sep = false;
    while idx < 8 {
        if best_start >= 0 && idx == best_start {
            out.push(58);
            out.push(58);
            idx += best_len;
            need_sep = false;
            continue;
        }
        if need_sep { out.push(58); }
        push_hex_group(out, g[idx]);
        need_sep = true;
        idx++;
    }
}

// Text/table form brackets the address so "ip:port" stays unambiguous:
// "[::1]:80". JSON/XML use format_ipv6 (plain "::1").
fn format_ipv6_bracket(out: u8[>..]&, t: Target6) {
    out.push(91);
    var plain: u8[>..] = [];
    format_ipv6(plain, t);
    for b in plain { out.push(b); }
    out.push(93);
}
