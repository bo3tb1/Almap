import std;
import modules.target;
namespace evasion;

// modules/evasion.goose - Step 21: evasion flag parsing and pure
// fragmentation planning helpers. No heap, no GC, no lifetime
// annotations. Fragmentation math here mirrors c/raw.c (RFC 791:
// non-last fragments carry a multiple of 8 payload bytes; offsets
// are in 8-byte units). C checksum/fragment helpers are exercised by
// tests/test_almap.goose via tests/integration_syn.sh expectations.

struct Evasion {
    fragment: bool,
    mtu: i64,
    decoy_count: i64,
    decoy0: u32,
    decoy1: u32,
    decoy2: u32,
    decoy3: u32,
    decoy4: u32,
    spoof_mac_enabled: bool,
    spoof_mac: u64,
}

fn default_evasion() -> Evasion {
    return Evasion { fragment: false, mtu: 32, decoy_count: 0, decoy0: 0, decoy1: 0, decoy2: 0, decoy3: 0, decoy4: 0, spoof_mac_enabled: false, spoof_mac: 0 };
}

fn decoy_cap() -> i64 {
    return 5;
}

// Custom MTU must be a multiple of 8, at least one IP header (20) plus
// one 8-byte fragment payload in an 8-aligned total, and no larger
// than 65535. The value is the per-fragment IP total length; c/raw.c
// derives the payload size (mtu - 20 rounded down to a multiple of 8).
fn parse_mtu(s: const u8[:]) -> i64, bool {
    let t = trim(s);
    if t.len == 0 { return 0, false; }
    if t[0] == '-' || t[0] == '+' { return 0, false; }
    let v, ok = parse_int(t);
    if !ok { return 0, false; }
    if v < 32 || v > 65535 { return 0, false; }
    if (v % 8) != 0 { return 0, false; }
    return v, true;
}

fn is_hex_digit(b: u8) -> bool {
    if b >= 48 && b <= 57 { return true; }
    if b >= 97 && b <= 102 { return true; }
    if b >= 65 && b <= 70 { return true; }
    return false;
}

fn hex_val(b: u8) -> u64 {
    if b >= 48 && b <= 57 { return b - 48; }
    if b >= 97 && b <= 102 { return b - 87; }
    return b - 55;
}

// Parses "aa:bb:cc:dd:ee:ff" (case-insensitive, exactly 17 bytes) into
// 6 big-endian bytes packed in a u64: byte 0 is the most significant
// of the low 48 bits. Returns 0,false on malformed input.
fn parse_mac(s: const u8[:]) -> u64, bool {
    let t = trim(s);
    if t.len != 17 { return 0, false; }
    var i: i64 = 0;
    var mac: u64 = 0;
    while i < 6 {
        let base = i * 3;
        let hi = t[base];
        let lo = t[base + 1];
        if !is_hex_digit(hi) { return 0, false; }
        if !is_hex_digit(lo) { return 0, false; }
        if i < 5 && t[base + 2] != ':' { return 0, false; }
        mac = (mac << 8) | (hex_val(hi) << 4) | hex_val(lo);
        i++;
    }
    return mac, true;
}

// Parses a comma-separated list of IPv4 addresses (up to 5). Returns
// the count and ok; count is -1 when the list has more than 5 entries
// so callers can distinguish overflow from bad syntax. Zero addresses
// (empty string) is not ok.
fn parse_decoys(s: const u8[:], out: u32[:]) -> i64, bool {
    let t = trim(s);
    if t.len == 0 { return 0, false; }
    let parts = split(t, ',');
    if parts.len == 0 { return 0, false; }
    if parts.len > decoy_cap() { return -1, false; }
    var i: i64 = 0;
    while i < parts.len {
        let ip, ok = target::parse_ipv4(trim(parts[i]));
        if !ok { return 0, false; }
        out[i] = ip;
        i++;
    }
    return parts.len, true;
}

fn any_evasion(e: Evasion) -> bool {
    return e.fragment || e.decoy_count > 0 || e.spoof_mac_enabled;
}

// Returns fragment payload bytes per non-last fragment: mtu - 20 with
// the IP header removed, rounded down to a multiple of 8, minimum 8.
fn fragment_payload(mtu: i64) -> i64 {
    if mtu < 28 { return 8; }
    var payload = mtu - 20;
    payload = (payload / 8) * 8;
    if payload < 8 { return 8; }
    return payload;
}

// Number of IP fragments for an ip_total_len packet split at mtu.
// Returns 0 for an invalid total/mtu.
fn fragment_count(ip_total_len: i64, mtu: i64) -> i64 {
    if ip_total_len < 20 || mtu < 28 { return 0; }
    let payload = ip_total_len - 20;
    if payload <= 0 { return 0; }
    let per = fragment_payload(mtu);
    if payload <= per { return 1; }
    return (payload + per - 1) / per;
}

fn fragment_offset_bytes(index: i64, mtu: i64) -> i64 {
    if index <= 0 { return 0; }
    return index * fragment_payload(mtu);
}

fn fragment_len(ip_total_len: i64, mtu: i64, index: i64) -> i64 {
    if ip_total_len < 20 || mtu < 28 || index < 0 { return 0; }
    let count = fragment_count(ip_total_len, mtu);
    if count == 0 || index >= count { return 0; }
    let total_payload = ip_total_len - 20;
    let off = fragment_offset_bytes(index, mtu);
    if off >= total_payload { return 0; }
    let remain = total_payload - off;
    let per = fragment_payload(mtu);
    if remain < per { return 20 + remain; }
    return 20 + per;
}

// C packet helpers declared beside the raw SYN engine (c/raw.c).
extern fn almap_packet_checksum(data: const u8&, len: i32) -> i32;
extern fn almap_fragment_count(total_len: i32, mtu: i32) -> i32;
extern fn almap_fragment_payload(mtu: i32) -> i32;

fn packet_checksum(data: const u8&, len: i32) -> i32 {
    return almap_packet_checksum(data, len);
}

fn c_fragment_count(ip_total_len: i32, mtu: i32) -> i32 {
    return almap_fragment_count(ip_total_len, mtu);
}

fn c_fragment_payload(mtu: i32) -> i32 {
    return almap_fragment_payload(mtu);
}
