#!/usr/bin/env python3
"""Import Nmap OS fingerprints into an ALmap os-signatures.db.

Reads a standard ``nmap-os-db`` file and emits the small heuristic
format understood by ALmap's ``--osdb`` loader:

    OS_NAME|MIN_TTL|MAX_TTL|WINDOW_SIZE|TCP_OPTIONS_FLAG

For every ``Fingerprint`` block the importer uses:

* ``Class <vendor> | <family> | ...`` to choose a general category:
  Linux, Windows, or Network Device.
* ``T1(... %T=...)`` for the initial TTL.  Values in nmap-os-db are
  hexadecimal and may contain ranges or ``|`` alternatives; the
  lowest and highest values are kept and clamped to 1..255.
  TSeq carries no TTL, so when T1 is absent the ECN/T3 tests are
  tried before the fingerprint is skipped.
* ``WIN(W1=...)`` for the TCP window.  A single hexadecimal value is
  used as-is; ranges and alternatives become 0, ALmap's wildcard.
* ``OPS(O1=...)`` for TCP options.  ``M`` maps to MSS, ``S`` to
  SACK, and ``T`` to TIMESTAMPS.  An empty option string matches any
  observed option set.

Identical rows are removed.  The database has no fixed cap (Step 29
full Nmap DB): by default ALL unique rows are imported (up to
--max, default 20000; Nmap yields ~1200 unique category rows from
6100 Fingerprint blocks). Within each category the most specific
rows (exact window first, then narrowest TTL range) are ordered
first, then categories are taken round-robin, so specific matches win
under first-match-wins.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

MAX_ENTRIES = 20000
CATEGORIES = ("Linux", "Windows", "Network Device")
HEX_VALUE = re.compile(r"^[0-9A-Fa-f]+$")


class Entry:
    """One candidate os-signatures.db row."""

    __slots__ = ("name", "min_ttl", "max_ttl", "window", "options", "order")

    def __init__(self, name, min_ttl, max_ttl, window, options, order):
        self.name = name
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self.window = window
        self.options = options
        self.order = order

    def key(self):
        return (self.name, self.min_ttl, self.max_ttl, self.window,
                self.options)


def parse_ttl(value):
    """Return (min_ttl, max_ttl) for an Nmap T= value, or None.

    Values are hexadecimal and may be ranges (``3B-45``) or
    alternatives (``3B-45|FA-104``).  Nmap occasionally stores values
    above 0xFF when TTL handling is broken; those are clamped.
    """
    numbers = []
    for alternative in value.split("|"):
        alternative = alternative.strip()
        if not alternative:
            continue
        for piece in alternative.split("-"):
            piece = piece.strip()
            if not piece or HEX_VALUE.match(piece) is None:
                return None
            numbers.append(int(piece, 16))
    if not numbers:
        return None
    low = min(numbers)
    high = max(numbers)
    # TTL 0 is not a usable observed value for ALmap's matcher.
    low = max(1, min(255, low))
    high = max(1, min(255, high))
    if low > high:
        low, high = high, low
    return low, high


def parse_window(value):
    """Return the window size, or 0 (wildcard) for ranges/alternatives."""
    values = [piece.strip() for piece in value.split("|")]
    values = [piece for piece in values if piece]
    if len(values) != 1 or HEX_VALUE.match(values[0]) is None:
        return 0
    return max(0, min(65535, int(values[0], 16)))


def parse_options(value):
    """Translate an Nmap OPS/O1 option string to ALmap flag names."""
    # Nmap separates alternate option strings with '|'; use the first.
    first = value.split("|")[0]
    flags = []
    if "M" in first:
        flags.append("MSS")
    if "S" in first:
        flags.append("SACK")
    if "T" in first:
        flags.append("TIMESTAMPS")
    return ",".join(flags)


def category_from_class(line):
    """Map a Class line's family to Linux, Windows, or Network Device."""
    fields = line[len("Class "):].split("|")
    if len(fields) < 2:
        return None
    family = fields[1].strip().lower()
    if family == "linux":
        return "Linux"
    if family == "windows":
        return "Windows"
    return "Network Device"


def category_from_classes(lines):
    """Pick the first specific (Linux/Windows) class, else Network Device.

    One fingerprint can carry several Class lines.  For example an OEM
    device may be listed first as ``embedded`` and then as ``Linux``.
    Prefer the first Linux/Windows family instead of blindly taking the
    first line.
    """
    fallback = None
    for line in lines:
        category = category_from_class(line)
        if category is None:
            continue
        if fallback is None:
            fallback = category
        if category != "Network Device":
            return category
    return fallback


def test_field(line, test, field):
    """Extract ``%FIELD=value`` (or a leading ``FIELD=value``)."""
    prefix = test + "("
    if not line.startswith(prefix):
        return None
    body = line[len(prefix):]
    if body.endswith(")"):
        body = body[:-1]
    for piece in body.split("%"):
        if piece.startswith(field + "="):
            return piece[len(field) + 1:]
    return None


def parse_fingerprints(path):
    """Yield one dict per complete Fingerprint block."""
    current = None

    def finish(block):
        if block is None:
            return
        block["ttl_raw"] = None
        block["window_raw"] = None
        for test in ("T1", "ECN", "T3"):
            if block.get(test + "_ttl") is not None:
                block["ttl_raw"] = block[test + "_ttl"]
                break
        for test in ("WIN", "ECN", "T3"):
            if block.get(test + "_window") is not None:
                block["window_raw"] = block[test + "_window"]
                break
        block["options_raw"] = block.get("ops_raw", "")
        yield block

    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.rstrip("\r\n")
            if line.startswith("Fingerprint "):
                yield from finish(current)
                current = {"name": line[len("Fingerprint "):].strip(),
                           "classes": []}
                continue
            if current is None:
                continue
            if line.startswith("Class "):
                current["classes"].append(line)
            elif line.startswith("T1("):
                current["T1_ttl"] = test_field(line, "T1", "T")
            elif line.startswith("ECN("):
                current["ECN_ttl"] = test_field(line, "ECN", "T")
                current["ECN_window"] = test_field(line, "ECN", "W")
            elif line.startswith("T3("):
                current["T3_ttl"] = test_field(line, "T3", "T")
                current["T3_window"] = test_field(line, "T3", "W")
            elif line.startswith("WIN("):
                current["WIN_window"] = test_field(line, "WIN", "W1")
            elif line.startswith("OPS("):
                current["ops_raw"] = test_field(line, "OPS", "O1") or ""
    yield from finish(current)


def imported_entries(path, max_entries):
    """Parse path and return (entries, stats)."""
    stats = {
        "fingerprints": 0,
        "no_class": 0,
        "no_ttl": 0,
        "bad_ttl": 0,
        "duplicates": 0,
        "truncated": 0,
    }
    candidates = []
    seen = set()
    for block in parse_fingerprints(path):
        stats["fingerprints"] += 1
        classes = block.get("classes") or []
        if not classes:
            stats["no_class"] += 1
            continue
        name = category_from_classes(classes)
        if name is None:
            stats["no_class"] += 1
            continue
        if block["ttl_raw"] is None:
            stats["no_ttl"] += 1
            continue
        bounds = parse_ttl(block["ttl_raw"])
        if bounds is None:
            stats["bad_ttl"] += 1
            continue
        low, high = bounds
        window = parse_window(block["window_raw"] or "")
        options = parse_options(block["options_raw"] or "")
        entry = Entry(name, low, high, window, options, len(candidates))
        key = entry.key()
        if key in seen:
            stats["duplicates"] += 1
            continue
        seen.add(key)
        candidates.append(entry)

    selected = select_entries(candidates, max_entries)
    stats["truncated"] = len(candidates) - len(selected)
    return selected, stats


def select_entries(candidates, max_entries):
    """Take a balanced, specificity-first sample across categories."""
    groups = {name: [] for name in CATEGORIES}
    for entry in candidates:
        groups[entry.name].append(entry)
    for name in CATEGORIES:
        groups[name].sort(key=lambda e: (
            0 if e.window != 0 else 1,
            e.max_ttl - e.min_ttl,
            e.order,
        ))

    selected = []
    positions = {name: 0 for name in CATEGORIES}
    while len(selected) < max_entries:
        progressed = False
        for name in CATEGORIES:
            if len(selected) >= max_entries:
                break
            position = positions[name]
            if position < len(groups[name]):
                selected.append(groups[name][position])
                positions[name] = position + 1
                progressed = True
        if not progressed:
            break
    return selected


def write_db(out, entries, source):
    out.write("# ALmap os-signatures.db generated by "
              "tools/import_nmap_os.py (Step 29).\n")
    out.write("# Source: {}\n".format(source))
    out.write("# Format: OS_NAME|MIN_TTL|MAX_TTL|WINDOW_SIZE|"
              "TCP_OPTIONS_FLAG\n")
    out.write("# Entry count: {}\n".format(len(entries)))
    for entry in entries:
        out.write("{}|{}|{}|{}|{}\n".format(
            entry.name, entry.min_ttl, entry.max_ttl, entry.window,
            entry.options))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Import an Nmap nmap-os-db file into ALmap "
                    "os-signatures.db")
    parser.add_argument("os_db", help="path to nmap-os-db")
    parser.add_argument("-o", "--output", default="-",
                        help="output file (default: stdout)")
    parser.add_argument("--max", type=int, default=MAX_ENTRIES,
                        help="maximum entries to emit (1..20000, default 20000; full DB)")
    parser.add_argument("--quiet", action="store_true",
                        help="do not print the summary to stderr")
    args = parser.parse_args(argv)

    if args.max < 1 or args.max > MAX_ENTRIES:
        parser.error("--max must be 1..{}".format(MAX_ENTRIES))
    if not os.path.isfile(args.os_db):
        parser.error("nmap-os-db file not found: " + args.os_db)

    entries, stats = imported_entries(args.os_db, args.max)

    if not args.quiet:
        print("imported {} OS signature(s) from {}".format(
            len(entries), args.os_db), file=sys.stderr)
        print("  fingerprints: {}  skipped without class: {}  "
              "without TTL: {}  bad TTL: {}".format(
                  stats["fingerprints"], stats["no_class"],
                  stats["no_ttl"], stats["bad_ttl"]), file=sys.stderr)
        print("  duplicates: {}  not selected: {}".format(
            stats["duplicates"], stats["truncated"]), file=sys.stderr)
        counts = {name: 0 for name in CATEGORIES}
        for entry in entries:
            counts[entry.name] += 1
        print("  selected: " + "  ".join(
            "{} {}".format(name, counts[name]) for name in CATEGORIES),
            file=sys.stderr)

    if args.output == "-":
        write_db(sys.stdout, entries, args.os_db)
    else:
        with open(args.output, "w", encoding="utf-8") as handle:
            write_db(handle, entries, args.os_db)
    return 0


if __name__ == "__main__":
    sys.exit(main())
