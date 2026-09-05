#!/usr/bin/env python3
"""
charset_mask.py
------------------------------------------------------------
General utility: read a .hc22000 file, pull each network's BSSID + SSID, and
build a hashcat mask attack whose custom charset is ONLY the (uppercase) hex
characters that appear in that network's BSSID and in the SSID's hex runs.

Why it can help: some WPA hex keys are derived from the device MAC, whose hex
digits surface in the BSSID and in the SSID. Restricting the mask alphabet to
just those characters keeps such a key inside the keyspace while making it much
smaller than the full 0-9A-F space -- when the alphabet is small. It is a generic
keyspace-reduction helper, not tied to any one vendor or scheme.

The SSID contributes its hex RUNS -- 2+ adjacent hex chars, anywhere in the name,
not just the tail. Isolated hex-valid letters in a name are skipped, and only hex
characters (0-9 A-F) are kept: a WPA hex key cannot contain anything else.

Key length: tries MIN_LEN..MAX_LEN characters. Default 8 (WPA-PSK minimum). Set
MAX_LEN > MIN_LEN to emit a hashcat --increment command that also tries longer
keys -- note the keyspace grows by a factor of the charset size per extra char.

The optional --positional (-p) tier goes further: instead of one charset for all
positions, it builds a PER-POSITION charset from the aligned BSSID + SSID chars.
Where they agree (the high bytes) the position is a fixed literal; only where they
diverge (the low byte) does it vary. Measured across ~1400 real MAC-derived
gateways that collapses the keyspace from ~10^8 to a median of 4 (max 64) while
still containing the key. It's a fast heuristic, not exhaustive — the uniform mask
stays the guaranteed fallback.

Usage:
    python charset_mask.py capture.hc22000
    python charset_mask.py --positional capture.hc22000   (add the aggressive tier)
    python charset_mask.py            (no args -> prompts / drag-drop friendly)

For authorised auditing of your own / consented equipment only.
"""

import os
import re
import sys

HASH_MODE  = 22000     # WPA/WPA2 (hashcat mode 22000)
MIN_LEN    = 8         # shortest key length to try (WPA-PSK minimum is 8)
MAX_LEN    = 8         # longest key length to try; > MIN_LEN emits --increment
MIN_RUN    = 2         # min length of an SSID hex run to include (2 = "adjacent")
HEX        = set("0123456789ABCDEF")
RATES      = (150_000,)   # H/s baseline for time estimates (measured -m 22000 avg)


def parse_22000(path):
    """[{essid, bssid}] for each unique network in a .hc22000 file."""
    seen = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or not line.upper().startswith("WPA"):
                continue
            parts = line.split("*")
            if len(parts) < 6:
                continue
            bssid = parts[3].lower()
            if len(bssid) != 12 or any(c not in "0123456789abcdef" for c in bssid):
                continue
            try:
                essid = bytes.fromhex(parts[5]).decode("utf-8", "replace")
            except ValueError:
                essid = ""
            key = (bssid, parts[5])
            if key not in seen:
                seen[key] = {"essid": essid, "bssid": bssid}
    return list(seen.values())


def ssid_hex_runs(essid):
    """All contiguous hex runs in the SSID with length >= MIN_RUN (anywhere).

    We take runs of ADJACENT hex chars, not just the trailing tail and not every
    hex-valid char in the name. A run (2+ in a row) is likely MAC-derived data;
    isolated hex-valid letters in a NAME (e.g. the single A in "CLARO") are skipped
    so they don't bloat the charset. Including a run only ever WIDENS the alphabet,
    never drops a needed char, so this is a safe superset of the tail-only rule.
    """
    return re.findall(r'[0-9A-Fa-f]{%d,}' % MIN_RUN, essid or "")


def hex_charset(bssid, essid):
    """Distinct uppercase hex chars in the BSSID + the SSID's hex runs, sorted."""
    pool = set((bssid + "".join(ssid_hex_runs(essid))).upper()) & HEX
    return "".join(sorted(pool))


def positional_candidates(bssid, essid, keylen):
    """Per-position candidate chars for a MAC-derived hex key: align the BSSID's
    last <keylen> hex to the key, and the SSID's longest hex run to the key's tail.
    Returns a list of <keylen> sets. Where BSSID and SSID agree at a position the
    set is 1 char (a literal); where they diverge — typically the low byte — it's 2.

    This is the basis of the aggressive --positional mask. It collapses the
    keyspace enormously (measured median 4, max 64 across ~1400 real gateways),
    but it ASSUMES each key char comes from that position's BSSID/SSID char — true
    for MAC-derived schemes, NOT guaranteed for an unknown one."""
    b = bssid.upper()
    bpart = b[-keylen:] if len(b) >= keylen else b.rjust(keylen, "0")
    runs = [r.upper() for r in ssid_hex_runs(essid)]
    tail = (max(runs, key=len) if runs else "")[-keylen:]
    tstart = keylen - len(tail)
    cand = []
    for i in range(keylen):
        s = set()
        if i < len(bpart) and bpart[i] in HEX:
            s.add(bpart[i])
        if tstart <= i < keylen and tail[i - tstart] in HEX:
            s.add(tail[i - tstart])
        cand.append(s or set("0123456789ABCDEF"))
    return cand


def positional_command(path, cand):
    """hashcat command from per-position candidate sets: size-1 positions become
    literal mask chars, multi-char positions get custom charsets (-1..-4). Rare
    overflow (>4 distinct multi-char sets) widens a position to ?H (all hex),
    which keeps the key in-keyspace. Returns (command, keyspace)."""
    charsets, mask, ks = [], "", 1
    for s in cand:
        ks *= len(s)
        if len(s) == 1:
            mask += next(iter(s))
            continue
        cs = "".join(sorted(s))
        if cs in charsets:
            mask += f"?{charsets.index(cs) + 1}"
        elif len(charsets) < 4:
            charsets.append(cs)
            mask += f"?{len(charsets)}"
        else:
            mask += "?H"                       # overflow: wider but still contains the key
    args = " ".join(f"-{i + 1} {c}" for i, c in enumerate(charsets))
    return re.sub(r"\s{2,}", " ", f'hashcat -m {HASH_MODE} -a 3 "{path}" {args} {mask}'), ks


def human_time(seconds):
    if seconds < 1:      return "< 1 s"
    if seconds < 90:     return f"{seconds:.1f} s"
    if seconds < 5400:   return f"{seconds/60:.1f} min"
    if seconds < 172800: return f"{seconds/3600:.1f} h"
    return f"{seconds/86400:.1f} days"


def report(path, net, positional=False):
    bssid = net["bssid"]
    essid = net["essid"]
    charset = hex_charset(bssid, essid)

    bssid_fmt = ":".join(bssid[i:i+2] for i in range(0, 12, 2)).upper()
    runs = [r.upper() for r in ssid_hex_runs(essid)]
    print("-" * 70)
    print(f"  SSID     : {essid or '(hidden/none)'}")
    print(f"  BSSID    : {bssid_fmt}")
    print(f"  SSID hex : {', '.join(runs) or f'(no hex run >= {MIN_RUN})'}   (runs >= {MIN_RUN}; charset = BSSID hex + these)")

    if not charset:
        print("  !! no hex characters found in BSSID/SSID -- cannot build a charset.")
        return

    n = len(charset)
    print(f"  Charset : {charset}   ({n} distinct hex chars)")

    if MIN_LEN == MAX_LEN:
        ks = n ** MIN_LEN
        print(f"  Keyspace: {n}^{MIN_LEN} = {ks:,} candidates")
        est = "   ".join(f"~{human_time(ks/r)} @ {r//1000}K H/s" for r in RATES)
        print(f"  Est.    : {est}")
        mask = "?1" * MIN_LEN
        cmd = f'hashcat -m {HASH_MODE} -a 3 "{path}" -1 {charset} {mask}'
    else:
        print(f"  Keyspace by length ({MIN_LEN}-{MAX_LEN}):")
        total = 0
        for L in range(MIN_LEN, MAX_LEN + 1):
            ks = n ** L
            total += ks
            print(f"    len {L:2}: {n}^{L} = {ks:,}   (~{human_time(ks/RATES[0])} @ {RATES[0]//1000}K)")
        print(f"    total : {total:,}   (~{human_time(total/RATES[0])} @ {RATES[0]//1000}K)")
        mask = "?1" * MAX_LEN
        cmd = (f'hashcat -m {HASH_MODE} -a 3 "{path}" -1 {charset} '
               f'--increment --increment-min {MIN_LEN} --increment-max {MAX_LEN} {mask}')
    print(f"  Command :\n    {cmd}")

    if positional:
        cmd_p, ks_p = positional_command(path, positional_candidates(bssid, essid, MIN_LEN))
        print(f"  Positional (aggressive) - keyspace {ks_p} candidate(s):")
        print(f"    {cmd_p}")
        print(f"    ^ per-position charset from the aligned BSSID+SSID; assumes each")
        print(f"      key char sits at that position (true for MAC-derived schemes).")
        print(f"      The uniform command above is the exhaustive fallback.")


def main():
    argv = [a.strip().strip('"') for a in sys.argv[1:]]
    positional = any(a in ("--positional", "-p") for a in argv)
    args = [a for a in argv if a not in ("--positional", "-p")]
    if not args:
        p = input("Drag a .hc22000 file here, or paste its path: ").strip().strip('"')
        if p:
            args = [p]
    if not args:
        print("No file given.")
        return

    for path in args:
        path = os.path.abspath(path)
        print("=" * 70)
        print(f"File: {path}")
        if not os.path.isfile(path):
            print("  !! not found")
            continue
        nets = parse_22000(path)
        if not nets:
            print("  !! no valid WPA*01/WPA*02 lines (is this a .hc22000?)")
            continue
        for i, net in enumerate(nets, 1):
            print(f"\nNetwork {i}/{len(nets)}")
            report(path, net, positional)


if __name__ == "__main__":
    main()
