#!/usr/bin/env python3
"""
analyze_wigle.py
------------------------------------------------------------
Bulk-analyze a WiGLE wardriving export (.kml or WiGLE .csv) for affected Claro
gateways, and summarize what it tells us about the default-key weakness.

For every AP whose SSID is a factory-default Claro name (CLARO_<band><hex> and
the field variants), it:

  * extracts the SSID + BSSID (the beacon data - no handshake needed),
  * classifies the gateway single-OUI vs split-OUI (does the password's leading
    byte read straight off the BSSID?), which is the whole basis of the "one
    guess off the beacon" claim,
  * builds an OUI / vendor histogram, and
  * flags any OUI block NOT yet in data/claro_ouis.csv, formatted as a
    ready-to-paste CSV row so you can widen the table via a one-line PR.

Privacy: WiGLE exports carry a per-AP GPS fix. This tool NEVER reads or emits
coordinates, and the console summary is aggregate. Full per-gateway output
(--detail / --out) still lists BSSID+SSID pairs, which are sensitive for real
home networks - keep those local, never publish them. Raw .kml/.csv inputs and
any saved report are git-ignored for the same reason.

Usage:
    python tools/analyze_wigle.py capture.kml [more.kml capture.csv ...]
    python tools/analyze_wigle.py *.kml --out wigle_report.txt   # full report to a file
    python tools/analyze_wigle.py capture.kml --detail           # per-gateway rows on screen
    python tools/analyze_wigle.py capture.kml --rows             # only the new-OUI CSV rows
"""

import os
import re
import sys
import csv
import glob
import argparse
from collections import Counter, OrderedDict

# Reuse the exact SSID/OUI logic the recovery tool uses, so this analyzer and
# claro_wpa_key.py can never disagree about what counts as a default Claro SSID
# or a split-OUI block. The script sits in tools/; the module is one level up.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from claro_wpa_key import parse_claro_ssid, oui_of, OUI_VENDORS, SPLIT_OUIS
except Exception as exc:                                   # pragma: no cover
    sys.exit(f"error: couldn't import claro_wpa_key.py (run this from the repo): {exc}")


# ---- input parsing ----------------------------------------------------------

_MAC_RE  = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")
_NAME_RE = re.compile(r"<name>(.*?)</name>", re.IGNORECASE | re.DOTALL)
_NETID_RE = re.compile(r"Network ID:\s*" + _MAC_RE.pattern, re.IGNORECASE)
_PLACEMARK_RE = re.compile(r"<Placemark\b.*?</Placemark>", re.IGNORECASE | re.DOTALL)


def _norm_bssid(mac):
    """'A0:B1:C2:0C:E4:59' -> 'a0b1c20ce459' as bare 12-hex lowercase, or None."""
    h = re.sub(r"[^0-9A-Fa-f]", "", mac or "").lower()
    return h if len(h) == 12 else None


def _unescape(s):
    return (s.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
             .replace("&quot;", '"').replace("&#39;", "'").strip())


def parse_kml(path):
    """Yield {essid, bssid} for each Placemark. WiGLE puts the SSID in <name> and
    the BSSID after 'Network ID:' in <description>. Coordinates are ignored."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    for block in _PLACEMARK_RE.findall(text):
        nm = _NAME_RE.search(block)
        nid = _NETID_RE.search(block)
        if not nid:
            continue
        bssid = _norm_bssid(nid.group(1))
        if not bssid:
            continue
        essid = _unescape(re.sub(r"<!\[CDATA\[|\]\]>", "", nm.group(1))) if nm else ""
        yield {"essid": essid, "bssid": bssid}


def parse_wigle_csv(path):
    """Yield {essid, bssid} from a WiGLE CSV export. Line 1 is a 'WigleWifi-1.x'
    pre-header; row columns are MAC,SSID,AuthMode,... Coordinates are ignored."""
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        first = fh.readline()
        if not first.lower().startswith("wiglewifi"):
            fh.seek(0)                                     # no pre-header; DictReader reads row 1 as header
        reader = csv.DictReader(fh)
        for row in reader:
            mac = row.get("MAC") or row.get("mac") or ""
            bssid = _norm_bssid(mac)
            if not bssid:
                continue
            if (row.get("Type") or row.get("type") or "WIFI").upper() not in ("", "WIFI"):
                continue                                   # skip BT/cell rows
            yield {"essid": (row.get("SSID") or row.get("ssid") or "").strip(),
                   "bssid": bssid}


def parse_any(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".kml":
        return parse_kml(path)
    if ext in (".csv", ".txt"):
        return parse_wigle_csv(path)
    # sniff: KML files start with an XML/kml tag
    with open(path, encoding="utf-8", errors="replace") as fh:
        head = fh.read(256).lower()
    return parse_kml(path) if ("<kml" in head or "<?xml" in head) else parse_wigle_csv(path)


# ---- classification ---------------------------------------------------------

def is_local_admin(bssid):
    """True if the BSSID's U/L bit (0x02 of octet 1) is set. Such addresses are
    LOCALLY ADMINISTERED - not IEEE-registered OUIs. A gateway mints them off its
    real MAC (U/L bit flipped) for its extra SSIDs: guest, mesh backhaul (-5G-BH),
    IoT. They belong to no vendor and must never be added to the OUI table."""
    return bool(int(bssid[0:2], 16) & 0x02)


def base_oui_of(bssid_or_oui):
    """The universally-administered OUI a locally-administered address was minted
    from: clear the U/L bit on octet 1. Flipping that bit never touches octet 3,
    so the password's leading byte still reads off the beacon - the single-OUI
    derivation survives on these secondary/virtual BSSIDs. 'XX:XX:XX'."""
    o1 = int(bssid_or_oui[0:2], 16) & ~0x02
    rest = bssid_or_oui[3:8] if ":" in bssid_or_oui[:3] else f"{bssid_or_oui[2:4]}:{bssid_or_oui[4:6]}"
    return f"{o1:02X}:{rest.upper()}"


def ssid_variant(essid):
    """Human label for the default-SSID shape (mesh backhaul, IoT, banded, ...)."""
    e = essid.upper()
    if "-5G-BH" in e:
        return "mesh backhaul (-5G-BH)"
    if e.endswith("-IOT") or "-IOT" in e:
        return "IoT (-IoT)"
    if re.match(r"^CLARO_(2\.4G|2G)", e):
        return "banded 2.4GHz"
    if re.match(r"^CLARO_5G", e):
        return "banded 5GHz"
    return "no-band"


def classify(net):
    """-> dict with the diagnostic for one default-Claro gateway, or None if the
    SSID isn't a factory-default CLARO_ name (renamed / non-default AP)."""
    tail6, full8 = parse_claro_ssid(net["essid"])
    if not tail6:
        return None
    oui = oui_of(net["bssid"])
    local = is_local_admin(net["bssid"])
    base = base_oui_of(net["bssid"]) if local else oui
    # A locally-administered BSSID is a secondary radio; look up its vendor by the
    # real (base) OUI. split-OUI is a property of the real block, so test base too.
    vendor = OUI_VENDORS.get(oui) or (OUI_VENDORS.get(base) if local else None)
    if full8:
        kind = "full-8 (determined)"
    elif base in SPLIT_OUIS:
        kind = "split-OUI (256-guess)"
    else:
        kind = "single-OUI (1-guess off beacon)"
    # Confidence hint: do BSSID octets 4-6 equal the SSID tail? (radio MAC == the
    # key-bearing MAC's low 3 bytes). Matches on most single-OUI units; a mismatch
    # with a same-OUI block is the benign Compal case, still single-OUI.
    beacon_tail = net["bssid"][6:12]
    return {
        "essid": net["essid"], "bssid": net["bssid"], "oui": oui,
        "local": local, "base_oui": base, "vendor": vendor, "kind": kind,
        "variant": ssid_variant(net["essid"]),
        "tail_match": (beacon_tail == tail6),
    }


# ---- reporting --------------------------------------------------------------

def analyze(paths):
    by_bssid = OrderedDict()          # dedupe: WiGLE logs each AP many times on a drive
    stats = {"rows": 0, "files": 0, "bad_files": 0}
    non_default_claro = 0
    for path in paths:
        if not os.path.isfile(path):
            print(f"  !! not found: {path}", file=sys.stderr)
            stats["bad_files"] += 1
            continue
        stats["files"] += 1
        try:
            for net in parse_any(path):
                stats["rows"] += 1
                b = net["bssid"]
                if b not in by_bssid or (not by_bssid[b]["essid"] and net["essid"]):
                    by_bssid[b] = net
        except Exception as exc:
            print(f"  !! failed to parse {path}: {exc}", file=sys.stderr)
            stats["bad_files"] += 1

    stats["unique"] = len(by_bssid)
    gateways = []
    split_hw = []                     # ARRIS/CommScope split-OUI hardware, ANY SSID
    for net in by_bssid.values():
        c = classify(net)
        if c:
            gateways.append(c)
        elif net["essid"].upper().startswith("CLARO"):
            non_default_claro += 1
        # A split gateway on a renamed SSID drops out of the default-Claro count
        # entirely (you can't derive a renamed net). Track split HARDWARE by OUI,
        # regardless of SSID, so it stays visible instead of vanishing.
        oui = oui_of(net["bssid"])
        base = base_oui_of(net["bssid"]) if is_local_admin(net["bssid"]) else oui
        if oui in SPLIT_OUIS or base in SPLIT_OUIS:
            tail6, _ = parse_claro_ssid(net["essid"])
            split_hw.append({"bssid": net["bssid"], "essid": net["essid"],
                             "default": bool(tail6)})
    return gateways, stats, non_default_claro, split_hw


def render(gateways, stats, non_default_claro, split_hw, detail=False, rows_only=False):
    lines = []
    ap = lines.append

    known_ouis = set(OUI_VENDORS)
    unknown = OrderedDict()           # REAL (universal) OUIs not in the CSV -> count
    variant_counts = Counter()
    oui_counts = Counter()
    oui_local = {}                    # oui -> is it a locally-administered address?
    single = split = full8 = mismatch = virtual = 0
    for g in gateways:
        variant_counts[g["variant"]] += 1
        oui_counts[g["oui"]] += 1
        oui_local[g["oui"]] = g["local"]
        if g["local"]:
            virtual += 1              # secondary/virtual radio, not a distinct gateway or OUI
        elif g["oui"] not in known_ouis:
            unknown[g["oui"]] = unknown.get(g["oui"], 0) + 1   # a genuinely new vendor block
        if g["kind"].startswith("single"):
            single += 1
            if not g["tail_match"]:
                mismatch += 1
        elif g["kind"].startswith("split"):
            split += 1
        else:
            full8 += 1

    if rows_only:
        return _render_new_rows(unknown, oui_counts)

    total = len(gateways)
    ap("=" * 70)
    ap("  WiGLE Claro-gateway analysis")
    ap("=" * 70)
    ap(f"  files parsed ....... {stats['files']}"
       + (f"  ({stats['bad_files']} unreadable)" if stats["bad_files"] else ""))
    ap(f"  AP records read .... {stats['rows']}   (WiGLE logs each AP many times on a drive)")
    ap(f"  unique APs ......... {stats.get('unique', 0)}")
    ap("")
    ap(f"  default-Claro BSSIDs ........ {total}")
    if virtual:
        ap(f"    of which secondary radios   {virtual}   (locally-administered MAC: guest / mesh / IoT)")
        ap(f"    distinct physical-ish ....  {total - virtual}   (primary BSSIDs only)")
    ap(f"  CLARO_-named but non-default  {non_default_claro}   (renamed / changed key)")
    if not total:
        ap("")
        ap("  No factory-default CLARO_ SSIDs in this capture.")
        ap("=" * 70)
        return "\n".join(lines)

    ap("")
    ap("  --- derivability (the core finding) ------------------------------")
    pct = lambda n: f"{100.0 * n / total:5.1f}%"
    ap(f"  single-OUI (1 guess off the beacon, no handshake) .. {single:5d}  {pct(single)}")
    ap(f"  split-OUI  (256-guess against a handshake) ......... {split:5d}  {pct(split)}")
    ap(f"  full-8 in SSID (key fully determined) .............. {full8:5d}  {pct(full8)}")
    beacon_derivable = single + full8
    ap(f"  -> derivable straight off the beacon ............... {beacon_derivable:5d}  {pct(beacon_derivable)}")
    if mismatch:
        ap(f"     ({mismatch} single-OUI had BSSID tail != SSID tail - benign same-OUI,")
        ap(f"      still 1-guess; the Compal case. Leading byte still = octet 3.)")
    if virtual:
        ap(f"     ({virtual} were secondary/virtual BSSIDs - the U/L bit is flipped in")
        ap(f"      octet 1, never octet 3, so the leading byte still reads off the beacon.)")
    ap("     NOTE: split counts DEFAULT-SSID gateways only. A split unit (e.g. ARRIS)")
    ap("     that was renamed drops out of this population entirely - see below - so a")
    ap("     low split % here is NOT evidence that split hardware is rare. Split cannot")
    ap("     be detected from a beacon alone; it needs a sticker MAC or a handshake.")

    # Split-OUI HARDWARE, by OUI, regardless of SSID. This is the honest counter
    # to a deceptively-low split % above: renamed ARRIS units vanish from the
    # default-Claro count but the hardware is still on the air.
    ap("")
    ap("  --- split-OUI hardware seen (ARRIS/CommScope, ANY SSID) ----------")
    if split_hw:
        dflt = sum(1 for s in split_hw if s["default"])
        ap(f"  {len(split_hw)} BSSID(s) on a known split-OUI router block "
           f"({dflt} on a default CLARO_ SSID, {len(split_hw) - dflt} renamed):")
        ap("  (LOCAL ONLY - real BSSID/SSID)")
        for s in sorted(split_hw, key=lambda x: x["bssid"]):
            tag = "default" if s["default"] else "RENAMED"
            ap(f"    {mac_fmt(s['bssid'])}  {(s['essid'] or '(hidden)'):<24}  [{tag}]")
        ap("  Only the C8:52:61 block is catalogued as split; other CommScope router")
        ap("  OUIs can't be flagged this way, so this is a floor, not a full count.")
    else:
        ap("  None on the catalogued split block (C8:52:61). Not proof of absence:")
        ap("  other CommScope router OUIs aren't flagged, and renamed units are invisible.")

    ap("")
    ap("  --- OUI / vendor histogram ---------------------------------------")
    for oui, n in oui_counts.most_common():
        if oui_local.get(oui):
            base = base_oui_of(oui)
            v = OUI_VENDORS.get(base)
            label = (f"{v}  (2nd BSSID of {base})" if v
                     else f"virtual BSSID of {base}  (not a real OUI - skip)")
            ap(f"  {oui}  {n:5d}  {label}")
            continue
        vendor = OUI_VENDORS.get(oui)
        flag = "  SPLIT-OUI" if oui in SPLIT_OUIS else ""
        if vendor:
            ap(f"  {oui}  {n:5d}  {vendor}{flag}")
        else:
            ap(f"  {oui}  {n:5d}  {'(NEW - not in claro_ouis.csv)'}")

    ap("")
    ap("  --- default-SSID variants ----------------------------------------")
    for variant, n in variant_counts.most_common():
        ap(f"  {n:5d}  {variant}")

    new_rows = _render_new_rows(unknown, oui_counts, as_block=True)
    ap("")
    ap("  --- NEW OUI blocks (not yet in data/claro_ouis.csv) --------------")
    if new_rows:
        ap("  Real (universal) OUIs only - virtual/secondary BSSIDs are excluded.")
        ap("  Paste these into data/claro_ouis.csv (fill in the vendor), then open a")
        ap("  one-line PR. OUI prefixes are public IEEE data - safe to share.")
        ap("")
        for line in new_rows:
            ap(f"  {line}")
    else:
        ap("  None - every real OUI block here is already in the table.")
    if virtual:
        ap(f"  ({virtual} locally-administered BSSIDs were skipped - not real OUIs.)")

    if detail:
        ap("")
        ap("  --- per-gateway detail (LOCAL ONLY - contains real BSSID+SSID) ---")
        for g in sorted(gateways, key=lambda x: (x["base_oui"], x["essid"])):
            v = (g["vendor"] or "?") + (" [2nd]" if g["local"] else "")
            tail = "match" if g["tail_match"] else "diff "
            ap(f"  {mac_fmt(g['bssid'])}  {g['essid']:<22}  {v:<28}  "
               f"{g['kind'].split(' ')[0]:<11}  tail:{tail}")

    ap("=" * 70)
    return "\n".join(lines)


def _render_new_rows(unknown, oui_counts, as_block=False):
    rows = []
    for oui, n in sorted(unknown.items(), key=lambda kv: -kv[1]):
        rows.append(f"{oui},,   # seen {n}x - fill vendor")
    if as_block:
        return rows
    return "\n".join(rows) if rows else "# no new OUIs - all blocks already in claro_ouis.csv"


def mac_fmt(b):
    return ":".join(b[i:i + 2] for i in range(0, 12, 2)).upper()


def main():
    ap = argparse.ArgumentParser(
        prog="analyze_wigle.py",
        description="Summarize a WiGLE .kml/.csv export for affected Claro "
                    "gateways: single-vs-split-OUI derivability, OUI histogram, "
                    "and new-OUI CSV rows for data/claro_ouis.csv.")
    ap.add_argument("paths", nargs="+", help="WiGLE .kml or .csv export(s); globs OK")
    ap.add_argument("--detail", action="store_true",
                    help="also list every gateway (BSSID+SSID) - LOCAL use only")
    ap.add_argument("--rows", action="store_true",
                    help="print ONLY the new-OUI CSV rows (nothing else)")
    ap.add_argument("--out", metavar="FILE",
                    help="also write the full report to FILE (keep it git-ignored)")
    args = ap.parse_args()

    # Expand globs (Windows cmd/PowerShell don't glob for us).
    paths = []
    for p in args.paths:
        hits = glob.glob(p)
        paths.extend(hits if hits else [p])

    gateways, stats, non_default, split_hw = analyze(paths)
    report = render(gateways, stats, non_default, split_hw,
                    detail=args.detail, rows_only=args.rows)
    print(report)

    if args.out and not args.rows:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(report + "\n")
            print(f"\n(report written to {os.path.abspath(args.out)} - git-ignored; keep local)")
        except OSError as exc:
            print(f"\n(could not write {args.out}: {exc})", file=sys.stderr)


if __name__ == "__main__":
    main()
