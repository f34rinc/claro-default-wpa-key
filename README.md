# CLARO Default WPA Key

[![tests](https://github.com/f34rinc/claro-default-wpa-key/actions/workflows/ci.yml/badge.svg)](https://github.com/f34rinc/claro-default-wpa-key/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python 3.6+](https://img.shields.io/badge/python-3.6%2B-blue.svg)
![Platform: Windows · macOS · Linux](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)
![Dependencies: stdlib only](https://img.shields.io/badge/deps-stdlib%20only-brightgreen.svg)
[![Use: authorized / defensive](https://img.shields.io/badge/use-authorized%20%2F%20defensive-critical.svg)](SECURITY.md)

**🇧🇷 Em português:** [documento técnico](CLARO_DEFAULT_KEY_WEAKNESS.pt.md) · [informe visual](https://legoclan.com/Claro/weakness.pt.html)

**Derive** the **factory-default** Wi-Fi password of **affected** Claro cable
gateways from the broadcast **SSID + BSSID alone** (or a single captured
handshake) — **but only while the gateway is still on its factory SSID *and*
password. Change either and there's nothing to derive: that's the fix.**

On affected gateways the factory default key is derived from the device MAC.
The broadcast SSID (e.g. `CLARO_2G3A9C2D`) leaks **6 of the 8** password
characters (the MAC's last 6 hex), and the missing leading byte is the MAC's
3rd octet — part of the vendor OUI, which the Wi-Fi **BSSID** also carries. So
the whole key is usually derivable from the **BSSID + SSID alone** (often 1
guess, no handshake); worst case it's a **256-guess** mask against a handshake,
resolved in well under a second. `claro_wpa_key.py` reads the SSID from a capture,
builds the `?H?H<tail>` mask, and (optionally) runs hashcat.

> **Affected hardware only.** This works on older Claro gateways (~2021 and
> earlier). Newer hardware (~2022+) ships full-entropy random keys and is **not**
> affected — see *Affected devices* below. A `CLARO_<hex>` SSID means *worth
> testing*, never *guaranteed vulnerable*.

For the full write-up of *why* the scheme is weak, see
[CLARO_DEFAULT_KEY_WEAKNESS.md](CLARO_DEFAULT_KEY_WEAKNESS.md) (renders on GitHub).
An interactive visual version is live at
**[legoclan.com/Claro/weakness.html](https://legoclan.com/Claro/weakness.html)**
(the `docs/` folder holds the source).

---

## Affected devices

The weakness is **model/era-specific, not vendor-specific.** It was verified
against **10 Claro gateways from 7 hardware vendors**:

- **Affected (MAC-derived key):** 5 devices, manufactured **2019–2021**, across 5
  vendors — the default Wi-Fi password equals the last 8 hex of the device MAC.
- **Not affected (random key):** 5 devices, manufactured **2022+** — full-entropy
  random passwords with no relation to the MAC.

The same vendor can appear on both sides (older model vulnerable, newer model
not), so **neither the vendor nor the `CLARO_` SSID name tells you** — treat any
`CLARO_<band><hex>` SSID as *worth testing*, not *guaranteed vulnerable*. The
tool simply finds no match on a random-key device, which is the correct answer.

**It's widespread and current.** Beyond the 10 hands-on devices, a passive
wardriving survey of one metro area (recent) found **over 1,000 distinct Claro
gateways still broadcasting a factory `CLARO_` SSID** (1,389 BSSIDs once each
unit's extra radios are counted) across 20+ vendor OUI blocks — every one leaking
its 6-hex tail, and every one single-OUI (leading byte readable straight off the
BSSID). So the "one guess off the beacon" case is the norm for the default-SSID
population the tool targets.

**One honest caveat on the split-OUI exception:** split-OUI hardware
(ARRIS/CommScope — see below) barely shows up in that count, but that is *not*
evidence it's rare. You can't tell split from single by a beacon alone, and split
units that were **renamed** drop out of the default-SSID count entirely. Scanning
the same captures directly for the ARRIS router OUI found **three distinct** ARRIS
gateways — **every one renamed**. Treat single-OUI as the norm *among the vendors
confirmed single-block*, and ARRIS/CommScope as a real split class a passive scan
under-counts, not a unicorn.

Full per-device evidence (real models, MACs, dates) is kept in a local,
git-ignored `EVIDENCE.md` — it contains real credential material and is not
published here. See
[CLARO_DEFAULT_KEY_WEAKNESS.md](CLARO_DEFAULT_KEY_WEAKNESS.md) §10–§11 for the
aggregate evidence and scope.

---

## ⚠️ Authorized use only

This is a security-research / recovery tool. Use it **only** on:

- networks you own, or
- networks you have **explicit, documented permission** to test.

Capturing handshakes from, or attempting to access, networks you do not own or
have permission to test is illegal in most jurisdictions. You are solely
responsible for how you use this. It works **only** while a gateway is on its
factory-default SSID *and* password — a renamed SSID or a user-changed password
cannot be derived this way, which is exactly why changing the default is the fix.

---

## How it works (TL;DR)

```
default SSID     = CLARO_<band><last 6 hex of device MAC>   e.g. CLARO_2G3A9C2D
default password = <last 8 hex of device MAC>, UPPERCASE     e.g. C23A9C2D
```

The SSID tail (`3A9C2D`) is the known **6 of 8** password characters. The
leading byte is the MAC's 3rd octet (`C2`) — part of the vendor **OUI**, which
the Wi-Fi **BSSID also carries** on the common **single-OUI** gateway (radio and
modem in one vendor block). So it's usually readable straight off the beacon,
giving the whole key with **no handshake**:

```
BSSID octet 3 (C2) + SSID tail (3A9C2D)  →  password C23A9C2D   (often 1 guess)
```

If octet 3 can't be read — a **split-OUI** gateway (ARRIS/CommScope units put the
Wi-Fi radio on a *different* OUI block than the modem, e.g. radio `C8:52:61` vs
modem `A8:70:5D`) — fall back to a 256-guess mask against a handshake:

```
password = ?H?H 3A9C2D      →  ?H = uppercase hex 0-9A-F  →  256 candidates
```

## Requirements

- **Python 3.6+** — standard library only, no `pip install` needed.
- **[hashcat](https://hashcat.net/hashcat/)** — to actually run the crack.
  The script auto-detects `hashcat` on your `PATH` and in common install dirs,
  or set `HASHCAT_EXE` at the top of the script to a full path.
- A capture in **hashcat `22000`** format (`.hc22000`), e.g. produced by
  [hcxtools / hcxpcapngtool](https://github.com/ZerBea/hcxtools) from a `.pcapng`.

## Usage

One cross-platform command — Windows, macOS, and Linux, no GUI:

```bash
# interactive: run it, then drag capture file(s) into the window or paste path(s)
python claro_wpa_key.py

# or pass one or more captures directly
python claro_wpa_key.py capture.hc22000 [more.hc22000 ...]

# flags: -y auto-run hashcat · -n print only · -d derive+save (no handshake) · -h help
python claro_wpa_key.py -y capture.hc22000
```

### Sample run

Point it at a capture and it derives the key straight from the beacon — no
handshake needed on a single-OUI gateway *(all data below is fabricated)*:

```text
$ python claro_wpa_key.py sample.hc22000

======================================================================
  CLARO Default WPA Key   -   sample.hc22000
  1 network(s) in this capture
======================================================================

[ network 1/1 ] ------------------------------------------------------

  SSID        CLARO_5G345678
  BSSID       AA:BB:12:DD:EE:00
  Vendor      AA:BB:12  (not a known Claro block - may still be valid)

  LIKELY KEY  12345678
              = BSSID octet 3 (12) + SSID tail (345678)
              Single-OUI gateway: type this straight in - no handshake needed.
              (copied to clipboard)

  hashcat  (run from this file's folder)
    1-guess    hashcat -m 22000 -a 3 sample.hc22000 12345678
    256-guess  hashcat -m 22000 -a 3 sample.hc22000 ?H?H345678
```

Output is **colorized** on a real terminal (Windows/macOS/Linux) and plain when
piped or redirected; force it with `--color always`, or disable via `--no-color`
or the `NO_COLOR` env var.

Choose the workflow that fits: let it run hashcat (`-y` / the default prompt), or
skip the handshake entirely with **`-d`** — it derives the likely key from the
BSSID + SSID and saves it (marked *unconfirmed*) so you can harvest keys straight
from a scan. Split-OUI gateways are not derive-saved (their derived byte is
probably wrong); those still need a handshake.

Running it with no arguments opens an interactive prompt, and **dragging a
capture onto the script keeps the window open afterward** (even when the capture
has no `CLARO_` networks) so you can read the result and drop in more files —
nothing vanishes on you, and nothing platform-specific to install. The prompt
lists the flags and lets you **type one inline** (e.g. `-d`) to switch mode
between files.

For each network the tool prints the SSID/BSSID/vendor, the **likely key**
(`BSSID octet 3 + SSID tail`, copied to your clipboard — just type it in), and
the ready-to-run hashcat commands. If hashcat is found it offers to run them and
reports the cracked key.

Any **hashcat-confirmed** key is appended to **`claro_cracked.txt`** (in the
current folder) as a timestamped `SSID / BSSID / password / method` row. That
file is **real credential material** — it's git-ignored and must never be
committed or shared. Pass `--no-save` to turn the log off.

### Just the raw command

If you'd rather skip the script, the whole attack is one line — take the last
6 hex of the SSID and prepend `?H?H`:

```bash
hashcat -a 3 -m 22000 capture.hc22000 ?H?H3A9C2D
```

- `-m 22000` — WPA-PBKDF2 (the `.hc22000` handshake format)
- `-a 3` — mask / brute-force mode
- `?H?H` — the 2 unknown chars, **uppercase** hex `0-9A-F` (use `?H`, not `?h`)
- `3A9C2D` — the literal 6-hex SSID tail (= the known 6 of 8 password chars)

## Limitations

- Only **affected** (pre-2022) Claro gateways on their factory-default SSID +
  password. Random-key models (2022+) and renamed/re-keyed networks won't match.
- Only handles SSIDs still in `CLARO_<band><hex>` form.
- The tool derives the likely key (`BSSID octet 3 + tail`) and tries that **1
  guess** first; split-OUI gateways (ARRIS/CommScope) need the `?H?H<tail>`
  **256-guess** fallback against a handshake. On single-OUI gateways you can skip
  the handshake entirely (see *How it works*); split can't be told apart from a
  beacon alone, so if the 1-guess misses, that's the case the fallback is for.
- The scheme is **uppercase** hex; for a lowercase variant, re-run with `?h?h`.

## Utilities

General helpers, not specific to the Claro scheme.

- [utils/charset_mask.py](utils/charset_mask.py) — reads a `.hc22000`, pulls each
  network's BSSID + SSID, and prints a hashcat mask command whose custom charset
  is only the uppercase hex characters present in that BSSID + SSID hex tail. A
  generic keyspace-reduction helper. Standalone, stdlib only.
  `python utils/charset_mask.py capture.hc22000`

## Defensive takeaway

If you own one of these gateways: **change the default Wi-Fi password** (and
ideally the SSID). Once the password is no longer the MAC-derived default, none
of the above applies.

## Contributing

New device/OUI data points and corrections are welcome — they widen the evidence
base and keep the tool current. The flow is built to collect only **non-sensitive,
aggregatable** signal: **never** submit passwords, captures/handshakes, GPS, or
the full BSSID **and** SSID of a real home network.

- **Quick data point** → open the *"New OUI / device / SSID variant"* issue.
- **Add a vendor OUI** → one-line PR to [`data/claro_ouis.csv`](data/claro_ouis.csv)
  (the tool loads it at runtime — no code change needed).

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full "helpful vs. never-submit"
lists.

## Security & disclosure

This documents a weakness that the vendor has **already remediated on 2022+
hardware** — the residual risk is the legacy installed base still on factory
defaults, and changing the key removes it. The repo carries **no real credential
material** (all examples fabricated; real evidence and any GPS-bearing data kept
private and git-ignored). If you're an affected owner, Claro, or a hardware
vendor, see [SECURITY.md](SECURITY.md) for the responsible-disclosure posture and
contact paths (including [CERT.br](https://www.cert.br/)).

## License

[MIT](LICENSE) — © 2026 F34RInc. See the file for the full text.
