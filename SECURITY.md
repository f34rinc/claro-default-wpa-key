# Security & Responsible Disclosure

This repository documents a **factory-default Wi-Fi key weakness** in a range of
older Claro (Brazil) cable gateways, and ships a tool that derives that default
key from public radio data for **authorised, defensive research**. This page
explains how the finding is handled responsibly, what is deliberately withheld,
and how to report things.

## Status of the weakness

- **Model/era-specific and already remediated by the vendor going forward.** The
  weakness affects gateways manufactured **~2021 and earlier**. Hardware from
  **~2022 onward ships full-entropy random keys and is not affected** — the fix
  is proven and already shipping. This is therefore documentation of a
  **known-class, vendor-remediated** weakness affecting a legacy installed base,
  **not** a novel or unpatched 0-day.
- The residual risk is entirely the **installed base of older units still on
  their factory-default SSID *and* password**. Changing either removes the
  exposure — that is the fix, and it is in the owner's hands.

## What this project deliberately does NOT publish

To keep disclosure responsible, the public repository contains **no real
credential material**:

- Every MAC, SSID, password and hash shown in the docs, the tool, and the visual
  briefings is a **fabricated example**.
- Real per-device evidence (actual MACs, SSIDs, recovered keys, capture files)
  and any wardriving data (which carries per-AP **GPS coordinates**) are kept in
  **local, git-ignored files** and are never committed or distributed.
- Aggregate figures (e.g. vendor OUI counts) are derived from public radio
  identifiers only; individual networks are not enumerated.

## If you own an affected gateway

**Change your Wi-Fi password** to a long, random passphrase (and ideally rename
the SSID so it no longer echoes the device MAC). Once the password is no longer
the MAC-derived default, none of this applies. See the *Defensive guidance*
section of [CLARO_DEFAULT_KEY_WEAKNESS.md](CLARO_DEFAULT_KEY_WEAKNESS.md#12-defensive-guidance).

## If you are Claro or an affected hardware vendor

Contact is welcome. Open a GitHub issue (or a private
[GitHub Security Advisory](https://docs.github.com/en/code-security/security-advisories)
on this repository) and the maintainer will share the underlying per-device
detail **privately** — it is intentionally not published here. The constructive
ask is simply the fix already deployed on newer hardware: provision per-device
random keys and never derive the SSID and the key from the same broadcast
identifier.

Brazilian users and vendors may also route coordinated reports through
**[CERT.br](https://www.cert.br/)**, the national CERT.

## Reporting a problem with the tool itself

For a bug or a security issue in `claro_wpa_key.py` or the other scripts (as
opposed to the Claro weakness they describe), please open a
[GitHub Security Advisory](https://docs.github.com/en/code-security/security-advisories)
or a regular issue. There is no sensitive server-side component — everything runs
locally on the user's machine.

## Acceptable use

This project is for **authorised auditing of your own or explicitly consented
equipment**, and for defensive and educational research. Capturing handshakes
from, or attempting to access, networks you do not own or have documented
permission to test is illegal in most jurisdictions. You are solely responsible
for how you use it. See [CONTRIBUTING.md](CONTRIBUTING.md) for what may and may
not be submitted (never passwords, captures, GPS, or a full home BSSID+SSID
pair).
