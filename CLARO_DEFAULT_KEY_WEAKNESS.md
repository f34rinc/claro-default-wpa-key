# Claro Default Wi-Fi Key Weakness (`claro_wpa_key.py`)

🇺🇸 English · [Português](CLARO_DEFAULT_KEY_WEAKNESS.pt.md)

How the factory-default WPA2 password of certain Claro gateways is derived from
the device MAC — so that it can be **derived** from public information alone (or
recovered from a single captured handshake), *as long as the gateway is still on
its factory SSID and password* — why the scheme is weak, which devices are
affected, and what `claro_wpa_key.py` automates.

> **Illustration note:** every MAC address, SSID, password and hash *shown in
> this document* is a fabricated example. The findings are backed by real
> devices; the per-device evidence (with real identifiers) is kept in a private
> file that is **not** part of this repository. See [§10, Evidence](#10-evidence).

> **This is affected-hardware-specific.** The weakness is present on a range of
> older Claro gateways (roughly 2021 and earlier). Newer hardware (roughly 2022
> onward) ships full-entropy random keys and is **not** affected. See
> [§11, Scope](#11-scope--which-devices-are-affected).

---

## 1. TL;DR

An affected factory-default Claro gateway broadcasts an SSID like
`CLARO_2G3A9C2D`. Two things follow from that name alone:

- The SSID **leaks 6 of the 8** characters of the Wi-Fi password (they are the
  last 6 hex of the device MAC).
- The remaining 2 characters are the MAC's 3rd octet — which is part of the
  vendor **OUI**, and the Wi-Fi radio's **BSSID** (in every beacon) is on that
  same OUI. So the "missing" byte is **usually readable too.**

Net effect: on affected devices the entire key is often derivable from **public
radio information** (BSSID + SSID) — no handshake required. In the worst case
(where the last byte cannot be read off the air) it is a **256-guess** brute
force against a captured handshake, resolved offline in well under a second.

- **Nominal strength** of an 8-hex WPA2 key: 2³² (~4.3 billion).
- **Actual strength** on an affected device: **1 to 256 candidates.**

A 24-to-32-bit collapse, for free, just by being in radio range.

---

## 2. Quick command

If you have a handshake as a `.hc22000` file, the fallback attack (brute the one
uncertain byte, tail fixed from the SSID) is a single line:

```bash
hashcat -a 3 -m 22000 capture.hc22000 ?H?H<LAST 6 HEX OF SSID>
```

Example — SSID `CLARO_2G3A9C2D` (tail = `3A9C2D`):

```bash
hashcat -a 3 -m 22000 capture.hc22000 ?H?H3A9C2D
```

- `-m 22000` — WPA-PBKDF2 (the `.hc22000` handshake format)
- `-a 3` — mask / brute-force mode
- `?H?H` — the 2 unknown chars, **uppercase** hex `0-9A-F` (use `?H`, not `?h`) → 256 tries
- `3A9C2D` — the literal 6-hex SSID tail = the known **6 of 8** password chars

Cracks in well under a second. Or let the script build the mask from the capture:

```bash
python claro_wpa_key.py capture.hc22000
```

Often you can skip the handshake entirely — see [§5](#5-the-leading-byte-is-usually-not-secret-either).

---

## 3. The default key scheme

On affected gateways, both the SSID and the Wi-Fi password are computed from the
**device MAC** (the cable-modem/base MAC — *not* the Wi-Fi radio's own MAC):

```
default SSID     = CLARO_<band><last 6 hex of device MAC>   e.g. CLARO_2G3A9C2D
default password = <last 8 hex of device MAC>, UPPERCASE     e.g. C23A9C2D
```

Mapping it to MAC octets. If the device MAC is `AA:BB:C2:3A:9C:2D`:

```
password (8 hex) = C2 3A 9C 2D    <- device MAC octets 3,4,5,6
SSID tail (6 hex) =  3A 9C 2D      <- device MAC octets 4,5,6  (= password chars 3-8)
```

So for `CLARO_2G3A9C2D`:

| Part                 | Value      | Source                                   |
|----------------------|------------|------------------------------------------|
| SSID trailing 6 hex  | `3A9C2D`   | broadcast in the beacon                  |
| = password chars 3-8 | `..3A9C2D` | **known to anyone in range**             |
| password chars 1-2   | `C2`       | device MAC octet 3 — see §5              |
| full password        | `C23A9C2D` | uppercase hex `0-9A-F`                    |

The admin login is derived the same way on affected units (username
`CLARO_<last 6 hex>`, password = the full 12-hex MAC), compounding the exposure.

---

## 4. Why the SSID leak matters: the offline-handshake property

WPA2-PSK authenticates with a 4-way handshake. Anyone who captures that
handshake — passively, or by forcing a reconnect with a deauth — can test
password guesses **offline**: no interaction with the AP, no lockout, no rate
limiting, as fast as the hardware will go.

So a WPA2 network is only ever as strong as the *guessability* of its
passphrase. Here the passphrase space is at most 256, so the handshake is a
formality — milliseconds to try them all.

The captured artifact is a hashcat `-m 22000` line:

```
WPA*02*<MIC>*<AP MAC>*<client MAC>*<ESSID hex>*<nonce>*<eapol>*<msg-pair>
```

`claro_wpa_key.py` parses the ESSID hex out of that line to learn the SSID, then
derives the candidate list — no device MAC needed.

---

## 5. The leading byte is usually *not* secret either

> **This corrects an earlier version of this document,** which claimed the
> leading byte had to be brute-forced across 256 values because "the Wi-Fi radio
> and the modem use unrelated MAC blocks." Measurement against real devices
> shows that is wrong.

The password's leading byte is the device MAC's **octet 3** — and octet 3 is the
last byte of the 3-octet vendor **OUI**. On the **common single-OUI gateway** the
**Wi-Fi radio and the cable modem share that OUI** (their interface MACs sit in
one vendor block), so the radio's **BSSID** — broadcast in every beacon — carries
the same octet 3 as the modem MAC that keys the password:

```
BSSID  (radio, in every beacon) = A0:B1:C2 : xx:xx:xx      OUI = A0:B1:C2
device MAC (keys the password)  = A0:B1:C2 : 3A:9C:2D      OUI = A0:B1:C2  (same)
                                     ^^^^^
password  = C2 3A9C2D            <- leading byte C2 = OUI octet 3 = BSSID octet 3
```

So on a single-OUI device the **full key is derivable from public radio data
(BSSID + SSID) with no handshake at all** — a single guess you can simply try
against the network. Across 1,000+ distinct live default-SSID gateways (see
[§10](#10-evidence)), this is the norm — with the split-OUI caveat noted next.

**The exception — split-OUI gateways.** Some units — **systematically**, the
ARRIS/CommScope models — put the Wi-Fi radio and the cable modem on **different
OUI blocks** — e.g. radio `C8:52:61:…` while the modem that keys the password is
`A8:70:5D:…`. There the BSSID's octet 3 (`61`) is **not** the password's leading
byte (`5D`), so it can't be read off the beacon. This is exactly the case the
**256-guess** fallback exists for: fix the 6-hex tail from the SSID and brute the
one leading byte against a handshake.

A crucial caveat on how common this is: **split cannot be detected from a beacon
alone.** The SSID leaks the *modem's* tail while the BSSID belongs to the *radio*;
on a single-OUI unit they share octet 3, on a split unit they don't — but the
modem's octet 3 is never broadcast, so telling the two apart requires a sticker
MAC or a handshake. In our metro scans, default-SSID gateways were dominated by
single-OUI vendors and split units barely appeared in that population — but that
is **not** evidence that split hardware is rare. Two effects hide it: split
gateways that were **renamed** leave the default-SSID population entirely (you
can't derive a renamed network), and a split unit on any CommScope OUI block we
haven't catalogued reads as single-OUI to a passive scan. Directly scanning the
same captures for the ARRIS router OUI turned up **three** distinct ARRIS
units — all on renamed SSIDs. So treat single-OUI as the norm **among the vendors
confirmed single-block**, and treat ARRIS/CommScope as a real, non-rare split
class that a beacon-only scan systematically under-counts.

Practically: **try `BSSID octet 3 + SSID tail` first** (one guess — works on the
single-OUI majority); if it misses, fall back to the 256-guess mask (covers the
split-OUI minority). `claro_wpa_key.py` does both automatically.

---

## 6. Deductive keyspace: attacking with what the beacon already tells you

The key is a *slice of the MAC*, and the MAC's hex characters are on display in
the BSSID (the OUI) and the SSID (the tail). That makes it possible to attack
the key **deductively** — with a candidate set you can *prove* contains the
answer — instead of brute-forcing the full 2³² hex space. Ordered cheapest-first:

1. **Derive & connect (1 try, no handshake).** `<BSSID octet 3> + <SSID tail>`.
   On an affected device this *is* the key; just try it.
2. **Octet-combo list (~thousands, instant).** Take the distinct 2-hex octets
   seen in the BSSID + SSID and try every 4-octet combination as a small
   wordlist (`hashcat -a 0`). Guaranteed to contain the key when the key's
   octets come from the beacon.
3. **Reduced-charset mask (instant→minutes).** Build a hashcat custom charset
   from only the hex characters present in the BSSID + SSID hex runs, over the
   8 positions. Implemented by [`utils/charset_mask.py`](utils/charset_mask.py).
4. **Full mask (fallback).** `?H?H<tail>` (256) if you trust the tail, or the
   full 2³² hex space as a last resort (~8 h on one consumer GPU at ~150 kH/s —
   note even *this* is not really "secure").

Each tier is a set you can reason about, not a probabilistic guess. Tiers 1–3
are effectively instant.

---

## 7. What `claro_wpa_key.py` does

1. **Parse** the `.hc22000` file → extract each network's `{essid, bssid}`.
2. **Recognise** default Claro SSIDs and pull the 6-hex device tail — handling
   every field variant: `CLARO_<band><6hex>`, no-band `CLARO_<6hex>`, mesh
   backhaul `…-5G-BH`, `…-IoT`, and the rare full-8-hex SSID. Renamed networks
   (e.g. `CLARO_MOVEL`) are skipped.
3. **Look up the BSSID's OUI** against a table of known Claro vendor blocks
   (informational — labels the maker and flags the split-OUI ARRIS block).
4. **Compute the most-likely key** = `<BSSID octet 3> + <SSID tail>` (tier 1) and
   print it to try directly — no handshake needed on single-OUI gateways.
5. **Verify / fall back with hashcat** `-m 22000 -a 3`: try the 1-guess likely key
   first; if it misses (split-OUI), brute the leading byte with `?H?H<tail>`
   (256). Reports which path cracked it (single- vs split-OUI).

The reduced-charset mask (tier 3) is in
[`utils/charset_mask.py`](utils/charset_mask.py); tiers 1–2 are the deductive
shortcuts described in §5–§6, now built into the main tool.

---

## 8. Worked example (fabricated, illustrative)

- **SSID:** `CLARO_2G3A9C2D`  (hex `434c41524f5f3247334139433244`)
- **BSSID (Wi-Fi radio, in the beacon):** `A0:B1:C2:0C:E4:59` → OUI `A0:B1:C2`, octet 3 `C2`
- **Device MAC (keys the password):** `A0:B1:C2:3A:9C:2D` (same OUI as the radio)
  → password = last 8 hex = `C23A9C2D`; SSID tail = last 6 hex = `3A9C2D`
- **Known from public radio data:** tail `3A9C2D` (SSID) + leading `C2` (BSSID octet 3)
  = **`C23A9C2D`** — the whole key, no handshake needed.
- **Fallback (if octet 3 can't be read):** `hashcat -m 22000 -a 3 <file> ?H?H3A9C2D` → 256 tries.
- **Derived password: `C23A9C2D`**

The leading byte `C2` **equals** the radio BSSID's octet 3 — because the radio
and the device are on the same vendor OUI, which is exactly why the byte is not
secret.

---

## 9. The weakness, generalised

On affected devices this is a textbook **vendor default-credential** failure —
four compounding design mistakes:

1. **Deterministic derivation from a low-entropy seed.** The key is a pure
   function of the MAC. A MAC is an identifier, not random key material.
2. **The seed is broadcast.** The SSID publishes the MAC's last 3 octets, and
   the BSSID publishes the OUI (octet 3) — together, all 4 password octets.
3. **A tiny alphabet, no stretching.** Uppercase hex only, never expanded by
   hashing or a larger character set. 8 hex = 32 bits at best; after the leaks,
   as little as 0.
4. **Offline-attackable protocol.** WPA2's captured handshake makes even a
   trivial space fully testable with no detection or lockout — and here you
   often don't even need it.

Any one is survivable. Together they reduce a "strong" WPA2 network to a lookup.

### It is a whole family

This pattern is not unique to Claro. The same reverse-engineered-default-key
problem has hit many ISP/vendor lines — Thomson/SpeedTouch, BT Home Hub,
UPC/Ubee, Arcadyan, Sky, and others. Whenever a default key is an algorithm over
a public identifier, that algorithm eventually gets published and the whole
fleet's defaults become recoverable.

---

## 10. Evidence

The findings above are empirical, not theoretical. They were verified against
**10 Claro gateways spanning 7 hardware vendors**, using a mix of live
handshake-and-derivation, factory-label photographs, ANATEL certification
images, and on-label QR/barcode data:

| Group | Count | Vendors | Mfr dates | Password |
|-------|-------|---------|-----------|----------|
| **Affected** (MAC-derived key) | 5 | 5 distinct | 2019–2021 | = last 8 hex of MAC |
| **Not affected** (random key)  | 5 | (2 shared) | 2022+      | full-entropy random |

- On the affected devices, the Wi-Fi password equals the last 8 hex of the
  device MAC — **verified by deriving the key from a live 4-way handshake on 2
  units** (pure-Python PBKDF2/PTK/MIC over only the SSID-derived candidates), and
  by reading the printed MAC + password on the rest.
- On the single-OUI devices, the password's **leading byte = the Wi-Fi BSSID's
  octet 3** — verified against captured BSSIDs on 2 units and the printed MAC
  block on the others. The one **split-OUI** unit (an ARRIS: Wi-Fi `C8:52:61`,
  modem `A8:70:5D`) was confirmed by reading both MACs from its admin page — the
  case the 256-guess fallback handles.
- The SSID = `CLARO_<band><last 6 hex of MAC>` on **all 10** devices, affected
  or not — so the SSID format alone does **not** indicate vulnerability.

### Corroboration at scale (passive survey)

Beyond the 10 hands-on devices, a passive wardriving survey of one metropolitan
area (fresh captures, **1,021 distinct Claro default-SSID gateways** — 1,389 BSSIDs
before folding in each unit's secondary radios — after de-duplication) confirms
the pattern is **pervasive and current**, not anecdotal:

- **1,021 distinct gateways** were still broadcasting a factory `CLARO_<...>` SSID —
  every one leaking the 6-hex tail, across **20+ vendor OUI blocks** (Kaon, Humax,
  Compal, Sagemcom, ZTE, Vantiva/Technicolor, MitraStar, and more).
- Counting a gateway's guest / mesh-backhaul (`-5G-BH`) / IoT radios: those extra
  BSSIDs are the same MAC with the **locally-administered bit flipped** in octet 1
  — which never touches octet 3 — so the leading byte still reads off the beacon
  on them too. They inflate the BSSID count but not the gateway count.
- For every default-SSID gateway in the survey the leading byte = BSSID octet 3
  relationship held: the population is **single-OUI-dominated**, and the derived
  candidate matched wherever we could check it (the two handshake-cracked units and
  the sticker-confirmed ones). Some had the radio MAC within a few of the modem
  MAC (textbook one-block assignment); others larger offsets **within the same
  OUI**, where the byte is still the BSSID's octet 3.
- **On split hardware — read this carefully.** Split-OUI (ARRIS/CommScope) units
  barely appeared *in the default-SSID population*, but that is **not** evidence
  that split hardware is rare, and we do not claim it is. Split cannot be seen from
  a beacon alone, and split units that were **renamed** leave the default-SSID
  population entirely. Scanning the very same captures directly for the ARRIS
  router OUI (`C8:52:61`) found **three distinct ARRIS gateways — every one on a
  renamed SSID** (two neighbours' units, not just the physically-inspected one).
  So the honest reading is: "one guess off the beacon" is the common case **for
  the default-SSID, single-OUI-dominated population** the tool targets — while
  ARRIS/CommScope is a real split class that a passive scan **systematically
  under-counts**, not a rarity.
- Only aggregate counts are reported here; the raw survey (which carries per-AP
  GPS coordinates) is **not** published.

> The full per-device table — real models, MACs, SSIDs, passwords, dates and
> sources — is kept in a local `EVIDENCE.md` that is **git-ignored** and never
> published, because it contains real credential material. This public document
> deliberately carries only aggregate counts and fabricated illustrations.

---

## 11. Scope — which devices are affected

- **The weakness is model/era-specific, not universal, and not vendor-specific.**
  Affected units observed were manufactured **~2021 and earlier**; units from
  **~2022 onward** ship full-entropy random keys and are **not** affected. The
  same vendor can appear on both sides (older model vulnerable, newer model not),
  so neither the vendor OUI nor the `CLARO_` SSID name tells you — **treat any
  `CLARO_<band><hex>` SSID as *worth testing*, never as *guaranteed
  vulnerable*.** The tool simply fails (no candidate matches) on a
  random-key device, which is the correct answer.
- Works **only** while a gateway is on its **factory-default SSID + password**. A
  renamed SSID or a changed password cannot be derived this way — which is
  exactly why changing the default is the fix.
- The transition to random keys was observed between **07/2021** (latest
  affected unit seen) and **07/2022** (earliest random-key unit seen).

---

## 12. Defensive guidance

**For a gateway owner:**

- **Change the Wi-Fi password** to a long, random passphrase (the real fix). A
  20+ char random passphrase defeats offline brute force outright.
- **Change the SSID** so it no longer echoes the MAC. On its own this only hides
  the leaked hex; it does *not* fix a still-default password, so do both.
- Treat any device still on its factory `CLARO_<band><hex>` name as effectively
  open, and check whether yours is one of the affected (pre-2022) models.

**For the vendor/ISP (root cause):**

- Provision **full-entropy, per-device random** Wi-Fi keys, generated and stored,
  not computed from the MAC. *(Claro's 2022+ hardware already does this — the fix
  is proven and shipping; the residual risk is the installed base of older
  units.)*
- **Never derive the SSID and the key from the same secret**, and never embed key
  material in a broadcast field.
- Force a password change on first setup.

---

## 13. Files

| File                     | Role                                                       |
|--------------------------|------------------------------------------------------------|
| `claro_wpa_key.py`          | parses `.hc22000`, builds the mask, drives hashcat         |
| `utils/charset_mask.py`  | reduced-charset mask from the BSSID + SSID hex             |
| `*.hc22000` / `EVIDENCE.md` | captures and the real-evidence file — **not** shipped   |
| `hashcat.exe`            | the cracker (`-m 22000 -a 3`) — installed separately       |

> `*.hc22000` captures, `hashcat.exe`, and `EVIDENCE.md` are **not** in this
> repository. Captures and the evidence file are real credential material and are
> excluded by `.gitignore`; install hashcat separately.

*For authorised auditing / your own or consented equipment only.*
