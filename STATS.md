# Claro gateway prevalence — WiGLE survey stats

Aggregate statistics from a metropolitan WiGLE survey, showing how common
factory-default (and therefore derivable-key) Claro cable/fibre gateways are in
the field. **Counts only** — this file contains no passwords, no BSSIDs, and no
GPS coordinates. Generated with [`tools/analyze_wigle.py`](tools/analyze_wigle.py)
from a local WiGLE database export.

_Snapshot: 2026-09-07._

## Dataset

| Metric | Value |
|---|--:|
| Unique APs surveyed | 56,562 |
| OUI vendor blocks catalogued | 160 |
| Distinct hardware vendors | 15 |

## Claro gateway population

| Metric | Count |
|---|--:|
| Default `CLARO_` BSSIDs | 2,214 |
| &nbsp;&nbsp;— primary (physical gateways) | 1,637 |
| &nbsp;&nbsp;— secondary / virtual (locally-administered) | 577 |
| Renamed `CLARO_` (non-default SSID) | 187 |

## Derivability — the core finding

Every default-SSID gateway observed is recoverable straight from the broadcast
beacon, with no handshake required.

| Class | Count | Share |
|---|--:|--:|
| single-OUI — 1 guess off the beacon | 2,211 | 99.9% |
| full-8 in SSID — key fully determined | 3 | 0.1% |
| split-OUI — 256-guess vs a handshake | 0 | 0.0% |
| **Derivable off the beacon** | **2,214** | **100%** |

2,125 of the single-OUI gateways had a BSSID tail that differs from the SSID tail
(the benign same-OUI "Compal case") — still a single guess, because the leading
byte is BSSID octet 3. 577 were secondary/virtual radios: the locally-administered
bit flips octet 1, never octet 3, so the leading byte still reads off the beacon.

> **Note on split-OUI.** This population counts default-SSID gateways only. An
> ARRIS/CommScope split unit that has been renamed drops out of the count entirely,
> and split cannot be detected from a beacon alone — it needs a sticker MAC or a
> handshake. A low split percentage here is *not* evidence that split hardware is
> rare; it is under-counted by passive scans.

## Default-SSID variants

| Variant | Count |
|---|--:|
| no-band | 681 |
| banded 5 GHz | 598 |
| banded 2.4 GHz | 471 |
| mesh backhaul (`-5G-BH`) | 407 |
| IoT (`-IoT`) | 57 |

## Split-OUI hardware (ARRIS/CommScope)

4 BSSIDs were seen on the catalogued `C8:52:61` router block — all of them renamed,
and none on a default `CLARO_` SSID. Because only that one block is catalogued as
split, and split cannot be seen from a beacon, this is a floor, not a full count.

## OUI vendor table (160 blocks)

One vendor holds many OUI blocks: each block covers ~16.7M addresses, so
high-volume makers exhaust blocks and register more, and acquisitions carry legacy
blocks (Vantiva is the renamed Technicolor; CommScope acquired ARRIS). So 160
blocks map to only 15 actual companies.

| Vendor | Blocks |
|---|--:|
| Sagemcom | 53 |
| ZTE | 35 |
| Vantiva/Technicolor | 27 |
| Huawei | 16 |
| Kaon | 7 |
| Arris/CommScope | 6 |
| TP-Link | 4 |
| Humax | 3 |
| Intelbras | 2 |
| Compal | 2 |
| D-Link | 1 |
| Hitron | 1 |
| MitraStar | 1 |
| SEI Robotics | 1 |
| Tellescom | 1 |

---

_Figures are a point-in-time snapshot from one metro survey and will drift as
coverage grows. Regenerate with `python tools/analyze_wigle.py <export>.kml`._
