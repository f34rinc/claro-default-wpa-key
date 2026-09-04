# Contributing

Thanks for helping sharpen this research. The most useful contributions are new
**device / OUI / SSID-variant** data points and corrections — they widen the
evidence base and keep the tool current across Claro's changing hardware.

Because this is a security-research project, the contribution flow is designed to
collect only **non-sensitive, aggregatable** signal. Please read the two lists
below before opening anything.

## ✅ Helpful to contribute

- **New vendor OUI blocks** that carry `CLARO_` SSIDs, and attributions for
  unmapped ones — the OUI (first 3 octets) is public IEEE registry data.
- **New split-OUI examples** — a gateway (ideally a model name) whose Wi-Fi radio
  OUI is a *different* block than the cable-modem OUI, ARRIS-style.
- **New default-SSID naming variants** (e.g. `-5G-BH`, `-IoT`, no-band forms) so
  the parser keeps recognising them.
- **Scope data points** — vendor / model / approximate manufacture year, and
  whether it used a **MAC-derived** key or a **random** key. This sharpens the
  ~2021↔2022 transition line.
- **Corrections** to the OUI→vendor table or the docs.

## ⛔ Never submit

Do **not** put any of the following in an issue, a PR, or the data file — they
are real credential material or personally-identifying:

- Wi-Fi **passwords** / recovered keys (including `claro_cracked.txt` rows).
- Packet **captures** — `.hc22000`, `.pcap`, `.pcapng`, `.cap`, handshakes.
- The **full BSSID *and* SSID of a specific home network** together (that pair
  identifies someone's network). An OUI prefix alone is fine; a full address
  tied to a real network is not.
- **GPS coordinates** or wardriving logs.

Contributions that include any of the above will be closed without merging.

## How to contribute

### 1. A quick data point → open an issue

Use the **"New OUI / device / SSID variant"** issue form. It asks only for the
safe fields above and has the never-submit reminder built in.

### 2. Add to the OUI table → open a pull request

The vendor-OUI table lives in [`data/claro_ouis.csv`](data/claro_ouis.csv) — the
tool loads it at runtime, so a contribution is usually a **one-line PR**:

```csv
oui,vendor,split
58:2F:F7,Askey,
```

- `oui` — first 3 octets, uppercase, colon-separated (e.g. `58:2F:F7`).
- `vendor` — maker name; a best-effort guess is fine.
- `split` — `yes` **only** for the router-side OUI of a split-OUI gateway (radio
  block ≠ modem block); leave blank otherwise.

Keep rows one-per-line and alphabetise loosely by vendor if you can. That's it —
no code changes needed for a new OUI.

**Have your own WiGLE data?** `tools/analyze_wigle.py` reads a WiGLE `.kml` or
`.csv` export and prints exactly the rows above for any OUI block it finds that
isn't in the table yet:

```bash
python tools/analyze_wigle.py your_export.kml --rows
```

It never reads or emits GPS, and only the OUI prefixes it prints are meant to
leave your machine — the raw export and the tool's full report stay local
(they're git-ignored). Copy the `--rows` output straight into your PR.

## Running the tests

If your PR touches code, please run the test suite first (stdlib only — no
`pip install`):

```bash
python -m unittest discover -s tests -v
```

All 13 should pass. New behaviour is welcome to come with a test. The same
suite runs automatically on every pull request via CI.

## Scope reminder

Everything here is for **authorised auditing of your own or consented
equipment**, and for defensive/educational research. Please keep contributions in
that spirit.
