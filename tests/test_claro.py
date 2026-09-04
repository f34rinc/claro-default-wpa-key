#!/usr/bin/env python3
"""Unit tests for the Claro default-key logic. Stdlib only:

    python -m unittest discover -s tests -v      # or:  python tests/test_claro.py

Covers SSID parsing (every field variant), OUI extraction, the beacon-derivation
(BSSID octet 3 + SSID tail), the .hc22000 parser, and the WiGLE analyzer's
single-vs-split classification and locally-administered-BSSID handling. All data
here is fabricated.
"""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import claro_wpa_key as k          # noqa: E402
import analyze_wigle as w          # noqa: E402


class TestSsidParsing(unittest.TestCase):
    def test_variants(self):
        cases = {
            "CLARO_2G3A9C2D":       ("3a9c2d", None),   # banded 2.4G
            "CLARO_5G3A9C2D":       ("3a9c2d", None),   # banded 5G
            "CLARO_2.4G3A9C2D":     ("3a9c2d", None),   # explicit 2.4G token
            "CLARO_3A9C2D":         ("3a9c2d", None),   # no band
            "CLARO_3A9C2D-5G-BH":   ("3a9c2d", None),   # mesh backhaul suffix
            "CLARO_112233-IoT":     ("112233", None),   # IoT suffix
            "CLARO_2G12345678":     ("345678", "12345678"),  # embedded full-8
        }
        for essid, expected in cases.items():
            self.assertEqual(k.parse_claro_ssid(essid), expected, essid)

    def test_case_insensitive(self):
        self.assertEqual(k.parse_claro_ssid("claro_2g3a9c2d"), ("3a9c2d", None))

    def test_non_default_rejected(self):
        for essid in ("CLARO_MOVEL", "CLARO_Mesh", "NET_VIRTUA_9988",
                      "MyHomeWiFi", "", "CLARO_"):
            self.assertEqual(k.parse_claro_ssid(essid), (None, None), essid)


class TestOuiAndDerivation(unittest.TestCase):
    def test_oui_of(self):
        self.assertEqual(k.oui_of("aabb12ddee00"), "AA:BB:12")
        self.assertEqual(k.oui_of("743AEF3A9C2D"), "74:3A:EF")

    def test_derived_key(self):
        # The single-OUI derivation used in handle_net: BSSID octet 3 + SSID tail.
        bssid, essid = "aabb12ddee00", "CLARO_5G345678"
        tail6, _ = k.parse_claro_ssid(essid)
        key = bssid[4:6].upper() + tail6.upper()
        self.assertEqual(key, "12345678")

    def test_full8_is_determined(self):
        tail6, full8 = k.parse_claro_ssid("CLARO_2G12345678")
        self.assertEqual(full8.upper(), "12345678")


class TestCaptureParser(unittest.TestCase):
    LINE = ("WPA*02*68330658ae024a468fba3ba845aaaad2*AABB12DDEE00*ca45f2ff68f2*"
            "434c41524f5f3547333435363738*"
            "561815e0306c26c6460ab0e2d45b4d64bfbaeedadf3bf0a3998c34d3e7399eeb*"
            "0103005f02010a00000000000000000001*02\n")

    def test_parse_22000(self):
        with tempfile.NamedTemporaryFile("w", suffix=".hc22000",
                                         delete=False, encoding="utf-8") as fh:
            fh.write(self.LINE)
            path = fh.name
        try:
            nets = k.parse_22000(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(nets), 1)
        self.assertEqual(nets[0]["essid"], "CLARO_5G345678")
        self.assertEqual(nets[0]["bssid"], "aabb12ddee00")


class TestAnalyzerLocalAdmin(unittest.TestCase):
    def test_is_local_admin(self):
        self.assertTrue(w.is_local_admin("aabb12ddee00"))    # 0xAA U/L bit set
        self.assertTrue(w.is_local_admin("223543f00000"))    # 0x22 U/L bit set
        self.assertFalse(w.is_local_admin("743aef3a9c2d"))   # 0x74 universal
        self.assertFalse(w.is_local_admin("203543f00000"))   # 0x20 universal

    def test_base_oui_clears_ul_bit(self):
        # U/L bit lives in octet 1 only; octet 3 (the key byte) is never touched.
        self.assertEqual(w.base_oui_of("223543f00000"), "20:35:43")
        self.assertEqual(w.base_oui_of("22:35:43"), "20:35:43")
        self.assertEqual(w.base_oui_of("aabb12ddee00"), "A8:BB:12")

    def test_ssid_variant_labels(self):
        self.assertEqual(w.ssid_variant("CLARO_2G3A9C2D"), "banded 2.4GHz")
        self.assertEqual(w.ssid_variant("CLARO_5G3A9C2D"), "banded 5GHz")
        self.assertEqual(w.ssid_variant("CLARO_3A9C2D"), "no-band")
        self.assertEqual(w.ssid_variant("CLARO_ABCDEF-5G-BH"), "mesh backhaul (-5G-BH)")
        self.assertEqual(w.ssid_variant("CLARO_112233-IoT"), "IoT (-IoT)")


class TestAnalyzerClassify(unittest.TestCase):
    def test_single_oui(self):
        c = w.classify({"essid": "CLARO_2G3A9C2D", "bssid": "743aef3a9c2d"})
        self.assertTrue(c["kind"].startswith("single-OUI"))
        self.assertFalse(c["local"])

    def test_split_oui_arris(self):
        # C8:52:61 is the confirmed ARRIS/CommScope split-OUI router block.
        c = w.classify({"essid": "CLARO_ABCDEF", "bssid": "c85261abcdef"})
        self.assertTrue(c["kind"].startswith("split-OUI"))

    def test_renamed_is_not_a_gateway(self):
        self.assertIsNone(w.classify({"essid": "MyHomeWiFi", "bssid": "743aef3a9c2d"}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
