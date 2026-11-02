# Black Ant: Static Triage & Security Research Framework

**Black Ant** is a Python-based utility designed for educational security research, rapid static triage, and Indicator of Compromise (IoC) extraction. Built to assist in defensive engineering and reverse engineering studies, it helps security students and analysts safely dissect obfuscated files and understand threat mechanics without executing them.

> **Academic Note:** This tool was developed as a Detection Engineering study project. Its primary goal is to automate defensive triage workflows, deepen knowledge in static analysis, and help researchers reduce analysis fatigue when examining complex, packed binaries and suspicious artifacts.

---

## 🛡️ Disclaimer & Acceptable Use
**This framework is strictly for educational purposes, defensive security research, and academic study.** It is designed to safely analyze and generate defensive metrics against security threats. The author does not support, endorse, or host any active malicious payloads. Users must ensure they have explicit permission to analyze any files passed through this tool.

---

## Key Features (v2.0 Architecture)

* **Context-Aware Scoring System:** Replaces blind scoring with evidence-based intelligence. The engine justifies its alerts logically (e.g., flagging suspicious configuration patterns, identifying abused public infrastructure, or detecting persistence mechanisms).
* **Automated Defensive Signatures:** Integrates YARA engines to scan raw binaries. Automatically compiles extracted network and host IoCs to generate defensive **YARA rules** and **Suricata/Snort network signatures** on the fly.
* **AppSec & API Hardening:** The REST API is secured against standard web vulnerabilities. Includes native Path Traversal (CWE-22) prevention, payload auto-wiping post-analysis to prevent disk contamination, strict upload limits, and local network binding by default.
* **False-Positive Mitigation:** The auto-generator includes a dynamic whitelist that strips out abused public services (e.g., standard GitHub pages, Telegram APIs) before compiling signatures, ensuring generated rules don't alert on legitimate software.
* **Smart Deobfuscation & Config Extraction:** Features recursive unpacking (Base64 -> Gzip -> XOR), native script deobfuscation, cryptographic constant detection, and static configuration extraction for various commodity remote access tools.
* **Advanced IoC Validation:** Utilizes native **Base58Check cryptographic validation** for cryptocurrency wallets to reduce False Positives. Extracts hidden network addresses, IPv6 infrastructure, and tracks abused cloud services.
* **Advanced PE & Container Analysis:** Deep inspection of Executables (TLSH/ssdeep clustering, Authenticode validation, contextual entropy), suspicious PDF structures, macro analysis, and MotW bypass detections.
* **SIEM-Ready Architecture:** Results are structured in JSON format conforming to modern CTI/SIEM standards. Telemetry is indexed in an SQLite database. Features a hardened Flask REST API for local SOC integrations.
* **Plugin Architecture:** Completely decoupled design. Drop any custom Python parser into the `plugins/` directory, and the framework dynamically hooks it into the analysis pipeline.

*(Capabilities include: Java decompilation workflows, V8 Bytenode extraction, and nested archive unrolling).*

---

## Detection Capabilities & CTI

Black Ant comes with a suite of custom YARA rules and heuristic engines developed through defensive research. Current capabilities include:

* **Data-Stealing Heuristics:** Signatures targeting modern credential stealers, detecting backend infrastructure, global configuration variables, and exfiltration endpoints.
* **Evasion Detection:** Detection of anti-VM techniques, anti-debugging mechanisms, hardware enumeration, sandbox blacklisting, and suspicious payload overlays.
* **API Abuse & Injection:** Identifies attempts to hijack core system modules, impersonate tokens, extract secure storage seeds, and access backup codes.

> **OpSec Notice:** For Operational Security and compliance reasons, all Command and Control (C2) domains, IP addresses, and specific threat actor tags in this repository have been fully redacted or neutralized.

---

## Sanitization & Safety Recommendations

Handling suspicious files involves inherent risks. Please follow these safety guidelines before running or testing this tool:

1. **Isolated Environment (VM):** Always run this tool inside an isolated Virtual Machine (VM) or sandbox (e.g., VirtualBox, VMware). **Never** execute untrusted binaries on your main host machine.
2. **Network Isolation:** Ensure your analysis VM is set to "Host-Only" or routed through a safe proxy to prevent accidental communication or data leakage.
3. **Safe Handling:** Treat every sample passed to this script with caution. Use proper sanitization methods when transferring files.

---

## Prerequisites

To ensure the framework utilizes 100% of its extraction and analysis capabilities, make sure you have the following binaries added to your operating system's `PATH`:

* [7-Zip](https://www.7-zip.org/)
* [JADX](https://github.com/skylot/jadx)
* [Mandiant CAPA](https://github.com/mandiant/capa)

**Python Dependencies:**

```bash
# Install core requirements
pip install -r requirements.txt
```

---

## Quick Start

### 1. Interactive Single-File Triage
Run deep static dissection and triage against a single suspicious file:
```bash
python main.py path/to/suspicious_file.bin
```

### 2. REST API Mode (Local SOC Integration)
Deploy the local microservice to receive files over the local network:
```bash
python api.py
# Example usage: POST /analyze with form-data 'file'
```

---
*Developed for the Detection Engineering & DFIR community.*