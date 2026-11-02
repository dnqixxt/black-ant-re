from core.plugin_manager import PluginManager
from modules.safe_downloader import safe_download_c2
from modules.database import FormigaDB
from modules.exporter import generate_snort_rules, generate_yara_rule, generate_attack_navigator
from modules.ioc_extractor import extract_advanced_iocs
from modules.reputation import check_malwarebazaar, check_urlhaus, run_clamav
from modules.emulation import run_speakeasy, submit_triage
from modules.family_extractor import attribute_malware_family
from config.settings import *
from core.yara_scanner import PurePythonYaraEngine
from modules.pdf_analyzer import analyze_pdf_content
from modules.lnk_analyzer import analyze_lnk_content
from modules.office_analyzer import analyze_office_content
from modules.script_analyzer import analyze_script_content
from modules.advanced_binaries_analyzer import analyze_advanced_binary
from modules.deobfuscator import (
    recursive_decode_base64,
    deobfuscate_powershell,
    find_crypto_constants,
    run_floss,
    extract_apk_byte_array_xor_strings,
    patch_apk_byte_array_xor_code,
)
from modules.pe_advanced import calculate_advanced_hashes, analyze_pe_deep


"""
Safe Vector Analyzer Framework
Automated static triage, IoC extraction, and capability analysis (MITRE ATT&CK)
for suspicious artifacts and malicious installers.
"""

import os
import re
import json
import stat
import socket
import string
import ipaddress
import hashlib
import zipfile
import subprocess
import shutil
import math
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import requests

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt
    from rich import print as rprint
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    class DummyConsole:
        def print(self, *args, **kwargs): print(*args)
        def input(self, *args, **kwargs): return input(args[0] if args else "")
    class DummyPrompt:
        @staticmethod
        def ask(*args, **kwargs): return input(args[0] + ": ")
    console = DummyConsole()
    Prompt = DummyPrompt()



class SSRFBlockedError(Exception):
    pass



class SafeVectorAnalyzer:
    def __init__(self, file_path, interactive=True):
        self.file_path = Path(file_path)
        self.interactive = interactive
        self.report_path = self.file_path.parent / f"{self.file_path.stem}_vector_report.json"
        self.plugin_manager = PluginManager()
        self.safe_download_dir = self.file_path.parent / "quarantine"
        self.jadx_output_dir = self.file_path.parent / f"{self.file_path.stem}_jadx_decompiled"
        self.deobfuscated_sources_dir = self.file_path.parent / f"{self.file_path.stem}_deobfuscated_sources"

        self.url_pattern = re.compile(rb'https?://[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s"\'\`<>\x00]*)?')
        self.ip_pattern = re.compile(rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d+)?\b')
        self.telegram_token_pattern = re.compile(rb'\b\d{8,10}:[A-Za-z0-9_-]{35}\b')
        self.discord_webhook_pattern = re.compile(rb'https?://(?:discord(?:app)?\.com|canary\.discord\.com)/api/webhooks/\d+/[\w-]+')
        self.email_pattern = re.compile(rb'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
        self.crypto_wallet_patterns = [
            re.compile(rb'\b(?:bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,39}\b'),
            re.compile(rb'\b0x[a-fA-F0-9]{40}\b'),
        ]

        if self.report_path.exists():
            try:
                with open(self.report_path, 'r', encoding='utf-8') as f:
                    self.results = json.load(f)
            except Exception:
                self._initialize_default_results()
        else:
            self._initialize_default_results()

        self._suspicious_api_seen = set()
        self._raw_data_cache = None
        self._cumulative_extracted_bytes = 0
        self._archives_extracted_count = 0

    def _initialize_default_results(self):
        """Hierarchical telemetry structure based on CTI/SIEM standards"""
        self.results = {
            "metadata": {
                "target_file": self.file_path.name,
                "analysis_date": datetime.now(timezone.utc).isoformat()
            },
            "file_info": {
                "file_type": "Unknown",
                "hashes": {"md5": "", "sha1": "", "sha256": "", "imphash": None},
                "is_packed": False,
                "payload_location": "None"
            },
            "threat_intel": {
                "is_suspected_vector": False,
                "suspicion_score": 0,
                "suspicion_level": "Clean",
                "scoring_breakdown": [],
                "virustotal_report": None,
                "yara_matches": [],
                "warnings": [],
                "family_attribution": {
                    "family": "Unknown",
                    "confidence": "N/A",
                    "extracted_config": {}
                }
            },
            "capabilities": {
                "downloader_dropper": False,
                "evasion_techniques": {
                    "timestomping_detected": False,
                    "silent_exception_swallowing_count": 0,
                    "process_output_suppressed": False,
                    "obfuscation_functions_detected": 0,
                    "suspicious_entrypoint_naming": None
                },
                "mitre_attack_tactics": []
            },
            "iocs": {
                "network": {
                    "urls_externas": [], "ips": [], "discord_webhooks": [], "telegram_bot_tokens": [],
                    "ip_ports": [], "ipv6": [], "onions": [], "abused_services": [], "user_agents": []
                },
                "host": {
                    "emails": [], "crypto_wallets": [], "suspicious_api_calls": [], "apis_de_rede_pe": [],
                    "persistence_artifacts": [], "dangerous_paths": [], "validated_wallets": {}
                }
            },
            "deep_analysis": {
                "pe_analysis": {"sections": []},
                "installer_analysis": {
                    "installer_type": None, "embedded_archives": [], "extraction_dir": None,
                    "nested_extractions": [], "converted_modules": []
                },
                "embedded_files": [],
                "manifest": {"main_class": None, "raw_snippet": None},
                "android_manifest": None,
                "mod_metadata": {"mod_loader": None, "mod_id": None, "entrypoints": {}},
                "jar_classes": [],
                "possible_base64_blobs": {"count": 0, "samples": []},
                "recovered_obfuscated_strings": [],
                "pdf_analysis": [],
                "lnk_analysis": [],
                "office_analysis": [],
                "script_analysis": [],
                "advanced_bin_analysis": []
            }
        }

    def get_file_hashes(self, data):
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "imphash": None 
        }

    def defang_indicator(self, indicator):
        return indicator.replace(".", "[.]").replace("http", "hxxp")

    def detect_file_type(self, data):
        if data.startswith(b'MZ'): return "PE Executable (.exe/.dll)"
        elif self.file_path.suffix.lower() == '.apk' or (data.startswith(b'PK\x03\x04') and b'AndroidManifest.xml' in data[:8192]):
            return "Android Package (.apk)"
        elif data.startswith(b'PK\x03\x04'): return "Compressed Archive (ZIP/Office/JAR)"
        elif data.startswith(b'\xD0\xCF\x11\xE0'): return "OLE Document (Office/MSI)"
        elif data.startswith(b'%PDF'): return "PDF Document"
        elif data.startswith(b'\x4C\x00\x00\x00\x01\x14\x02\x00'): return "Windows Shortcut (.lnk)"
        return "Unknown / Raw Data"

    def _calculate_entropy(self, data):
        if not data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0: entropy += - p_x * math.log(p_x, 2)
        return entropy

    def run_yara_scan(self, raw_data):
        if YARA_AVAILABLE:
            rules_dir = Path(YARA_RULES_DIR)
            if rules_dir.exists():
                filepaths = {rule_file.stem: str(rule_file) for rule_file in rules_dir.glob("*.yar*")}
                if filepaths:
                    try:
                        compiled_rules = yara.compile(filepaths=filepaths)
                        matches = compiled_rules.match(data=raw_data)
                        if matches:
                            self.results["threat_intel"]["is_suspected_vector"] = True
                            for m in matches:
                                if not any(y["rule_name"] == m.rule for y in self.results["threat_intel"]["yara_matches"]):
                                    self.results["threat_intel"]["yara_matches"].append({"rule_name": m.rule, "description": "Matched via yara-python"})
                    except Exception as e:
                        self.results["threat_intel"]["warnings"].append(f"yara-python error: {e}")
        else:
            yara_engine = PurePythonYaraEngine(YARA_RULES_DIR)
            if yara_engine.rules:
                matches = yara_engine.match(raw_data)
                if matches:
                    self.results["threat_intel"]["is_suspected_vector"] = True
                    for m in matches:
                        if m not in self.results["threat_intel"]["yara_matches"]:
                            self.results["threat_intel"]["yara_matches"].append(m)

    def _is_ip_blocked(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return True
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified

    def _validate_url_for_ssrf(self, url):
        parsed = urlparse(url)
        if parsed.scheme not in ALLOWED_SCHEMES: raise SSRFBlockedError(f"Disallowed HTTP(S) scheme: {parsed.scheme}")
        if not parsed.hostname: raise SSRFBlockedError("URL missing valid hostname")
        addrinfos = socket.getaddrinfo(parsed.hostname, None)
        resolved_ips = {info[4][0] for info in addrinfos}
        for ip_str in resolved_ips:
            if self._is_ip_blocked(ip_str): raise SSRFBlockedError(f"Restricted destination address detected (internal IP): {ip_str}")
        return True

    def analyze_pe(self):
        if not PEFILE_AVAILABLE: return
        
        # TLSH and SSDEEP hashes
        adv_hashes = calculate_advanced_hashes(self._raw_data_cache)
        if adv_hashes:
            self.results["file_info"]["hashes"].update(adv_hashes)
            
        try:
            # We must load full directories to get TLS, SECURITY, DEBUG
            pe = pefile.PE(data=self._raw_data_cache, fast_load=False)
            
            try:
                self.results["file_info"]["hashes"]["imphash"] = pe.get_imphash()
            except Exception: pass
            
            is_packed_heuristic = False
            
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                section_data = section.get_data()
                ent = self._calculate_entropy(section_data)
                self.results["deep_analysis"]["pe_analysis"]["sections"].append({"name": section_name, "entropy": round(ent, 2)})
                
                # Contextual Entropy: Only flag > 7.2 if it's an executable section or completely anomalous (not a resource block like .rsrc usually)
                is_executable = section.Characteristics & 0x20000000
                is_resource = b".rsrc" in section.Name
                
                if ent > 7.4 and not is_resource:
                    is_packed_heuristic = True
                elif ent > 7.2 and is_executable:
                    is_packed_heuristic = True
                    
            if is_packed_heuristic:
                self.results["file_info"]["is_packed"] = True
                self.results["threat_intel"]["is_suspected_vector"] = True
            
            # Extract basic network APIs
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('utf-8', 'ignore').lower()
                    if dll in ['wininet.dll', 'urlmon.dll', 'ws2_32.dll', 'winhttp.dll']:
                        self.results["threat_intel"]["is_suspected_vector"] = True
                        if hasattr(entry, 'imports'):
                            for imp in entry.imports:
                                if imp.name:
                                    api_str = f"{dll} -> {imp.name.decode('utf-8')}"
                                    if api_str not in self.results["iocs"]["host"]["apis_de_rede_pe"]:
                                        self.results["iocs"]["host"]["apis_de_rede_pe"].append(api_str)
                                        
            # Deep PE Analysis
            deep_findings = analyze_pe_deep(pe, self._raw_data_cache, self.file_path)
            
            # Merge findings
            self.results["deep_analysis"]["pe_analysis"]["metadata"] = deep_findings["metadata"]
            if deep_findings["warnings"]:
                self.results["threat_intel"]["is_suspected_vector"] = True
                self.results["threat_intel"]["warnings"].extend(deep_findings["warnings"])
            if deep_findings["api_combinations"]:
                self.results["threat_intel"]["is_suspected_vector"] = True
                self.results["iocs"]["host"]["suspicious_api_calls"].extend(deep_findings["api_combinations"])
                
        except Exception as e:
            self.results["threat_intel"]["warnings"].append(f"Failed to parse PE header: {e}")

    def check_virustotal(self):
        # 1. ClamAV Local
        clamav_res = run_clamav(self.file_path)
        if clamav_res:
            self.results["threat_intel"]["is_suspected_vector"] = True
            self.results["threat_intel"]["warnings"].append(f"ClamAV match: {clamav_res}")
            
        # 2. MalwareBazaar (Abuse.ch) - Keyless lookup
        mb_res = check_malwarebazaar(self.results['file_info']['hashes']['sha256'])
        if mb_res:
            self.results["threat_intel"]["is_suspected_vector"] = True
            self.results["threat_intel"]["warnings"].append(mb_res)
            
        # 3. URLhaus (Check Network IoCs)
        for url in self.results["iocs"]["network"]["urls_externas"]:
            uh_res = check_urlhaus(url)
            if uh_res and uh_res not in self.results["threat_intel"]["warnings"]:
                self.results["threat_intel"]["warnings"].append(f"{url} -> {uh_res}")

        if not VT_API_KEY:
            self.results["threat_intel"]["virustotal_report"] = "API Key not configured in environment."
            return
        url = f"https://www.virustotal.com/api/v3/files/{self.results['file_info']['hashes']['sha256']}"
        headers = {"x-apikey": VT_API_KEY}
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                total = malicious + stats.get('undetected', 0) + stats.get('harmless', 0)
                self.results["threat_intel"]["virustotal_report"] = f"{malicious} / {total} security vendors flagged as malicious"
                if malicious > 0: self.results["threat_intel"]["is_suspected_vector"] = True
            elif response.status_code == 404:
                self.results["threat_intel"]["virustotal_report"] = "Not found (Possible unknown sample / 0-day)"
            else:
                self.results["threat_intel"]["virustotal_report"] = f"API communication error: HTTP {response.status_code}"
        except Exception as e:
            self.results["threat_intel"]["virustotal_report"] = f"VirusTotal connection error: {e}"

    def run_capa(self):
        capa_path = shutil.which("capa")
        if not capa_path:
            console.print("[red][-] CAPA executable not found in system PATH. Install via Mandiant CAPA.[/red]")
            return
        
        console.print("[cyan][*] Initializing Mandiant CAPA engine (TTP extraction)...[/cyan]")
        capa_json_out = self.file_path.parent / f"{self.file_path.stem}_capa_temp.json"
        
        try:
            subprocess.run([capa_path, "-j", str(self.file_path)], stdout=open(capa_json_out, 'w'), stderr=subprocess.DEVNULL, timeout=CAPA_TIMEOUT)
            
            if capa_json_out.exists():
                with open(capa_json_out, 'r') as f:
                    capa_data = json.load(f)
                
                tactics = set(self.results["capabilities"].get("mitre_attack_tactics", []))
                
                for rule_name, rule_data in capa_data.get("rules", {}).items():
                    if "meta" in rule_data and "att&ck" in rule_data["meta"]:
                        for attack in rule_data["meta"]["att&ck"]:
                            tactic_str = attack.get("tactic", "Unknown") + " [" + attack.get("id", "") + "]"
                            tactics.add(tactic_str)
                
                self.results["capabilities"]["mitre_attack_tactics"] = list(tactics)
                if tactics:
                    self.results["threat_intel"]["is_suspected_vector"] = True
                
                console.print(f"[green][+] Analysis complete: {len(tactics)} TTPs injected into main report.[/green]")
                self.save_report()
                capa_json_out.unlink()
                
        except subprocess.TimeoutExpired:
            console.print("[red][-] CAPA analysis aborted due to execution timeout.[/red]")
        except Exception as e:
            console.print(f"[red][-] CAPA execution error: {e}[/red]")

    def scan_suspicious_content(self, data, filename=""):
        for pattern, description in SUSPICIOUS_CLASS_PATTERNS:
            if re.search(pattern, data, re.IGNORECASE):
                if description not in self._suspicious_api_seen:
                    self._suspicious_api_seen.add(description)
                    self.results["iocs"]["host"]["suspicious_api_calls"].append(description)
                self.results["threat_intel"]["is_suspected_vector"] = True
                
        crypto_consts = find_crypto_constants(data)
        if crypto_consts:
            self.results["threat_intel"]["is_suspected_vector"] = True
            for c in crypto_consts:
                if c not in self.results["threat_intel"]["warnings"]:
                    self.results["threat_intel"]["warnings"].append(f"Cryptographic constant detected: {c}")
        
        blobs = BASE64_BLOB_PATTERN.findall(data)
        if blobs:
            self.results["deep_analysis"]["possible_base64_blobs"]["count"] += len(blobs)
            for b in blobs:
                # Recursive decoding and IoC extraction from embedded payload
                decoded_layers = recursive_decode_base64(b)
                for layer in decoded_layers:
                    self.extract_network_iocs(layer)
                    
                if len(self.results["deep_analysis"]["possible_base64_blobs"]["samples"]) >= MAX_BASE64_SAMPLES: continue
                sample = b.decode('ascii', 'ignore')
                truncated = sample[:60] + ("..." if len(sample) > 60 else "")
                if truncated not in self.results["deep_analysis"]["possible_base64_blobs"]["samples"]:
                    self.results["deep_analysis"]["possible_base64_blobs"]["samples"].append(truncated)

    def extract_network_iocs(self, data):
        # Whitelist
        whitelist_urls = [b'w3.org', b'schemas.microsoft.com', b'xml.org', b'apache.org']
        whitelist_ips = [b'0.0.0.0', b'1.0.0.0', b'6.0.0.0']

        urls = [u.decode('utf-8', 'ignore') for u in self.url_pattern.findall(data) if not any(w in u.lower() for w in whitelist_urls)]
        ips = [i.decode('utf-8', 'ignore') for i in self.ip_pattern.findall(data) if i not in whitelist_ips]
        t_tokens = [t.decode('utf-8', 'ignore') for t in self.telegram_token_pattern.findall(data)]
        d_webhooks = [w.decode('utf-8', 'ignore') for w in self.discord_webhook_pattern.findall(data)]
        emails = [e.decode('utf-8', 'ignore') for e in self.email_pattern.findall(data)]

        net = self.results["iocs"]["network"]
        host = self.results["iocs"]["host"]

        net["urls_externas"] = list(set(net["urls_externas"] + urls))
        net["ips"] = list(set(net["ips"] + ips))
        net["telegram_bot_tokens"] = list(set(net["telegram_bot_tokens"] + t_tokens))
        net["discord_webhooks"] = list(set(net["discord_webhooks"] + d_webhooks))
        host["emails"] = list(set(host["emails"] + emails))
        
        # Deep IoC extraction
        adv_iocs = extract_advanced_iocs(data)
        
        # Merge advanced Network IoCs
        for k in ["ip_ports", "ipv6", "onions", "abused_services", "user_agents"]:
            net[k] = list(set(net.get(k, []) + adv_iocs["network"].get(k, [])))
            
        # Merge advanced Host IoCs
        host["persistence_artifacts"] = list(set(host.get("persistence_artifacts", []) + adv_iocs["host"].get("persistence", [])))
        host["dangerous_paths"] = list(set(host.get("dangerous_paths", []) + adv_iocs["host"].get("dangerous_paths", [])))
        
        # Merge and Validate Wallets
        for w_type, w_list in adv_iocs["wallets"].items():
            if w_type not in host.get("validated_wallets", {}): host.setdefault("validated_wallets", {})[w_type] = []
            host["validated_wallets"][w_type] = list(set(host["validated_wallets"][w_type] + w_list))

        if any([urls, ips, t_tokens, d_webhooks, adv_iocs["wallets"], adv_iocs["network"]["abused_services"], adv_iocs["network"]["onions"]]):
            self.results["threat_intel"]["is_suspected_vector"] = True
            if "Externo" not in self.results["file_info"]["payload_location"]:
                self.results["file_info"]["payload_location"] = "External Access (URL/IP/C2 detected)"

    def detect_embedded_payloads(self, data):
        mz_index = data.find(b'MZ', 2 if data.startswith(b'MZ') else 0)
        if mz_index != -1:
            self.results["threat_intel"]["is_suspected_vector"] = True
            self.results["capabilities"]["downloader_dropper"] = True
            self.results["file_info"]["payload_location"] = f"Internal (Embedded PE binary at offset {mz_index})"
            item = {"type": "PE File", "offset": mz_index}
            if not any(e["offset"] == mz_index for e in self.results["deep_analysis"]["embedded_files"]):
                self.results["deep_analysis"]["embedded_files"].append(item)
            warning = f"Dropper capability: Embedded PE binary found at offset {mz_index}"
            if warning not in self.results["threat_intel"]["warnings"]:
                self.results["threat_intel"]["warnings"].append(warning)

    def detect_downloader_dropper_capabilities(self, data):
        downloader_patterns = [
            (rb'(?i)(?:DownloadFile|DownloadString|DownloadData)', "PowerShell/.NET WebClient Remote Download"),
            (rb'(?i)(?:Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b)', "PowerShell Web Request Transfer"),
            (rb'(?i)Start-BitsTransfer', "BITS Background Transfer Job"),
            (rb'(?i)certutil(?:\.exe)?\s+-[a-zA-Z0-9]*urlcache', "Certutil Remote Staging (Living-off-the-Land)"),
            (rb'(?i)bitsadmin(?:\.exe)?\s+/transfer', "Bitsadmin Command Line Transfer"),
            (rb'(?i)curl(?:\.exe)?\s+-[a-zA-Z0-9]*[oO]', "cURL Command Line Downloader"),
            (rb'(?i)URLDownloadToFile', "Win32 URLDownloadToFile API"),
            (rb'(?i)(?:InternetOpenUrl|HttpOpenRequest|WinHttpOpenRequest)', "WinINet / WinHTTP Low-Level Network API"),
            (rb'(?i)(?:MSXML2\.XMLHTTP|Microsoft\.XMLHTTP|MSXML2\.ServerXMLHTTP)', "MSXML HTTP Retrieval Object"),
            (rb'(?i)WinHttp\.WinHttpRequest', "WinHTTP Request COM Object"),
            (rb'(?i)mshta(?:\.exe)?\s+https?://', "MSHTA Remote Script Execution"),
            (rb'(?i)(?:WScript\.Shell|Shell\.Application).*?https?://', "Script Remote Payload Invocation"),
        ]

        dropper_patterns = [
            (rb'(?i)TVqQAAMAAAAEAAAA', "Base64-encoded Windows PE Executable (MZ header)"),
            (rb'(?i)UEsDBBQ', "Base64-encoded ZIP Archive (PK header)"),
        ]

        # 1. Downloader Detection
        for pattern, desc in downloader_patterns:
            if re.search(pattern, data):
                self.results["capabilities"]["downloader_dropper"] = True
                self.results["threat_intel"]["is_suspected_vector"] = True
                warning = f"Downloader capability identified: {desc}"
                if warning not in self.results["threat_intel"]["warnings"]:
                    self.results["threat_intel"]["warnings"].append(warning)

        # 2. Dropper / Embedded Artifact Detection
        for pattern, desc in dropper_patterns:
            if re.search(pattern, data):
                self.results["capabilities"]["downloader_dropper"] = True
                self.results["threat_intel"]["is_suspected_vector"] = True
                warning = f"Dropper capability identified: {desc}"
                if warning not in self.results["threat_intel"]["warnings"]:
                    self.results["threat_intel"]["warnings"].append(warning)

        # 3. Payload Location Correlation
        has_downloader = self.results["capabilities"]["downloader_dropper"]
        has_embedded = bool(self.results["deep_analysis"].get("embedded_files"))
        urls = self.results["iocs"]["network"].get("urls_externas", [])

        if has_downloader and urls and has_embedded:
            self.results["file_info"]["payload_location"] = f"Dual Vector (Embedded Dropper + Remote C2: {urls[0]})"
        elif has_downloader and urls:
            self.results["file_info"]["payload_location"] = f"Remote C2 Downloader (Target: {urls[0]})"
        elif has_embedded:
            self.results["file_info"]["payload_location"] = f"Internal Embedded Payload ({len(self.results['deep_analysis']['embedded_files'])} artifact(s))"
        elif urls:
            self.results["file_info"]["payload_location"] = f"External Network Access ({len(urls)} URL(s) detected)"

    def detect_installer_type(self, data):
        found = [label for pattern, label in INSTALLER_MARKERS if re.search(pattern, data)]
        if found:
            self.results["deep_analysis"]["installer_analysis"]["installer_type"] = found[0]
            note = f"Installer framework detected: {', '.join(sorted(set(found)))}"
            if note not in self.results["threat_intel"]["warnings"]: 
                self.results["threat_intel"]["warnings"].append(note)
        return found

    def detect_embedded_archives_by_signature(self, data):
        found = []
        for signature, label in EMBEDDED_ARCHIVE_SIGNATURES:
            start = 0
            while True:
                idx = data.find(signature, start)
                if idx == -1: break
                if idx != 0:
                    item = {"type": label, "offset": idx}
                    found.append(item)
                    if item not in self.results["deep_analysis"]["embedded_files"]:
                        self.results["deep_analysis"]["embedded_files"].append(item)
                start = idx + 1
        
        for f in found:
            if f not in self.results["deep_analysis"]["installer_analysis"]["embedded_archives"]:
                self.results["deep_analysis"]["installer_analysis"]["embedded_archives"].append(f)
                
        if found and self.results["file_info"]["payload_location"] in ["None", "Nenhum"]:
            self.results["file_info"]["payload_location"] = "Internal (Embedded archive detected)"
        return found

    def _parse_fabric_mod_json(self, data):
        try:
            meta = json.loads(data.decode('utf-8', 'ignore'))
            self.results["deep_analysis"]["mod_metadata"]["mod_loader"] = "fabric"
            self.results["deep_analysis"]["mod_metadata"]["mod_id"] = meta.get("id")
            flat = {}
            for key, refs in meta.get("entrypoints", {}).items():
                flat[key] = [ref["value"] if isinstance(ref, dict) else ref for ref in refs]
            self.results["deep_analysis"]["mod_metadata"]["entrypoints"] = flat
        except Exception: pass

    def analyze_archive(self):
        try:
            with zipfile.ZipFile(self.file_path, 'r') as zf:
                infos = zf.infolist()[:MAX_ZIP_MEMBERS]
                total_uncompressed = 0
                for info in infos:
                    if info.file_size > MAX_ZIP_MEMBER_UNCOMPRESSED or os.path.isabs(info.filename) or ".." in Path(info.filename).parts:
                        continue
                    total_uncompressed += info.file_size
                    if total_uncompressed > MAX_ZIP_TOTAL_UNCOMPRESSED: break
                    if info.filename.endswith(".class") and info.filename not in self.results["deep_analysis"]["jar_classes"]: 
                        self.results["deep_analysis"]["jar_classes"].append(info.filename)
                    with zf.open(info.filename) as f:
                        data = f.read(MAX_ZIP_MEMBER_UNCOMPRESSED)
                        if info.filename.upper().endswith("MANIFEST.MF"):
                            manifest_text = data.decode('utf-8', 'ignore')
                            self.results["deep_analysis"]["manifest"]["raw_snippet"] = manifest_text[:MAX_MANIFEST_SNIPPET]
                            match = re.search(r'Main-Class:\s*(\S+)', manifest_text)
                            if match: self.results["deep_analysis"]["manifest"]["main_class"] = match.group(1)
                        if info.filename == "fabric.mod.json": self._parse_fabric_mod_json(data)
                        self.extract_network_iocs(data)
                        self.scan_suspicious_content(data, info.filename)
        except zipfile.BadZipFile:
            if "Corrupted or malformed ZIP archive." not in self.results["threat_intel"]["warnings"]:
                self.results["threat_intel"]["warnings"].append("Corrupted or malformed ZIP archive.")

    def _decode_int_array_xor(self, values, key, step):
        return bytes([v ^ ((key + (i * step)) & 255) for i, v in enumerate(values)])

    def _printable_ratio(self, data):
        return sum(1 for b in data if 32 <= b < 127) / len(data) if data else 0.0

    def _brute_force_xor_array(self, values):
        best = None
        for key in range(MAX_XOR_KEY):
            for step in range(MAX_XOR_STEP):
                decoded = self._decode_int_array_xor(values, key, step)
                ratio = self._printable_ratio(decoded)
                if ratio >= MIN_PRINTABLE_RATIO:
                    score = ratio + (1.0 if any(kw in decoded.lower() for kw in DECODE_KEYWORDS) else 0.0)
                    if not best or score > best[0]: best = (score, key, step, decoded)
        if best and best[0] >= MIN_PRINTABLE_RATIO:
            try: text = best[3].decode('utf-8')
            except UnicodeDecodeError: text = best[3].decode('latin-1', errors='replace')
            return {"key": best[1], "step": best[2], "decoded": text}
        return None

    def _check_evasion_techniques(self, text, class_simple_name):
        ev = self.results["capabilities"]["evasion_techniques"]
        if TIMESTOMPING_PATTERN.search(text): ev["timestomping_detected"] = True
        ev["silent_exception_swallowing_count"] += len(EMPTY_CATCH_PATTERN.findall(text))
        if SUPPRESSED_OUTPUT_PATTERN.search(text): ev["process_output_suppressed"] = True
        ev["obfuscation_functions_detected"] += len(XOR_DECODER_METHOD_PATTERN.findall(text))
        
        if class_simple_name and class_simple_name.lower() in SUSPICIOUS_ENTRYPOINT_NAMES:
            ev["suspicious_entrypoint_naming"] = class_simple_name
        
        if any(v for k,v in ev.items() if k != "silent_exception_swallowing_count" and v): 
            self.results["threat_intel"]["is_suspected_vector"] = True

    def scan_decompiled_sources(self):
        if not self.jadx_output_dir.exists(): return

        # Base directory for relative Java package paths (e.g., com/sample/target/...)
        sources_root = self.jadx_output_dir / "sources"
        base_dir = sources_root if sources_root.is_dir() else self.jadx_output_dir

        total_replaced = 0
        files_patched = 0

        for java_file in self.jadx_output_dir.rglob("*.java"):
            try:
                text = java_file.read_text(encoding='utf-8', errors='ignore')
                try:
                    rel_src = str(java_file.relative_to(base_dir))
                except ValueError:
                    rel_src = str(java_file.relative_to(self.jadx_output_dir))

                # 1. Android Byte Array Repeating-Key XOR Deobfuscation & Inline Patching
                patched_code, repl_count, apk_xor_items = patch_apk_byte_array_xor_code(text)

                # Persist rewritten Java file preserving exact directory hierarchy
                dest_file = self.deobfuscated_sources_dir / rel_src
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                dest_file.write_text(patched_code, encoding='utf-8')

                if repl_count > 0:
                    total_replaced += repl_count
                    files_patched += 1

                for item in apk_xor_items:
                    decoded_val = item["decoded_value"]
                    entry = {
                        "source_file": rel_src,
                        "obfuscation_type": "apk_repeating_byte_xor",
                        "data_length": item["data_length"],
                        "key_length": item["key_length"],
                        "decoded_value": decoded_val
                    }
                    if entry not in self.results["deep_analysis"]["recovered_obfuscated_strings"]:
                        self.results["deep_analysis"]["recovered_obfuscated_strings"].append(entry)

                    if decoded_val:
                        # Extract network IoCs from decrypted strings
                        self.extract_network_iocs(decoded_val.encode('utf-8', errors='ignore'))
                        
                        # Flag malicious keywords/commands
                        lowered = decoded_val.lower()
                        if any(kw in lowered for kw in ["http://", "https://", ".apk", ".dex", "chmod", "su ", "/system/", "exec(", "payload"]):
                            self.results["threat_intel"]["is_suspected_vector"] = True
                            warning_text = f"Decrypted Android string ({java_file.name}): {decoded_val[:80]}"
                            if warning_text not in self.results["threat_intel"]["warnings"]:
                                self.results["threat_intel"]["warnings"].append(warning_text)

                        if total_replaced <= 15:
                            console.print(f"[green][+] Decrypted Android XOR string ({java_file.name}):[/green] [bold white]{decoded_val}[/bold white]")

                # 2. Generic Java Integer Array XOR Brute-Force
                for name, raw_values in INT_ARRAY_PATTERN.findall(text):
                    values = [int(v.strip()) for v in raw_values.split(',') if v.strip()]
                    if len(values) >= 2:
                        res = self._brute_force_xor_array(values)
                        if res:
                            entry = {
                                "source_file": rel_src,
                                "array_name": name, "xor_key": res["key"], "xor_step": res["step"], "decoded_value": res["decoded"]
                            }
                            if entry not in self.results["deep_analysis"]["recovered_obfuscated_strings"]:
                                self.results["deep_analysis"]["recovered_obfuscated_strings"].append(entry)

                if "ProcessBuilder" in text and ("openStream" in text or "openConnection" in text) and "setExecutable" in text:
                    self.results["capabilities"]["downloader_dropper"] = True
                self._check_evasion_techniques(text, java_file.stem)
            except Exception: pass

        # Copy decoded AndroidManifest.xml if present so analyst has full source + manifest in deobfuscated folder
        for manifest_candidate in [
            self.jadx_output_dir / "AndroidManifest.xml",
            self.jadx_output_dir / "resources" / "AndroidManifest.xml"
        ]:
            if manifest_candidate.is_file():
                try:
                    dest_manifest = self.deobfuscated_sources_dir / "AndroidManifest.xml"
                    dest_manifest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(manifest_candidate, dest_manifest)
                    break
                except Exception: pass

        self.results["deep_analysis"]["deobfuscated_sources_dir"] = str(self.deobfuscated_sources_dir)
        self.results["deep_analysis"]["deobfuscated_strings_count"] = total_replaced

        if total_replaced > 0:
            console.print(f"[green][+] Inline Deobfuscation complete:[/green] [white]{total_replaced} XOR strings patched across {files_patched} Java file(s).[/white]")
            console.print(f"[bold green][+] Deobfuscated source code ready for review in:[/bold green] [cyan]{self.deobfuscated_sources_dir}[/cyan]")
        elif list(self.jadx_output_dir.rglob("*.java")):
            console.print(f"[dim][*] Java sources cloned to: {self.deobfuscated_sources_dir}[/dim]")

    def _compute_suspicion_score(self):
        score = 0
        breakdown = []
        ti = self.results["threat_intel"]
        
        # 1. Family Attribution
        fam = ti.get('family_attribution', {}).get('family', 'Unknown')
        if fam and fam not in ['Unknown', 'Desconhecida']:
            pts = 10
            score += pts
            breakdown.append({"category": "Threat Intel", "weight": pts, "justification": f"Malware family '{fam}' identified."})
            
        # 2. YARA Signatures
        if ti.get('yara_matches'):
            pts = len(ti['yara_matches']) * 3
            score += pts
            breakdown.append({"category": "YARA", "weight": pts, "justification": f"{len(ti['yara_matches'])} detection rule(s) triggered."})
            
        # 3. C2 Infrastructure
        iocs = self.results["iocs"]["network"]
        if iocs.get("abused_services") or iocs.get("onions") or iocs.get("ip_ports"):
            pts = 5
            score += pts
            breakdown.append({"category": "C2 Infrastructure", "weight": pts, "justification": "Tor .onion, exotic port, or abused cloud service detected."})
            
        # 4. Persistence
        if self.results["iocs"]["host"].get("persistence_artifacts"):
            pts = 4
            score += pts
            breakdown.append({"category": "Persistence", "weight": pts, "justification": "Auto-run registry key, scheduled task, or service installation detected."})
            
        # 5. Heuristic Warnings
        if ti.get("warnings"):
            pts = min(len(ti["warnings"]), 4)
            score += pts
            breakdown.append({"category": "Heuristics", "weight": pts, "justification": f"{len(ti['warnings'])} anomalous behavior warning(s) flagged."})
            
        # 6. Delivery Capabilities (Downloader / Dropper)
        if self.results["capabilities"].get("downloader_dropper"):
            pts = 4
            score += pts
            breakdown.append({"category": "Delivery Vector", "weight": pts, "justification": "Downloader or dropper staging mechanism identified."})
            
        ti["suspicion_score"] = score
        ti["scoring_breakdown"] = breakdown
        
        if score >= 8: level = "Critical"
        elif score >= 5: level = "High"
        elif score >= 3: level = "Medium"
        elif score > 0: level = "Low"
        else: level = "Clean"
        ti["suspicion_level"] = level

    def run_analysis(self):
        console.print(f"\n[cyan][*] Initializing triage routine:[/cyan] {self.file_path.name}")
        with open(self.file_path, 'rb') as f:
            self._raw_data_cache = f.read(MAX_FILE_READ_BYTES)

        self.results["file_info"]["hashes"] = self.get_file_hashes(self._raw_data_cache)
        self.results["file_info"]["file_type"] = self.detect_file_type(self._raw_data_cache)

        self.run_yara_scan(self._raw_data_cache)
        self.extract_network_iocs(self._raw_data_cache)
        self.detect_embedded_payloads(self._raw_data_cache)
        self.detect_installer_type(self._raw_data_cache)
        self.detect_embedded_archives_by_signature(self._raw_data_cache)
        self.scan_suspicious_content(self._raw_data_cache)
        self.detect_downloader_dropper_capabilities(self._raw_data_cache)

        ft = self.results["file_info"]["file_type"]
        if "PE" in ft:
            self.analyze_pe()
        elif "Archive" in ft or "ZIP" in ft or "Android" in ft or "APK" in ft:
            self.analyze_archive()
        elif "PDF" in ft:
            pdf_findings = analyze_pdf_content(self._raw_data_cache)
            self.results["deep_analysis"]["pdf_analysis"] = pdf_findings
            if pdf_findings:
                self.results["threat_intel"]["is_suspected_vector"] = True
                self.results["threat_intel"]["warnings"].extend(pdf_findings)
        elif "Shortcut" in ft or "LNK" in ft:
            lnk_findings = analyze_lnk_content(self._raw_data_cache)
            self.results["deep_analysis"]["lnk_analysis"] = lnk_findings
            if lnk_findings:
                self.results["threat_intel"]["is_suspected_vector"] = True
                self.results["threat_intel"]["warnings"].append(f"Suspicious shortcut detected. Extracted commands: {len(lnk_findings)}")
        
        # New Routings
        if "OLE" in ft or "RTF" in ft:
            office_findings = analyze_office_content(self._raw_data_cache)
            self.results["deep_analysis"]["office_analysis"] = office_findings
            if office_findings:
                self.results["threat_intel"]["is_suspected_vector"] = True
                self.results["threat_intel"]["warnings"].extend(office_findings)
                
        if "Script" in ft or "Raw Data" in ft or "Unknown" in ft:
            # PS1 Deobfuscation
            deobfuscated = deobfuscate_powershell(self._raw_data_cache)
            if deobfuscated and deobfuscated != self._raw_data_cache:
                self.extract_network_iocs(deobfuscated)  # Extract IoCs from deobfuscated payload
                
            script_findings = analyze_script_content(self._raw_data_cache)
            if deobfuscated: script_findings.extend(analyze_script_content(deobfuscated))
            script_findings = list(set(script_findings))
            
            self.results["deep_analysis"]["script_analysis"] = script_findings
            if script_findings:
                self.results["threat_intel"]["is_suspected_vector"] = True
                self.results["threat_intel"]["warnings"].extend(script_findings)
                
        # Run advanced binary analysis on all PE, ELF, Mach-O and generic payloads
        if any(t in self.results["file_info"]["file_type"] for t in ["PE", "ELF", "Mach-O", "Archive"]):
            bin_findings = analyze_advanced_binary(self._raw_data_cache)
            self.results["deep_analysis"]["advanced_bin_analysis"] = bin_findings
            if bin_findings:
                self.results["threat_intel"]["is_suspected_vector"] = True
                self.results["threat_intel"]["warnings"].extend(bin_findings)

        self.plugin_manager.run_all(self._raw_data_cache, self.results)
        self.check_virustotal()
        
        # Family Attribution Engine
        family, confidence, config = attribute_malware_family(self._raw_data_cache, self.results["threat_intel"]["yara_matches"])
        self.results["threat_intel"]["family_attribution"]["family"] = family
        self.results["threat_intel"]["family_attribution"]["confidence"] = confidence
        self.results["threat_intel"]["family_attribution"]["extracted_config"] = config
        
        if family != "Unknown":
            self.results["threat_intel"]["is_suspected_vector"] = True
            
        self._compute_suspicion_score()
        self.save_report()
        if self.interactive:
            self.interactive_menu()

    def save_report(self):
        # Remove empty deep_analysis node for SIEM ingestion safely
        report_data = dict(self.results)
        if 'deep_analysis' in report_data and not any(report_data['deep_analysis'].values()):
            report_data.pop('deep_analysis', None)

        with open(self.report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
            
        # SQLite Database Cache
        try:
            db = FormigaDB()
            db.save_report(self.results)
        except: pass
        
        # Auto-Generators (Yara / Snort / MITRE)
        try:
            family = self.results['threat_intel']['family_attribution']['family']
            sha256 = self.results['file_info']['hashes']['sha256']
            
            snort_rules = generate_snort_rules(self.results["iocs"], family)
            if snort_rules:
                with open(self.file_path.parent / f"{self.file_path.stem}_snort.rules", 'w', encoding='utf-8') as f:
                    f.write(snort_rules)
                    
            all_strings = self.results["iocs"]["network"]["urls_externas"] + self.results["iocs"]["host"]["persistence_artifacts"]
            if all_strings:
                yara_rule = generate_yara_rule(sha256, family, all_strings)
                with open(self.file_path.parent / f"{self.file_path.stem}_auto.yar", 'w', encoding='utf-8') as f:
                    f.write(yara_rule)
        except: pass

    def _find_7z_binary(self):
        found = shutil.which("7z") or shutil.which("7z.exe") or shutil.which("7zz") or shutil.which("7za")
        if found: return found
        if os.name == "nt":
            for c in [os.path.expandvars(r"%ProgramFiles%\7-Zip\7z.exe"), os.path.expandvars(r"%ProgramFiles(x86)%\7-Zip\7z.exe")]:
                if c and os.path.isfile(c): return c
        return None

    def _list_archive_with_7z(self, archive_path):
        sevenzip = self._find_7z_binary()
        if not sevenzip: return None, "7z binary not found in system PATH."
        try:
            result = subprocess.run([sevenzip, "l", "-slt", str(archive_path)], capture_output=True, text=True, timeout=60)
            return result.stdout if result.returncode == 0 else None, result.stderr
        except Exception as e: return None, str(e)

    def _estimate_uncompressed_size_7z(self, listing_text):
        total, count = 0, 0
        for line in listing_text.splitlines():
            if line.strip().startswith("Size ="):
                try:
                    total += int(line.split("=", 1)[1].strip())
                    count += 1
                except ValueError: pass
        return total, count

    def safe_extract_with_7z(self, archive_path, dest_dir):
        sevenzip = self._find_7z_binary()
        if not sevenzip: return False
        listing, _ = self._list_archive_with_7z(archive_path)
        if listing:
            total_size, member_count = self._estimate_uncompressed_size_7z(listing)
            if member_count > MAX_ZIP_MEMBERS or total_size > MAX_ZIP_TOTAL_UNCOMPRESSED: return False
        
        dest_dir.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run([sevenzip, "x", f"-o{dest_dir}", "-y", str(archive_path)], capture_output=True, timeout=180)
            for p in dest_dir.rglob("*"):
                if p.is_file():
                    try: os.chmod(p, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
                    except Exception: pass
            return True
        except Exception: return False

    def recursive_extract_archives(self, root_dir, base_dir=None, depth=0):
        if depth > MAX_RECURSION_DEPTH: return
        for p in Path(root_dir).rglob("*"):
            if p.is_file() and p.suffix.lower() in ARCHIVE_EXTENSIONS:
                dest_dir = p.parent / f"{p.name}_extracted"
                if not dest_dir.exists() and self.safe_extract_with_7z(p, dest_dir):
                    entry = {"archive": str(p), "extracted_to": str(dest_dir), "depth": depth + 1}
                    if entry not in self.results["deep_analysis"]["installer_analysis"]["nested_extractions"]:
                        self.results["deep_analysis"]["installer_analysis"]["nested_extractions"].append(entry)
                    self.recursive_extract_archives(dest_dir, base_dir=base_dir, depth=depth + 1)

    def find_and_convert_unusual_modules(self, root_dir):
        converted = []
        for f in Path(root_dir).rglob("*"):
            if f.is_file() and f.suffix.lower() not in COMMON_KNOWN_EXTENSIONS:
                try:
                    data = f.read_bytes()
                    kind = None
                    new_extension = None
                    
                    # Identify V8 Bytenode via binary signature
                    if len(data) > 4 and data[2:4] == b'\xde\xc0':
                        kind = "v8_bytecode_compiled"
                        new_extension = ".v8c"
                        self.results["threat_intel"]["is_suspected_vector"] = True
                        
                        # Raw string extraction for IoC hunting
                        printable = set(string.printable.encode('ascii'))
                        current_string = bytearray()
                        for byte in data:
                            if byte in printable:
                                current_string.append(byte)
                            else:
                                if len(current_string) >= 15:
                                    s = current_string.decode('ascii', 'ignore')
                                    if any(kw in s.lower() for kw in ["http", "discord", "api", "webhook"]):
                                        entry = {"source_file": f.name, "extracted_string": s}
                                        if entry not in self.results["deep_analysis"]["recovered_obfuscated_strings"]:
                                            self.results["deep_analysis"]["recovered_obfuscated_strings"].append(entry)
                                        current_string = bytearray()
                        if len(current_string) >= 15:
                            s = current_string.decode('ascii', 'ignore')
                            if any(kw in s.lower() for kw in ["http", "discord", "api", "webhook"]):
                                entry = {"source_file": f.name, "extracted_string": s}
                                if entry not in self.results["deep_analysis"]["recovered_obfuscated_strings"]:
                                    self.results["deep_analysis"]["recovered_obfuscated_strings"].append(entry)
                    
                    elif f.suffix.lower() == '.nqc':
                        kind = "obfuscated_javascript"
                        new_extension = ".js"
                    elif data.strip().startswith(b'{'):
                        kind = "json"
                        new_extension = ".json"
                    elif sum(1 for b in data[:8192] if 32 <= b < 127)/8192 > 0.85:
                        kind = "text"
                        new_extension = ".txt"
                    
                    if kind:
                        dest = f.with_name(f.name + new_extension)
                        shutil.copy2(f, dest)
                        converted.append({"original": str(f.name), "converted": str(dest.name), "detected_type": kind})
                except Exception: pass
        
        for c in converted:
            if c not in self.results["deep_analysis"]["installer_analysis"]["converted_modules"]:
                self.results["deep_analysis"]["installer_analysis"]["converted_modules"].append(c)

    def analyze_installer_pipeline(self):
        console.print("\n[yellow][*] Initializing recursive extraction routine...[/yellow]")
        dest_dir = self.file_path.parent / f"{self.file_path.stem}_extracted_safe"
        if self.safe_extract_with_7z(self.file_path, dest_dir):
            self.results["deep_analysis"]["installer_analysis"]["extraction_dir"] = str(dest_dir)
            self.recursive_extract_archives(dest_dir, dest_dir)
            self.find_and_convert_unusual_modules(dest_dir)
            console.print(f"[green][+] Structure mapped successfully to: {dest_dir}[/green]")

    def safe_download_payload(self, url):
        self.safe_download_dir.mkdir(exist_ok=True)
        dest_path = self.safe_download_dir / "quarantine_payload.vir"
        try:
            self._validate_url_for_ssrf(url)
            with requests.get(url, stream=True, timeout=DOWNLOAD_TIMEOUT) as r:
                r.raise_for_status()
                with open(dest_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192): f.write(chunk)
            console.print(f"[green][+] Payload capture completed: {dest_path}[/green]")
        except Exception as e:
            console.print(f"[red][-] Remote payload acquisition failed: {e}[/red]")

    def _find_jadx_cmd(self):
        found = shutil.which("jadx") or shutil.which("jadx.bat")
        if found:
            return [found]
        if os.name == "nt":
            candidates = [
                Path(os.path.expandvars(r"%ProgramFiles%\jadx\bin\jadx.bat")),
                Path(os.path.expandvars(r"%ProgramFiles(x86)%\jadx\bin\jadx.bat")),
                Path(os.path.expandvars(r"%USERPROFILE%\jadx\bin\jadx.bat")),
            ]
            for c in candidates:
                if c.is_file():
                    return [str(c)]
            downloads = Path.home() / "Downloads"
            if downloads.is_dir():
                for jdir in downloads.glob("*jadx*"):
                    if jdir.is_dir():
                        bat = jdir / "bin" / "jadx.bat"
                        if bat.is_file():
                            return [str(bat)]
                        jre_java = jdir / "jre" / "bin" / "java.exe"
                        for jar in jdir.rglob("jadx-*.jar"):
                            if jar.is_file():
                                java_bin = str(jre_java) if jre_java.is_file() else (shutil.which("java") or "java")
                                return [java_bin, "-cp", str(jar), "jadx.cli.JadxCLI"]
        else:
            # Linux / Unix candidates
            candidates = [
                Path("/usr/local/bin/jadx"),
                Path("/usr/bin/jadx"),
                Path("/opt/jadx/bin/jadx"),
                Path.home() / ".local/bin/jadx",
                Path.home() / "jadx/bin/jadx",
            ]
            for c in candidates:
                if c.is_file() and os.access(c, os.X_OK):
                    return [str(c)]
            for search_dir in [Path.home() / "Downloads", Path.home()]:
                if search_dir.is_dir():
                    for jdir in search_dir.glob("*jadx*"):
                        if jdir.is_dir():
                            bin_path = jdir / "bin" / "jadx"
                            if bin_path.is_file() and os.access(bin_path, os.X_OK):
                                return [str(bin_path)]
        return None

    def _find_target_for_jadx(self):
        target = self.file_path
        if target.suffix.lower() == ".dex":
            # Search parent or grandparent for the original container .apk
            candidates = [
                target.with_suffix(".apk"),
                target.parent.with_suffix(".apk"),
                target.parent / f"{target.parent.name}.apk",
                target.parent.parent / f"{target.parent.name.replace('_extracted_safe', '').replace('_extracted', '')}.apk"
            ]
            for c in candidates:
                if c.is_file():
                    return c
        return target

    def _extract_manifest_with_apktool(self, apk_path):
        apktool_bin = shutil.which("apktool") or shutil.which("apktool.bat")
        if not apktool_bin:
            return None
        
        console.print("[cyan][*] Invoking apktool fallback (apktool d -s) to decode AndroidManifest.xml...[/cyan]")
        temp_dir = self.jadx_output_dir / "_apktool_manifest_tmp"
        try:
            subprocess.run(
                [apktool_bin, "d", str(apk_path), "-s", "-f", "-o", str(temp_dir)],
                capture_output=True,
                timeout=60
            )
            candidate = temp_dir / "AndroidManifest.xml"
            if candidate.is_file():
                res_dir = self.jadx_output_dir / "resources"
                res_dir.mkdir(parents=True, exist_ok=True)
                dest = res_dir / "AndroidManifest.xml"
                shutil.copy2(candidate, dest)
                shutil.copy2(candidate, self.jadx_output_dir / "AndroidManifest.xml")
                console.print("[green][+] AndroidManifest.xml recovered via apktool fallback.[/green]")
                return dest
        except Exception as e:
            console.print(f"[dim]apktool fallback error: {e}[/dim]")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
        return None

    def analyze_android_manifest(self, manifest_path):
        try:
            xml_text = manifest_path.read_text(encoding="utf-8", errors="ignore")
            if not xml_text.strip():
                return

            pkg_match = re.search(r'package\s*=\s*["\']([^"\']+)["\']', xml_text)
            pkg_name = pkg_match.group(1) if pkg_match else "Unknown"

            permissions = re.findall(r'<uses-permission[^>]+android:name\s*=\s*["\']([^"\']+)["\']', xml_text)
            permissions = sorted(list(set(permissions)))

            dangerous_map = {
                "android.permission.BIND_ACCESSIBILITY_SERVICE": "Accessibility Abuse (Banking Trojan / Keylogger / Overlay)",
                "android.permission.SYSTEM_ALERT_WINDOW": "System Overlay Window (Screen Hijacking / Phishing Overlay)",
                "android.permission.RECEIVE_BOOT_COMPLETED": "Boot Persistence (Auto-start on device reboot)",
                "android.permission.READ_SMS": "SMS Interception / Reading (2FA OTP Theft)",
                "android.permission.RECEIVE_SMS": "SMS Interception / Receiving (2FA OTP Theft)",
                "android.permission.SEND_SMS": "Unauthorized SMS Dispatch (Premium SMS Fraud)",
                "android.permission.REQUEST_INSTALL_PACKAGES": "Arbitrary Package Installer (Dropper / Payload Stager)",
                "android.permission.RECORD_AUDIO": "Audio Surveillance / Eavesdropping",
                "android.permission.CAMERA": "Unauthorized Camera Capture / Spyware",
                "android.permission.READ_CALL_LOG": "Call Log Interception",
                "android.permission.READ_CONTACTS": "Address Book Exfiltration",
                "android.permission.ACCESS_FINE_LOCATION": "Precise GPS Geolocation Tracking",
                "android.permission.QUERY_ALL_PACKAGES": "Installed App Enumeration (Targeting Banking / Crypto Apps)",
            }

            flagged_dangerous = []
            for perm in permissions:
                for dangerous_perm, desc in dangerous_map.items():
                    if dangerous_perm in perm:
                        flagged_dangerous.append(f"{perm} ({desc})")
                        warning_msg = f"APK Permission: {desc}"
                        if warning_msg not in self.results["threat_intel"]["warnings"]:
                            self.results["threat_intel"]["warnings"].append(warning_msg)
                        self.results["threat_intel"]["is_suspected_vector"] = True

            if any("ACCESSIBILITY" in p for p in permissions) or any("SYSTEM_ALERT_WINDOW" in p for p in permissions):
                self.results["capabilities"]["downloader_dropper"] = True

            self.results["deep_analysis"]["android_manifest"] = {
                "manifest_path": str(manifest_path),
                "package_name": pkg_name,
                "total_permissions": len(permissions),
                "declared_permissions": permissions,
                "dangerous_permissions": flagged_dangerous,
            }

            console.print(f"[green][+] AndroidManifest.xml successfully decoded:[/green] [white]Package:[/white] [cyan]{pkg_name}[/cyan] | [white]Permissions:[/white] [yellow]{len(permissions)}[/yellow] ([red]{len(flagged_dangerous)} high-risk[/red])")
            for d in flagged_dangerous:
                console.print(f"    [red][!] Dangerous Android Permission:[/red] {d}")

        except Exception as e:
            console.print(f"[dim]Failed to parse decoded AndroidManifest.xml: {e}[/dim]")

    def decompile_with_jadx(self):
        jadx_cmd = self._find_jadx_cmd()
        if not jadx_cmd: 
            console.print("[red][-] Missing dependency: JADX not found in system PATH or common directories.[/red]")
            if os.name != "nt":
                console.print("[dim]Quick install on Ubuntu: sudo apt install -y default-jre && wget https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip && unzip jadx-1.5.0.zip -d ~/jadx[/dim]")
            else:
                console.print("[dim]Download JADX from https://github.com/skylot/jadx and add it to PATH.[/dim]")
            return

        target_input = self._find_target_for_jadx()
        is_apk = target_input.suffix.lower() == ".apk" or "APK" in self.results["file_info"]["file_type"] or "Android" in self.results["file_info"]["file_type"]

        console.print(f"[cyan][*] Decompiling target using JADX (sources + resources): {target_input.name}...[/cyan]")
        self.jadx_output_dir.mkdir(exist_ok=True)
        try:
            # Without --no-res / -r to ensure resources and AndroidManifest.xml are decoded
            cmd = jadx_cmd + ["-d", str(self.jadx_output_dir), str(target_input)]
            subprocess.run(cmd, capture_output=True, timeout=JADX_TIMEOUT)
            
            # Locate decoded AndroidManifest.xml
            manifest_file = None
            for cand in [
                self.jadx_output_dir / "resources" / "AndroidManifest.xml",
                self.jadx_output_dir / "AndroidManifest.xml",
            ]:
                if cand.is_file():
                    manifest_file = cand
                    break
            
            if not manifest_file:
                for cand in self.jadx_output_dir.rglob("AndroidManifest.xml"):
                    if cand.is_file():
                        manifest_file = cand
                        break

            # Fallback to apktool if AndroidManifest.xml was not generated for an APK
            if not manifest_file and is_apk:
                manifest_file = self._extract_manifest_with_apktool(target_input)

            # Ensure clean AndroidManifest.xml is accessible both in resources/ and at root
            if manifest_file and manifest_file.is_file():
                root_manifest = self.jadx_output_dir / "AndroidManifest.xml"
                res_manifest = self.jadx_output_dir / "resources" / "AndroidManifest.xml"
                if manifest_file != root_manifest and not root_manifest.exists():
                    try: shutil.copy2(manifest_file, root_manifest)
                    except Exception: pass
                if manifest_file != res_manifest and not res_manifest.exists():
                    try:
                        (self.jadx_output_dir / "resources").mkdir(exist_ok=True)
                        shutil.copy2(manifest_file, res_manifest)
                    except Exception: pass
                
                self.analyze_android_manifest(manifest_file)
            elif is_apk:
                console.print("[yellow][!] Warning: AndroidManifest.xml was not found. Install JADX or apktool to decode APK resources.[/yellow]")

            self.scan_decompiled_sources()
            self.save_report()
            console.print(f"[green][+] Decompilation completed. Output: {self.jadx_output_dir}[/green]")
        except Exception as e:
            console.print(f"[red][-] Decompilation failed: {e}[/red]")

    def interactive_menu(self):
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            
            console.print("\n")
            console.print(Panel(f"[bold white]THREAT VECTOR:[/bold white] [bold cyan]{self.file_path.name}[/bold cyan]", border_style="cyan"))
            
            ti = self.results["threat_intel"]
            fi = self.results["file_info"]
            
            level = ti.get('suspicion_level', 'Clean')
            status_color = "bold red" if level in ["Critical", "High"] else ("bold yellow" if level == "Medium" else "bold green")
            console.print(f"[{status_color}]>> Threat Level: {level.upper()}[/{status_color}] | [white]Score: {ti['suspicion_score']} ({level})[/white]")
            
            vt_status = ti["virustotal_report"] or "Pending validation"
            console.print(f"[bold yellow]>> VirusTotal Integration:[/bold yellow] {vt_status}")
            
            # Show Threat Actor Family Attribution
            fa = ti.get("family_attribution", {})
            if fa.get("family") and fa.get("family") != "Unknown":
                console.print(f"[bold red]>> Malware Family Attribution (Threat Intel):[/bold red] [white]{fa['family']} | Confidence: {fa['confidence']}[/white]")
                if fa.get("extracted_config"):
                    console.print(f"   [dim]Extracted Configuration: {fa['extracted_config']}[/dim]")
            console.print("\n")

            hash_table = Table(show_header=True, header_style="bold magenta", box=None)
            hash_table.add_column("Algorithm")
            hash_table.add_column("Checksum", style="dim")
            hash_table.add_row("MD5", fi["hashes"]["md5"])
            hash_table.add_row("SHA256", fi["hashes"]["sha256"])
            if fi["hashes"]["imphash"]:
                hash_table.add_row("Imphash", fi["hashes"]["imphash"])
            console.print(hash_table)
            
            if fi["is_packed"]:
                console.print("\n[on red][bold white] ALERT [/bold white][/on red] [red]Anomalous entropy detected (> 7.2). Potential packer/cryptor present.[/red]")
            if ti['yara_matches']:
                console.print(f"[on red][bold white] YARA [/bold white][/on red] [red]Matching signatures:[/red] {', '.join([m['rule_name'] for m in ti['yara_matches']])}")
            if self.results["capabilities"]["mitre_attack_tactics"]:
                console.print(f"[on yellow][bold black] MITRE [/bold black][/on yellow] [yellow]{len(self.results['capabilities']['mitre_attack_tactics'])} operational tactics mapped.[/yellow]")

            can_download = "External" in fi.get("payload_location", "") or bool(self.results["iocs"]["network"]["urls_externas"])
            can_extract_raw = bool(self.results["deep_analysis"].get("embedded_files"))
            can_jadx = "Archive" in fi["file_type"] or "PE" in fi["file_type"] or "Android" in fi["file_type"] or "APK" in fi["file_type"] or self.file_path.suffix.lower() in [".apk", ".dex", ".jar"]
            can_extract_7z = bool(self.results["deep_analysis"]["installer_analysis"]["installer_type"] or self.results["deep_analysis"]["installer_analysis"]["embedded_archives"])

            console.print("\n")
            menu = Table(title="[bold white]OPERATIONAL CONTROL[/bold white]", show_header=True, header_style="bold cyan", expand=True)
            menu.add_column("ID", justify="center", style="bold cyan", width=5)
            menu.add_column("Analysis Routine", justify="left")
            menu.add_column("Module Status", justify="center", width=25)

            menu.add_row("1", "Remote Payload Acquisition (Network/C2)", "[green]Available[/green]" if can_download else "[dim]Inactive[/dim]")
            menu.add_row("2", "Embedded Artifact Dumping (Base offset)", "[green]Available[/green]" if can_extract_raw else "[dim]Inactive[/dim]")
            menu.add_row("3", "Static Reversing (JADX Decompilation)", "[yellow]Optional[/yellow]" if can_jadx else "[dim]Inactive[/dim]")
            menu.add_row("4", "Structural Unpacking (Archive/Installer)", "[bold green]Recommended[/bold green]" if can_extract_7z else "[dim]Inactive[/dim]")
            menu.add_row("5", "MITRE ATT&CK Integration (Mandiant CAPA)", "[bold yellow]Highly Recommended[/bold yellow]")
            menu.add_row("6", "Obfuscated Strings Extraction (Mandiant FLOSS)", "[bold cyan]Advanced Static Analysis[/bold cyan]")
            menu.add_row("7", "CPU/Memory Emulation (Speakeasy)", "[bold magenta]Safe Dynamic Analysis[/bold magenta]")
            menu.add_row("8", "Cloud Detonation (Sandbox API - Triage)", "[bold red]External Action[/bold red]")
            menu.add_row("0", "Finish Triage", "")

            console.print(menu)

            escolha = Prompt.ask("\n[bold cyan]Module selection[/bold cyan]", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8"], default="0")
            
            if escolha == '0':
                console.print("[bold green]\n[+] Analysis session ended.[/bold green]")
                break
                
            elif escolha == '1':
                if can_download:
                    for url in self.results["iocs"]["network"]["urls_externas"]:
                        if "http" in url.lower() and Prompt.ask(f"Confirm acquisition of {self.defang_indicator(url)}?", choices=["y", "n"]) == 'y':
                            self.safe_download_payload(url)
                            break
                else:
                    console.print("[red][-] No active C2/URL instances for capture.[/red]")
                    
            elif escolha == '2':
                if can_extract_raw:
                    self.safe_download_dir.mkdir(exist_ok=True)
                    for item in self.results["deep_analysis"]["embedded_files"]:
                        offset = item["offset"]
                        extracted_path = self.safe_download_dir / f"extracted_payload_{offset}.vir"
                        with open(extracted_path, 'wb') as f:
                            f.write(self._raw_data_cache[offset:offset + MAX_DOWNLOAD_BYTES])
                        console.print(f"[+] Artifact isolated to: {extracted_path}")
                else:
                    console.print("[red][-] Embedded files not found in original binary.[/red]")
                    
            elif escolha == '3':
                if can_jadx:
                    self.decompile_with_jadx()
                else:
                    console.print("[red][-] File signature incompatible with JADX.[/red]")
                    
            elif escolha == '4':
                if can_extract_7z:
                    self.analyze_installer_pipeline()
                    self.save_report()
                else:
                    console.print("[red][-] Artifact does not require archive unpacking.[/red]")
                    
            elif escolha == '5':
                self.run_capa()
            elif escolha == '6':
                console.print("[cyan][*] Initializing FLOSS engine... (This may take time depending on obfuscation)[/cyan]")
                success, output = run_floss(self.file_path)
                if success:
                    out_file = self.file_path.parent / f"{self.file_path.stem}_floss.txt"
                    with open(out_file, 'w', encoding='utf-8') as f: f.write(output)
                    console.print(f"[green][+] FLOSS analysis completed! Results saved to: {out_file}[/green]")
                else:
                    console.print(f"[red][-] FLOSS Error/Warning: {output}[/red]")
            elif escolha == '7':
                console.print("[cyan][*] Emulating executable in memory via Speakeasy...[/cyan]")
                success, output = run_speakeasy(self.file_path)
                if success: console.print(f"[green][+] {output}[/green]")
                else: console.print(f"[red][-] {output}[/red]")
            elif escolha == '8':
                console.print("[cyan][*] Packaging artifact for Hatching Triage Sandbox...[/cyan]")
                success, output = submit_triage(self.file_path)
                if success: console.print(f"[green][+] {output}[/green]")
                else: console.print(f"[red][-] {output}[/red]")

            console.input("\n[dim]Press ENTER to return to the central panel...[/dim]")





















