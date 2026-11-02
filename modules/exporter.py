import json
import hashlib
from datetime import datetime

# Whitelist of known legitimate domains to prevent noise in auto-generated rules
YARA_WHITELIST = ["github.com", "google.com", "pastebin.com", "discord.com", "mega.nz", "api.telegram.org"]

def generate_snort_rules(iocs, family="Unknown"):
    rules = []
    sid = 1000000
    for ip in iocs.get("network", {}).get("ips", []) + iocs.get("network", {}).get("ip_ports", []):
        clean_ip = ip.split(":")[0] if ":" in ip else ip
        rules.append(f'alert tcp $HOME_NET any -> {clean_ip} any (msg:"Black Ant - C2 {family}"; sid:{sid}; rev:1;)')
        sid += 1
    for url in iocs.get("network", {}).get("urls_externas", []) + iocs.get("network", {}).get("abused_services", []):
        clean_url = url.replace('"', '')
        rules.append(f'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Black Ant - Malicious URL {family}"; content:"{clean_url}"; sid:{sid}; rev:1;)')
        sid += 1
    return "\n".join(rules)

def generate_yara_rule(file_hash, family, strings_list):
    clean_family = family.replace(' ', '_').replace('/', '_').replace('-', '_')
    rule_name = f"BlackAnt_Auto_{clean_family}_{file_hash[:8]}"
    
    strings_section = ""
    # Filter short strings or common whitelist entries to minimize false positives
    valid_strings = [s for s in strings_list if len(s) > 8 and s.isprintable() and not any(w in s for w in YARA_WHITELIST)]
    valid_strings = list(set(valid_strings))[:15]  # Top 15 unique strings
    
    for i, s in enumerate(valid_strings):
        clean_s = s.replace('\\', '\\\\').replace('"', '\\"')
        strings_section += f'        $s{i} = "{clean_s}" ascii wide\n'
        
    yara = f'''rule {rule_name} {{
    meta:
        author = "Black Ant Auto-Generator"
        description = "Automated detection rule for {family}"
        hash = "{file_hash}"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
    strings:
{strings_section}
    condition:
        2 of them
}}'''
    return yara
    
def generate_attack_navigator(results):
    layer = {
        "name": f"Black Ant - {results['file_info']['hashes']['sha256'][:8]}",
        "version": "4.3",
        "domain": "enterprise-attack",
        "description": f"Family: {results['threat_intel']['family_attribution']['family']}",
        "techniques": []
    }
    return json.dumps(layer, indent=4)
