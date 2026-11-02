import re
import hashlib

B58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def is_valid_base58check(address_bytes):
    """Validate pure Base58Check (BTC/LTC/TRX) in Python."""
    try:
        addr_str = address_bytes.decode('ascii')
        n = 0
        for char in addr_str:
            n = n * 58 + B58_ALPHABET.index(char.encode('ascii'))
        
        h = hex(n)[2:]
        if len(h) % 2 != 0: h = '0' + h
        res = bytes.fromhex(h)
        
        pad = 0
        for char in addr_str:
            if char == '1': pad += 1
            else: break
        res = (b'\x00' * pad) + res
        
        if len(res) < 4: return False
        
        payload = res[:-4]
        checksum = res[-4:]
        hash1 = hashlib.sha256(payload).digest()
        hash2 = hashlib.sha256(hash1).digest()
        return checksum == hash2[:4]
    except Exception:
        return False

# High-precision IoC detection regexes
REGEX_CRYPTO = [
    (rb'\b(?:bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,39}\b', "BTC", True),  # Base58 or Bech32
    (rb'\bT[A-Za-z1-9]{33}\b', "Tron (TRX)", True),
    (rb'\b(?:L|M)[a-km-zA-HJ-NP-Z1-9]{26,33}\b', "Litecoin (LTC)", True),
    (rb'\b0x[a-fA-F0-9]{40}\b', "Ethereum (ETH)", False),
    (rb'\b(?:4|8)[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b', "Monero (XMR)", False),
    (rb'\b[1-9A-HJ-NP-Za-km-z]{32,44}\b', "Solana (SOL)", False)  # Base58 without BTC checksum
]

REGEX_NETWORK = {
    "ip_port": rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:\d{2,5}\b',
    "ipv6": rb'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b',
    "onion": rb'\b[a-z2-7]{16,56}\.onion\b',
    "abused_services": rb'(?i)(?:pastebin\.com/(?:raw/)?\w+|raw\.githubusercontent\.com/[\w.-]+/[\w.-]+|mega\.nz/(?:file|folder)/[\w!#-]+|discord\.com/api/webhooks/\d+/[\w.-]+|api\.telegram\.org/bot\d+:[\w.-]+)',
    "user_agent": rb'\bMozilla/5\.0 \([^)]+\)(?: AppleWebKit/[0-9.]+ \(KHTML, like Gecko\))?(?: Chrome/[0-9.]+)?(?: Safari/[0-9.]+)?\b'
}

REGEX_HOST = {
    "persistence_registry": rb'(?i)Software\\(?:WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce|Policies\\Explorer)',
    "scheduled_task": rb'(?i)schtasks(?:\.exe)?\s+.*?/create',
    "services": rb'(?i)sc(?:\.exe)?\s+.*?create.*?binpath',
    "dangerous_paths": rb'(?i)(?:%APPDATA%|%TEMP%|%PUBLIC%|C:\\Users\\Public)',
}

def extract_advanced_iocs(data):
    results = {
        "network": {"ip_ports": [], "ipv6": [], "onions": [], "abused_services": [], "user_agents": []},
        "host": {"persistence": [], "dangerous_paths": []},
        "wallets": {}
    }
    
    # Cryptocurrency wallets with checksum validation to eliminate false positives
    for pattern, name, require_b58 in REGEX_CRYPTO:
        matches = re.findall(pattern, data)
        valid_matches = []
        for m in matches:
            if require_b58 and not is_valid_base58check(m) and not m.startswith(b'bc1'): 
                continue  # Skip invalid candidates
            valid_matches.append(m.decode('utf-8', 'ignore'))
        if valid_matches:
            if name not in results["wallets"]: results["wallets"][name] = []
            results["wallets"][name].extend(list(set(valid_matches)))

    # Network IoCs
    for key, pattern in REGEX_NETWORK.items():
        matches = [m.decode('utf-8', 'ignore') for m in re.findall(pattern, data)]
        results["network"][key + "s" if not key.endswith('s') else key] = list(set(matches))
        
    # Host IoCs
    for key, pattern in REGEX_HOST.items():
        matches = [m.decode('utf-8', 'ignore').strip() for m in re.findall(pattern, data)]
        results["host"]["persistence" if "persistence" in key or "task" in key or "service" in key else key] += list(set(matches))
        
    results["host"]["persistence"] = list(set(results["host"]["persistence"]))
    results["host"]["dangerous_paths"] = list(set(results["host"]["dangerous_paths"]))
    
    return results
