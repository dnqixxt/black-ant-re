import re

def extract_njrat(data):
    try:
        if b"netsh firewall add allowedprogram" in data.lower():
            if b"|'|'|" in data:
                chunks = data.split(b"|'|'|")
                if len(chunks) >= 4:
                    return {"c2": chunks[1].decode('utf-8', 'ignore'), "version": chunks[0][-6:].decode('utf-8', 'ignore')}
    except Exception:
        pass
    return None

def extract_asyncrat(data):
    if b'Bf3c88' in data or b'AsyncRAT' in data:
        return {"notice": "AsyncRAT cryptographic constants identified. Requires static AES decryption."}
    return None

def extract_cobalt_strike(data):
    if b'\x00\x00\x00\x01\x00\x01\x00\x02' in data or b'\x69\x69\x69\x69\x69' in data:
        return {"notice": "Cobalt Strike Beacon Configuration structure (XOR 0x69 or Default) detected."}
    return None

def extract_agent_tesla(data):
    if b'smtp.' in data and (b'passwords' in data.lower() or b'credentials' in data.lower()):
        emails = re.findall(rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', data)
        if emails:
            return {"exfiltration_emails": list(set([e.decode('utf-8', 'ignore') for e in emails]))}
    return None

def extract_redline(data):
    if b'http://tempuri.org/Entity/' in data or (b'Authorization: Basic' in data and b'net.tcp://' in data):
        urls = re.findall(rb'net\.tcp://[a-zA-Z0-9.:\-]+', data)
        if urls:
            return {"c2_net_tcp": [u.decode('utf-8', 'ignore') for u in urls]}
        return {"notice": "WCF/SOAP communication pattern typical of RedLine Stealer."}
    return None

def extract_formbook(data):
    if b'FBC_' in data or b'formbook' in data.lower() or b'\x46\x4F\x52\x4D\x42\x4F\x4F\x4B' in data:
        return {"notice": "Formbook/XLoader Hash Pattern detected."}
    return None

def attribute_malware_family(raw_data, yara_matches):
    """
    Family attribution engine based on YARA, Imphash, and static heuristics.
    Returns: (FamilyName, ConfidenceLevel, ExtractedConfigDict)
    """
    # 1. Cross-reference with triggered YARA rules
    for y_match in yara_matches:
        rule_name = y_match.get("rule_name", "").lower()
        if "redline" in rule_name: return "RedLine Stealer", "High (YARA)", extract_redline(raw_data) or {}
        if "asyncrat" in rule_name: return "AsyncRAT", "High (YARA)", extract_asyncrat(raw_data) or {}
        if "remcos" in rule_name: return "Remcos RAT", "High (YARA)", {"notice": "Config likely inside RC4 SETTINGS resource."}
        if "agenttesla" in rule_name: return "Agent Tesla", "High (YARA)", extract_agent_tesla(raw_data) or {}
        if "cobalt" in rule_name: return "Cobalt Strike", "High (YARA)", extract_cobalt_strike(raw_data) or {}
        if "lumma" in rule_name: return "Lumma Stealer", "High (YARA)", {}
        if "craxs" in rule_name or "spynote" in rule_name or "blackant" in rule_name:
            return "CraxsRAT / SpyNote (Variant)", "High (YARA)", {
                "crypto_scheme": "PBKDF2/AES",
                "c2_fallback": "log_error.php",
                "panel_path": "/yaarsa/private/"
            }
        
    # 2. Deep static heuristics & configuration extraction
    njrat = extract_njrat(raw_data)
    if njrat: return "njRAT", "High (Structural Extraction)", njrat
    
    redline = extract_redline(raw_data)
    if redline: return "RedLine Stealer", "Medium (String Pattern)", redline
    
    asyncrat = extract_asyncrat(raw_data)
    if asyncrat: return "AsyncRAT", "Medium (Cryptography)", asyncrat
    
    tesla = extract_agent_tesla(raw_data)
    if tesla: return "Agent Tesla", "Medium (SMTP Exfiltration)", tesla
    
    cobalt = extract_cobalt_strike(raw_data)
    if cobalt: return "Cobalt Strike", "Medium (Beacon Pattern)", cobalt
    
    formbook = extract_formbook(raw_data)
    if formbook: return "Formbook/XLoader", "Low (Strings)", formbook
    
    return "Unknown", "N/A", {}
