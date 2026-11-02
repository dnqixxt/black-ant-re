import re

def analyze_lnk_content(data):
    """
    Extracts strings (ASCII and UTF-16LE) from LNK files to map
    embedded commands and Mark-of-the-Web (MotW) bypass attempts.
    """
    ascii_strings = re.findall(rb'[ -~]{5,}', data)
    utf16_strings = re.findall(rb'(?:[ -~]\x00){5,}', data)
    
    all_strings = [s.decode('ascii', 'ignore') for s in ascii_strings] + \
                  [s.decode('utf-16le', 'ignore') for s in utf16_strings]
    
    suspicious_keywords = [
        'powershell', 'cmd.exe', 'wscript', 'cscript', 'mshta', 
        'http://', 'https://', 'ftp://', '.ps1', '.bat', '.vbs', '.exe'
    ]
    
    findings = []
    for s in all_strings:
        s_lower = s.lower()
        if any(kw in s_lower for kw in suspicious_keywords):
            # Filter common legitimate paths to reduce false positives
            if "system32" in s_lower and "cmd.exe" in s_lower and len(s) < 30:
                continue
            findings.append(s.strip())
            
    return list(set(findings))
