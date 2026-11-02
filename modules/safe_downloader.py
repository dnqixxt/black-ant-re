import socket
import requests
from urllib.parse import urlparse
import ipaddress

def is_safe_ip(ip_str):
    """ Validates SSRF (Server-Side Request Forgery) """
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global and not ip.is_private and not ip.is_loopback
    except: return False

def safe_download_c2(url, max_size=1024*1024*10):  # 10MB max payload limit
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname: return None, "Invalid URL"
    
    try:
        # 1. Fixed DNS resolution (mitigates DNS rebinding)
        ip = socket.gethostbyname(hostname)
    except:
        return None, "DNS resolution failed"
    
    # 2. SSRF validation
    if not is_safe_ip(ip):
        return None, f"SSRF Blocked: The IP ({ip}) belongs to an internal network."
        
    # 3. Pinned IP request with virtual Host header
    safe_url = url.replace(hostname, ip)
    headers = {"Host": hostname, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BlackAnt/1.0"}
    
    try:
        r = requests.get(safe_url, headers=headers, stream=True, timeout=10, allow_redirects=False)
        if r.status_code in [301, 302, 307, 308]:
            return None, "Redirect blocked (Evasion risk)."
            
        content = b""
        for chunk in r.iter_content(8192):
            content += chunk
            if len(content) > max_size:
                return None, "Size exceeded safe limit (10MB)."
                
        return content, f"Success (Pinned IP: {ip})"
    except Exception as e:
        return None, f"Connection error: {str(e)}"
