import base64
import gzip
import re
import subprocess
import shutil
from modules.apk_deobfuscator import (
    decrypt_java_byte_array_xor,
    escape_java_string,
    patch_apk_byte_array_xor_code,
    extract_apk_byte_array_xor_strings,
    BYTE_ARRAY_XOR_PATTERN,
)

CRYPTO_CONSTANTS = {
    b'\x20\x83\xb8\xed': "CRC32 Polynomial (Reversing / Malware Hash)",
    b'expand ' + b'32-byte k': "ChaCha/Salsa20 Constant (Ransomware / C2)",
    b'\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5': "AES S-Box Table (Embedded Cryptography)",
    b'\xa5\x63\x63\xc6\x84\x7c\x7c\xf8': "AES Inv S-Box Table",
    b'This program cannot be ' + b'run in DOS mode': "Embedded PE Binary Header Identified"
}

def try_decompress(data):
    if data.startswith(b'\x1f\x8b'):
        try:
            return gzip.decompress(data)
        except Exception:
            pass
    return None

def recursive_decode_base64(blob, depth=0, max_depth=3):
    if depth > max_depth:
        return []
    results = []
    
    padding = b'=' * (-len(blob) % 4)
    padded_blob = blob + padding
    
    try:
        decoded = base64.b64decode(padded_blob, validate=False)
        results.append(decoded)
        
        decomp = try_decompress(decoded)
        if decomp:
            results.append(decomp)
            nested_b64 = re.findall(rb'(?:[A-Za-z0-9+/]{4}){15,}', decomp)
            for n_blob in nested_b64:
                results.extend(recursive_decode_base64(n_blob, depth + 1))
                
    except Exception:
        pass
    return results

def deobfuscate_powershell(script_bytes):
    try:
        script = script_bytes.decode('utf-8', 'ignore')
    except Exception:
        return None
    
    # 1. Remove backticks
    script = re.sub(r'`([^`])', r'\1', script)
    # 2. String concat
    script = re.sub(r"(?i)(['\"])\s*\+\s*(['\"])", "", script)
    # 3. Char arrays
    chars = re.findall(r'\[char\]\s*\(?\s*(\d{2,3})\s*\)?', script, re.IGNORECASE)
    if len(chars) > 5:
        try:
            decoded_str = "".join(chr(int(c)) for c in chars)
            script += f"\n--- DECODED CHAR ARRAY ---\n{decoded_str}"
        except Exception:
            pass
        
    return script.encode('utf-8', 'ignore')

def find_crypto_constants(data):
    findings = []
    for pattern, desc in CRYPTO_CONSTANTS.items():
        if pattern in data:
            findings.append(desc)
    return findings

def run_floss(filepath):
    floss_path = shutil.which("floss") or shutil.which("floss.exe")
    if not floss_path:
        return False, "FLOSS not found. Install via: pip install flare-floss"
        
    try:
        res = subprocess.run([floss_path, "-q", str(filepath)], capture_output=True, text=True, timeout=120)
        return True, res.stdout
    except subprocess.TimeoutExpired:
        return False, "FLOSS Timeout (Analysis took too long)."
    except Exception as e:
        return False, str(e)
