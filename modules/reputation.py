import requests
import shutil
import subprocess

def check_malwarebazaar(sha256):
    try:
        r = requests.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": sha256}, timeout=5)
        if r.status_code == 200 and r.json().get("query_status") == "ok":
            data = r.json().get("data", [{}])[0]
            tags = data.get('tags') or []
            return f"MalwareBazaar: {data.get('signature', 'Generic')} | Tags: {','.join(tags)}"
    except Exception:
        pass
    return None

def check_urlhaus(url):
    try:
        r = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, timeout=5)
        if r.status_code == 200 and r.json().get("query_status") == "ok":
            return "URLhaus: HIGH Risk (Malware/Phishing)"
    except Exception:
        pass
    return None

def run_clamav(filepath):
    clam = shutil.which("clamscan") or shutil.which("clamscan.exe")
    if clam:
        try:
            res = subprocess.run([clam, "--no-summary", str(filepath)], capture_output=True, text=True, timeout=60)
            if "FOUND" in res.stdout:
                parts = res.stdout.split(":")
                return parts[-1].strip() if len(parts) > 1 else "Detected"
        except Exception:
            pass
    return None
