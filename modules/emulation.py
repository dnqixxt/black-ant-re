import os
import requests

def run_speakeasy(filepath):
    try:
        import speakeasy
        se = speakeasy.Speakeasy()
        module = se.load_module(str(filepath))
        se.run_module(module)
        apis = se.get_api_calls()
        if not apis:
            return True, "Emulation completed (0 API calls traced)."
        api_list = [f"{api.api_name}" for api in apis[:20]]
        return True, f"Hooked / Traced APIs: {', '.join(api_list)}"
    except ImportError:
        return False, "Speakeasy emulator engine not installed. Install via: pip install speakeasy-emulator"
    except Exception as e:
        return False, f"CPU emulation error: {str(e)}"

def submit_triage(filepath):
    api_key = os.environ.get("TRIAGE_API_KEY", "")
    if not api_key:
        return False, "Environment variable TRIAGE_API_KEY not configured."
    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        with open(filepath, 'rb') as f:
            r = requests.post("https://api.tria.ge/v0/samples", headers=headers, files={"file": f}, timeout=15)
        if r.status_code == 200:
            return True, f"Submitted to Hatching Triage! ID: {r.json().get('id')}"
        return False, f"Sandbox API Error: HTTP {r.status_code}"
    except Exception as e:
        return False, f"Connection error: {str(e)}"
