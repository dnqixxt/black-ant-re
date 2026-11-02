import re

SCRIPT_SUSPICIOUS = {
    rb'(?i)Invoke-Expression': "PowerShell IEX (Dynamic Execution)",
    rb'(?i) IEX ': "PowerShell IEX (Alias)",
    rb'(?i)FromBase64String': "PowerShell Base64 Decode",
    rb'(?i)VirtualAlloc': "Memory Allocation (Shellcode / Injection)",
    rb'(?i)DllCall': "AutoIt/AHK Direct DLL Call",
    rb'(?i)RunPE': "RunPE Technique (Process Hollowing)",
    rb'(?i)WScript\.Network': "VBS Network Reconnaissance",
    rb'(?i)install_requires\s*=\s*\[': "PyPI/npm Supply Chain Setup",
    rb'(?i)process\.env': "Environment Variable Access (NodeJS/Supply Chain)",
}

def analyze_script_content(data):
    findings = []
    for pattern, desc in SCRIPT_SUSPICIOUS.items():
        if re.search(pattern, data):
            findings.append(desc)
    return findings
