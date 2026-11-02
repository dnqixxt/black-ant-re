import re

OFFICE_SUSPICIOUS = {
    rb'(?i)AutoOpen': "Auto-executing Macro (AutoOpen)",
    rb'(?i)Document_Open': "Auto-executing Macro (Document_Open)",
    rb'(?i)WScript\.Shell': "Shell Execution (VBA/VBS)",
    rb'(?i)CreateObject': "COM Object Creation",
    rb'(?i)\\objdata': "Potential RTF Exploit (CVE-2017-11882 / Equation Editor)",
    rb'(?i)powershell': "PowerShell Invocation via Office",
    rb'(?i)cmd\.exe': "CMD Invocation via Office",
    rb'(?i)XMLHTTP': "Network Communication (Payload Download)",
    rb'(?i)DDEAUTO': "DDE Execution (Dynamic Data Exchange)"
}

def analyze_office_content(data):
    findings = []
    for pattern, desc in OFFICE_SUSPICIOUS.items():
        if re.search(pattern, data):
            findings.append(desc)
    return findings
