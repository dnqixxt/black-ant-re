import re

BIN_SUSPICIOUS = {
    rb'(?i)ConfuserEx': ".NET Obfuscator (ConfuserEx)",
    rb'(?i)_CorExeMain': ".NET Binary Signature",
    rb'MEI\x00': "PyInstaller/py2exe Detected (Embedded Python Package)",
    rb'pyi-windows-manifest': "PyInstaller Manifest",
    rb'app\.asar': "Electron ASAR Archive Detected",
    rb'Go build ID': "Golang Binary Signature Detected",
    rb'rustc': "Rust Binary Signature Detected",
    rb'\/system\/bin\/sh': "Android/ELF Shell Invocation",
    rb'BIND_ACCESSIBILITY_SERVICE': "APK Accessibility Service Abuse (Banking / Spyware)",
    rb'SYSTEM_ALERT_WINDOW': "APK Overlay Permission (Screen Overlay Attack)",
}

def analyze_advanced_binary(data):
    findings = []
    for pattern, desc in BIN_SUSPICIOUS.items():
        if re.search(pattern, data):
            findings.append(desc)
    return findings
