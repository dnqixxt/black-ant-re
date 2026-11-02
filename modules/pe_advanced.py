import shutil
import tempfile
import subprocess
import os
import time

try:
    import ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False

try:
    import tlsh
    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False

def calculate_advanced_hashes(data):
    hashes = {}
    if SSDEEP_AVAILABLE:
        try:
            hashes["ssdeep"] = ssdeep.hash(data)
        except Exception:
            pass
    if TLSH_AVAILABLE:
        try:
            hashes["tlsh"] = tlsh.hash(data)
        except Exception:
            pass
    return hashes

def analyze_pe_deep(pe, raw_data, filepath):
    findings = {
        "warnings": [],
        "api_combinations": [],
        "has_overlay": False,
        "tls_callbacks": False,
        "is_signed": False,
        "metadata": {}
    }
    
    # 1. Signature (Security Directory)
    try:
        if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4:
                security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # IMAGE_DIRECTORY_ENTRY_SECURITY
                if security_dir.VirtualAddress > 0 and security_dir.Size > 0:
                    findings["is_signed"] = True
    except Exception:
        pass
    
    # 2. Overlay Detection
    try:
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset and overlay_offset < len(raw_data):
            findings["has_overlay"] = True
            if not findings["is_signed"]:
                findings["warnings"].append("Malicious overlay detected (Data appended outside PE structure without valid digital signature).")
    except Exception:
        pass
            
    # 3. TLS Callbacks
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS and hasattr(pe.DIRECTORY_ENTRY_TLS, 'struct'):
            if getattr(pe.DIRECTORY_ENTRY_TLS.struct, 'AddressOfCallBacks', 0):
                findings["tls_callbacks"] = True
                findings["warnings"].append("TLS Callbacks detected (Evasion technique: code executes prior to main EntryPoint).")
    except Exception:
        pass
            
    # 4. RWX Sections & Discrepancies
    try:
        for section in pe.sections:
            sec_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
            characteristics = section.Characteristics
            is_rwx = (characteristics & 0x20000000) and (characteristics & 0x80000000) and (characteristics & 0x40000000)
            
            if is_rwx:
                findings["warnings"].append(f"Section '{sec_name}' has RWX permissions (Read/Write/Execute - Typical of injection/unpacking).")
                
            virtual_size = getattr(section, 'Misc_VirtualSize', 0)
            raw_size = getattr(section, 'SizeOfRawData', 0)
            if virtual_size > 0 and raw_size > 0:
                if virtual_size / raw_size > 3.0:
                    findings["warnings"].append(f"Section '{sec_name}' disproportionate (VSize > 3x RSize). Strong indicator of packing.")
    except Exception:
        pass
                
    # 5. Metadata & Rich Header
    try:
        if hasattr(pe, 'FILE_HEADER') and hasattr(pe.FILE_HEADER, 'TimeDateStamp'):
            findings["metadata"]["compile_timestamp"] = pe.FILE_HEADER.TimeDateStamp
            # Timestamp spoofing check (before 1995 or in the future)
            if pe.FILE_HEADER.TimeDateStamp < 800000000 or pe.FILE_HEADER.TimeDateStamp > time.time() + 86400:
                findings["warnings"].append(f"Potentially spoofed compilation timestamp: {pe.FILE_HEADER.TimeDateStamp}")
    except Exception:
        pass
        
    try:
        rich_header = pe.parse_rich_header()
        if rich_header:
            findings["metadata"]["rich_header_hash"] = rich_header.get('checksum', 'N/A')
    except Exception:
        pass
    
    # PDB Path
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            for debug in pe.DIRECTORY_ENTRY_DEBUG:
                if hasattr(debug, 'entry') and hasattr(debug.entry, 'PdbFileName'):
                    pdb = debug.entry.PdbFileName.decode('utf-8', 'ignore').strip('\x00')
                    findings["metadata"]["pdb_path"] = pdb
                    if "users\\" in pdb.lower() or "desktop" in pdb.lower():
                        findings["warnings"].append(f"Suspicious developer PDB path leaked: {pdb}")
    except Exception:
        pass
                    
    # 6. APIs and Anti-Analysis/Sandbox Evasion
    try:
        imports = set()
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if hasattr(entry, 'imports'):
                    for imp in entry.imports:
                        if imp and imp.name:
                            imports.add(imp.name.decode('utf-8', 'ignore'))
                        
        # Anti-Analysis combos
        if {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}.issubset(imports):
            findings["api_combinations"].append("Process Hollowing / Remote Thread Injection")
        if {"IsDebuggerPresent"}.issubset(imports) or {"CheckRemoteDebuggerPresent"}.issubset(imports):
            findings["api_combinations"].append("Anti-Debug (Active debugger detection)")
        if {"GetTickCount", "Sleep"}.issubset(imports):
            findings["api_combinations"].append("Sandbox Evasion (Timing Checks / Long sleep)")
    except Exception:
        pass
        
    # 7. UPX Unpacker
    try:
        if any(b"UPX" in section.Name for section in pe.sections):
            findings["warnings"].append("UPX packer signature detected.")
            upx_path = shutil.which("upx")
            if upx_path:
                out_path = str(filepath) + ".unpacked"
                try:
                    subprocess.run([upx_path, "-d", str(filepath), "-o", out_path], capture_output=True, timeout=10)
                    if os.path.exists(out_path):
                        findings["warnings"].append(f"UPX successfully unpacked to: {out_path}. Re-analysis recommended!")
                except Exception:
                    pass
    except Exception:
        pass
            
    return findings
