import os
import re

# ============================================================
# GENERAL CONFIGURATION & SAFETY THRESHOLDS
# ============================================================
# VirusTotal integration (optional: set VT_API_KEY in environment)
VT_API_KEY = os.environ.get("VT_API_KEY", "")

MAX_FILE_READ_BYTES = 200 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024
MAX_ZIP_MEMBER_UNCOMPRESSED = 50 * 1024 * 1024
MAX_ZIP_TOTAL_UNCOMPRESSED = 300 * 1024 * 1024
MAX_ZIP_MEMBERS = 2000
MAX_RECURSION_DEPTH = 8
MAX_ARCHIVES_TO_EXTRACT = 300
MAX_CUMULATIVE_EXTRACTED_BYTES = 800 * 1024 * 1024
DOWNLOAD_TIMEOUT = (5, 15)
ALLOWED_SCHEMES = {"http", "https"}
MAX_BASE64_SAMPLES = 5
MAX_MANIFEST_SNIPPET = 2000
JADX_TIMEOUT = 120
CAPA_TIMEOUT = 180
YARA_RULES_DIR = "rules"

SUSPICIOUS_CLASS_PATTERNS = [
    (rb'java/lang/Runtime', "java.lang.Runtime execution (potential command execution)"),
    (rb'ProcessBuilder', "ProcessBuilder invocation (potential command execution)"),
    (rb'java/net/URLClassLoader', "URLClassLoader (dynamic remote class loading)"),
    (rb'DexClassLoader', "DexClassLoader (dynamic bytecode loading)"),
    (rb'java/lang/reflect', "Reflection API usage (potential bypass/obfuscation)"),
    (rb'setAccessible', "setAccessible invocation (access control bypass)"),
    (rb'javax/crypto', "Payload cryptographic primitives (javax.crypto)"),
    (rb'java/util/Base64', "Base64 payload decoder (java.util.Base64)"),
    (rb'sun/misc/BASE64Decoder', "Legacy Base64 decoder (sun.misc.BASE64Decoder)"),
    (rb'java/net/Socket', "Raw TCP socket communication"),
    (rb'java/net/HttpURLConnection', "HttpURLConnection usage (C2 / Exfiltration)"),
    (rb'okhttp', "OkHttp HTTP client usage"),
    (rb'discord', "Discord token/webhook reference"),
    (rb'webhook', "Generic webhook endpoint reference"),
    (rb'\.minecraft', ".minecraft directory traversal / stealer targeting"),
    (rb'AppData', "AppData directory targeting"),
    (rb'Chrome', "Google Chrome user data targeting"),
    (rb'discordapp', "Discord API endpoint reference"),
    (rb'v8\.setFlagsFromString', "V8 engine flag manipulation (Bytenode Loader)"),
    (rb'Module\._extensions\[.*\]\s*=', "Node.js module extension hijacking"),
]

BASE64_BLOB_PATTERN = re.compile(rb'(?:[A-Za-z0-9+/]{4}){15,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

INSTALLER_MARKERS = [
    (rb'NullsoftInst', "NSIS (Nullsoft Scriptable Install System)"),
    (rb'\$PLUGINSDIR', "NSIS ($PLUGINSDIR reference)"),
    (rb'Inno Setup', "Inno Setup"),
    (rb'InstallShield', "InstallShield"),
    (rb'Windows Installer', "Windows Installer (MSI)"),
]

EMBEDDED_ARCHIVE_SIGNATURES = [
    (b'7z\xBC\xAF\x27\x1C', "7-Zip Archive (.7z)"),
    (b'PK\x03\x04', "ZIP / JAR / Office Archive (.zip)"),
    (b'Rar!\x1A\x07', "RAR Archive (.rar)"),
    (b'MSCF', "Microsoft Cabinet Archive (.cab)"),
]

ARCHIVE_EXTENSIONS = {'.7z', '.zip', '.jar', '.rar', '.cab', '.apk'}
COMMON_KNOWN_EXTENSIONS = {
    '.txt', '.md', '.py', '.java', '.class', '.png', '.jpg', '.jpeg', '.gif',
    '.ico', '.ttf', '.otf', '.woff', '.woff2', '.dll', '.exe', '.json', '.js',
    '.html', '.htm', '.css', '.map', '.node', '.pdb', '.xml', '.yml', '.yaml',
    '.svg', '.wasm', '.bmp', '.webp', '.mp3', '.mp4', '.wav', '.zip', '.7z',
    '.rar', '.cab', '.dat.lock',
}

INT_ARRAY_PATTERN = re.compile(r'(?:private|public|protected)?\s*static\s*final\s+int\[\]\s+(\w+)\s*=\s*\{([^}]+)\}')

MAX_XOR_KEY = 256
MAX_XOR_STEP = 64
MIN_PRINTABLE_RATIO = 0.85
DECODE_KEYWORDS = [b'http', b'https', b'.exe', b'.dll', b'.bat', b'cmd', b'powershell',
                   b'appdata', b'temp', b'tmp', b'discord', b'webhook', b'/c', b'-c']

TIMESTOMPING_PATTERN = re.compile(r'setLastModifiedTime\s*\([^;]*currentTimeMillis\(\)\s*-', re.DOTALL)
EMPTY_CATCH_PATTERN = re.compile(r'catch\s*\([^)]*\)\s*\{\s*\}')
SUPPRESSED_OUTPUT_PATTERN = re.compile(r'Redirect\.DISCARD|redirectOutput\s*\([^)]*DISCARD')
XOR_DECODER_METHOD_PATTERN = re.compile(r'private\s+static\s+\w+\s+\w+\s*\([^)]*\)\s*\{[^}]*\^[^}]*\}', re.DOTALL)
SUSPICIOUS_ENTRYPOINT_NAMES = {
    "java", "system", "runtime", "update", "updater", "loader", "core",
    "utils", "util", "helper", "main", "client", "service", "manager", "init"
}
