import re

# Regex matching Android byte-array repeating XOR patterns in JADX decompiled code:
# e.g., mb0.a(new byte[]{-9, -84, 102}, new byte[]{-124, -99, 21})
BYTE_ARRAY_XOR_PATTERN = re.compile(
    r'[a-zA-Z0-9_$]+(?:\.[a-zA-Z0-9_$]+)*\s*\(\s*new\s+byte\s*\[\s*\]\s*\{([^}]+)\}\s*,\s*new\s+byte\s*\[\s*\]\s*\{([^}]+)\}\s*\)',
    re.DOTALL
)

def decrypt_java_byte_array_xor(data_integers, key_integers):
    """
    Decrypts repeating-key XOR strings where bytes are represented as signed Java integers (-128 to 127).
    Converts each signed byte to unsigned via (b & 0xFF) and performs repeating-key XOR.
    """
    if not data_integers or not key_integers:
        return ""

    key_len = len(key_integers)
    decrypted_bytes = bytearray(len(data_integers))

    for i, d in enumerate(data_integers):
        k = key_integers[i % key_len]
        decrypted_bytes[i] = (d & 0xFF) ^ (k & 0xFF)

    return decrypted_bytes.decode('utf-8', errors='ignore')

def escape_java_string(s: str) -> str:
    """
    Escapes a raw decrypted string so it can be safely embedded as a valid Java string literal enclosed in "...".
    Handles backslashes, double quotes, standard escapes (\n, \r, \t), and non-printable control characters.
    """
    if not s:
        return ""

    escaped = []
    for ch in s:
        if ch == '\\':
            escaped.append('\\\\')
        elif ch == '"':
            escaped.append('\\"')
        elif ch == '\n':
            escaped.append('\\n')
        elif ch == '\r':
            escaped.append('\\r')
        elif ch == '\t':
            escaped.append('\\t')
        elif ord(ch) < 32 or ord(ch) == 127:
            escaped.append(f'\\u{ord(ch):04x}')
        else:
            escaped.append(ch)
    return ''.join(escaped)

def patch_apk_byte_array_xor_code(java_source_code: str):
    """
    Parses Java source code for byte array repeating XOR invocations, replaces each invocation inline
    with its decrypted, properly escaped Java string literal (e.g. "decrypted_string"), and collects
    metadata on all decrypted strings.

    Returns:
        (patched_source, replacement_count, extracted_items)
    """
    if not java_source_code:
        return "", 0, []

    extracted_items = []
    replacement_count = 0

    def repl_func(match):
        nonlocal replacement_count
        data_raw, key_raw = match.groups()
        try:
            data_ints = [int(x) for x in re.findall(r'-?\d+', data_raw)]
            key_ints = [int(x) for x in re.findall(r'-?\d+', key_raw)]

            if not data_ints or not key_ints:
                return match.group(0)

            decrypted_str = decrypt_java_byte_array_xor(data_ints, key_ints)
            extracted_items.append({
                "call_snippet": match.group(0)[:80].replace('\n', ' ').strip(),
                "data_length": len(data_ints),
                "key_length": len(key_ints),
                "decoded_value": decrypted_str
            })
            replacement_count += 1
            escaped_val = escape_java_string(decrypted_str)
            return f'"{escaped_val}"'
        except Exception:
            return match.group(0)

    patched_code = BYTE_ARRAY_XOR_PATTERN.sub(repl_func, java_source_code)
    return patched_code, replacement_count, extracted_items

def extract_apk_byte_array_xor_strings(java_source_code):
    """
    Parses decompiled Java source code for byte array repeating XOR invocations,
    extracts the signed integer arrays, and returns decrypted strings.
    """
    _, _, items = patch_apk_byte_array_xor_code(java_source_code)
    return items
