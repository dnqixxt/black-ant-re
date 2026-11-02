import re
from pathlib import Path

class PurePythonYaraEngine:
    def __init__(self, rules_dir):
        self.rules_dir = Path(rules_dir)
        self.rules = []
        self._load_rules()

    def _load_rules(self):
        if not self.rules_dir.exists() or not self.rules_dir.is_dir(): return
        for yar_file in self.rules_dir.glob("*.yar*"):
            try:
                content = yar_file.read_text(encoding='utf-8', errors='ignore')
                rule_blocks = re.findall(r'rule\s+(\w+)\s*\{([^}]+)\}', content, re.DOTALL)
                for rule_name, body in rule_blocks:
                    meta_match = re.search(r'description\s*=\s*"([^"]+)"', body)
                    description = meta_match.group(1) if meta_match else "No description provided"
                    strings_block = re.search(r'strings\s*:(.*?)(?:condition\s*:|$)', body, re.DOTALL)
                    string_map = {}
                    if strings_block:
                        str_matches = re.findall(r'(\$\w+)\s*=\s*"([^"]+)"', strings_block.group(1))
                        for s_name, s_val in str_matches:
                            string_map[s_name] = s_val.encode('utf-8', errors='ignore')
                    cond_match = re.search(r'condition\s*:(.*)', body, re.DOTALL)
                    condition_str = cond_match.group(1).strip() if cond_match else "any of them"
                    self.rules.append({
                        "name": rule_name, "description": description, 
                        "strings": string_map, "condition": condition_str
                    })
            except Exception: pass

    def match(self, file_data):
        matched_rules = []
        for r in self.rules:
            found_strings = {s_name: (s_val.lower() in file_data.lower()) for s_name, s_val in r["strings"].items()}
            triggered = False
            cond = r["condition"]
            if "any of them" in cond:
                triggered = any(found_strings.values())
            elif "any of ($" in cond.lower():
                prefix_match = re.search(r'any of \(\$(\w+)\*\)', cond)
                if prefix_match:
                    prefix = prefix_match.group(1)
                    triggered = any(v for k, v in found_strings.items() if k.startswith(f"${prefix}"))
            if not triggered and r["strings"] and all(found_strings.values()):
                triggered = True
            if triggered:
                matched_rules.append({
                    "rule_name": r["name"], "description": r["description"],
                    "matched_strings": [k for k, v in found_strings.items() if v]
                })
        return matched_rules
