import sqlite3
import json
import os

class FormigaDB:
    def __init__(self, db_path="formiga_history.db"):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self.cursor.execute("""CREATE TABLE IF NOT EXISTS history (
            sha256 TEXT PRIMARY KEY,
            family TEXT,
            score INTEGER,
            is_vector BOOLEAN,
            report_json TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )""")
        self.conn.commit()

    def save_report(self, results):
        try:
            sha256 = results['file_info']['hashes']['sha256']
            family = results['threat_intel']['family_attribution']['family']
            score = results['threat_intel']['suspicion_score']
            is_vec = results['threat_intel']['is_suspected_vector']
            self.cursor.execute("REPLACE INTO history (sha256, family, score, is_vector, report_json) VALUES (?, ?, ?, ?, ?)", 
                (sha256, family, score, is_vec, json.dumps(results)))
            self.conn.commit()
        except Exception as e: 
            print(f"SQLite database error: {e}")
