"""
Database Layer: Encrypted SQLite Audit Ledger (vault_ledger.db).
Stores AES-256-CBC ciphertexts and Encrypt-then-MAC HMAC-SHA256 authentication tags
produced inside the native C enclave (`libvaultcrypto.dylib`).
"""

import json
import os
import sqlite3
import time
from typing import Any, Dict, List


class EncryptedLedger:
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
        with open(schema_path, "r", encoding="utf-8") as f:
            ddl = f.read()
        with self._connect() as conn:
            conn.executescript(ddl)
            conn.commit()

    def append_sealed_entry(
        self,
        action: str,
        target_token: str,
        quorum_nodes: List[str],
        iv_hex: str,
        ciphertext_hex: str,
        hmac_hex: str,
    ) -> int:
        now = time.time()
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO sealed_transactions
                (created_at, action, target_token, quorum_nodes, iv_hex, ciphertext_hex, hmac_hex)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    action,
                    target_token,
                    json.dumps(quorum_nodes),
                    iv_hex,
                    ciphertext_hex,
                    hmac_hex,
                ),
            )
            conn.commit()
            return int(cur.lastrowid)

    def list_entries(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, created_at, action, target_token, quorum_nodes, iv_hex, ciphertext_hex, hmac_hex
                FROM sealed_transactions
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [
            {
                "id": r["id"],
                "created_at": r["created_at"],
                "action": r["action"],
                "target_token": r["target_token"],
                "quorum_nodes": json.loads(r["quorum_nodes"]),
                "iv_hex": r["iv_hex"],
                "ciphertext_hex": r["ciphertext_hex"],
                "hmac_hex": r["hmac_hex"],
            }
            for r in rows
        ]

    def count_entries(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM sealed_transactions").fetchone()
            return int(row["cnt"]) if row else 0
