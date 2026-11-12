-- VaultMind Encrypted Audit Ledger Schema
CREATE TABLE IF NOT EXISTS sealed_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    action TEXT NOT NULL,
    target_token TEXT NOT NULL,
    quorum_nodes TEXT NOT NULL,
    iv_hex TEXT NOT NULL,
    ciphertext_hex TEXT NOT NULL,
    hmac_hex TEXT NOT NULL
);
