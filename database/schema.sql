-- VaultMind Encrypted Audit Ledger Schema (v4: hash-chained + canonical JSON AAD)
-- Each row's prev_hash = SHA-256 over the previous row (id, action, target_token,
-- iv_hex, ciphertext_hex, hmac_hex, prev_hash); row 1 links to a fixed genesis value.
-- The C enclave HMAC binds canonical JSON AAD = [id, prev_hash, action, target_token],
-- so deleting, duplicating, reordering, or delimiter-shifting rows breaks verification.
CREATE TABLE IF NOT EXISTS sealed_transactions (
    id INTEGER PRIMARY KEY,
    created_at REAL NOT NULL,
    action TEXT NOT NULL,
    target_token TEXT NOT NULL,
    quorum_nodes TEXT NOT NULL,
    iv_hex TEXT NOT NULL,
    ciphertext_hex TEXT NOT NULL,
    hmac_hex TEXT NOT NULL,
    prev_hash TEXT NOT NULL
);
