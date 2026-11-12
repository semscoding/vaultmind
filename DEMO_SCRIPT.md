# VaultMind v2: 2.5-Minute Hackathon Demo Video Script

> **Target Length:** 2:15 – 2:45  
> **Track:** AI Pipeline Secret Sharing Track  

---

### 1. Intro & Low-Level Architecture (0:00 – 0:35)
- **On Screen:** Show `http://127.0.0.1:8000` top telemetry bar (`0 BYTES IN PYTHON RAM`, `libvaultcrypto.dylib ACTIVE`, `2048-bit Feldman VSS`, `1024-bit Paillier`).
- **Say:**
  > *"Hi, this is VaultMind v2 for the AI Pipeline Secret Sharing track. Standard AI agents leak PII and financial figures to cloud host logs, and keep master API keys in Python memory where prompt injection or heap scraping can steal them.*  
  > *VaultMind combines high-level Python orchestration with a compiled native C cryptographic enclave (`libvaultcrypto.dylib`). Sensitive inputs are blinded locally with HMAC-SHA256 and 1024-bit fixed-point Paillier homomorphic encryption, while the 256-bit Master Key is split across 5 isolated disk shards using constant-time $\text{GF}(2^8)$ Shamir Secret Sharing and 2048-bit Feldman Verifiable Secret Sharing."*

---

### 2. Blind FHE Bonus Calculation & Zero-Leak Wire (0:35 – 1:25)
- **On Screen:**
  1. Click **"💼 15% Bonus FHE Calculation & DB Seal"** and click **"Execute Zero-Trust Pipeline"**.
  2. Point to **Column 2 (External Cloud Wire)**:
     > *"Notice what goes across the wire: Marcus Vance is blinded to an HMAC token, and both his \$130,000 salary and 4.9 rating are encrypted as 1024-bit Paillier ciphertexts. Zero plaintext PII or keys leave the machine."*
  3. Point to the **Cyan FHE Banner & Column 1**:
     > *"Even without decrypting the salary, the pipeline evaluates $c_{\text{bonus}} = c_1^{15} \bmod n^2$ and $c_{\text{total}} = c_1^{115} \bmod n^2$ directly on the ciphertexts — decrypting locally to an exact \$19,500.00 bonus and \$149,500.00 total!"*
  4. Click **"💳 Executive IBAN Wire Transfer Auth"** and run it:
     > *"It works equally on European IBANs, medical BSNs, and enterprise transfers — sealing every authorized transaction into an AES-256 + HMAC-SHA256 SQLite ledger strictly on the C stack, followed by C11 `memset_s()` zeroization."*

---

### 3. Live Byzantine Shard Attack & Feldman VSS Defense (1:25 – 2:10)
- **On Screen:**
  1. In **Column 3**, click **"⚡ Corrupt"** on `node-02`.
  2. Point to the red `TAMPERED` badge and the red cross jumping off the $\text{GF}(2^8)$ polynomial curve in the live chart!
  3. Click **"Execute Zero-Trust Pipeline"** again.
  4. Point to the Enclave Receipt & Bottom SQLite Ledger:
     > *"Watch what happens when an attacker corrupts shard 2 on disk: our 2048-bit RFC 3526 Feldman VSS check $g^{s_i} \equiv \prod C_j^{i^j} \bmod P$ immediately flags `node-02` as tampered, visually ejects it from the polynomial curve, and automatically fails over to quorum nodes 1, 3, and 4! If we corrupt 3 nodes so fewer than $k=3$ valid shards remain, the C enclave mathematically blocks execution."*
  5. Click **"↺ Restore Shards"** and **"✔ Verify HMACs in C Enclave"** on the SQLite table.

---

### 4. Terminal TUI & Closing (2:10 – 2:30)
- **On Screen:** Show `python3 -m unittest tests/test_security_audit.py -v` passing all 6 cryptographic audit tests + `python3 tui.py`.
- **Say:**
  > *"Every cryptographic claim — from $\text{GF}(2^8)$ field axioms and `memset_s()` wiping to SQLite ciphertext bit-flip detection — is backed by our automated audit suite and available in both our loopback web dashboard and Rich TUI. Thanks for watching!"*
