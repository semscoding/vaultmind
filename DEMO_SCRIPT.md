# VaultMind v2: 2.5-Minute Hackathon Demo Video Script

> **Target Length:** 2:15 – 2:45  
> **Track:** AI Pipeline Secret Sharing Track  
> **Pre-Recording Checklist:** Put a live `GEMINI_API_KEY` (free at `aistudio.google.com`) or `OPENAI_API_KEY` / `AWS_BEARER_TOKEN_BEDROCK` in `.env` before starting `python3 main.py`. The dashboard automatically detects `.env` and selects the live cloud provider without exposing your key on screen!

---

### 1. Intro & Low-Level Architecture (0:00 – 0:35)
- **On Screen:** Open `http://127.0.0.1:8000`. Point to the top header (`✨ Google Gemini 2.5 Flash (Live API)` auto-loaded from `.env`) and telemetry bar (`0 BYTES IN PYTHON RAM`, `libvaultcrypto.dylib ACTIVE`, `2048-bit Feldman VSS`, `Paillier 1024-bit PHE + C RLWE-BFV FHE`).
- **Say:**
  > *"Hi, this is VaultMind v2 for the AI Pipeline Secret Sharing track. Connecting cloud LLMs like Google Gemini, OpenAI, or AWS Bedrock to enterprise workflows normally leaks PII, passwords, and financial figures to host-provider servers, while exposing master keys in agent memory.*  
  > *VaultMind pairs Python orchestration with a compiled C11 cryptographic enclave (`libvaultcrypto.dylib`). Before any prompt leaves localhost, sensitive identifiers and arbitrary secrets are blinded and AES-256-sealed locally, numbers are encrypted under both 1024-bit Paillier PHE and Ring-LWE BFV Lattice FHE, and our 256-bit Master Key stays split across 5 isolated disk shards using constant-time $\text{GF}(2^8)$ Shamir Secret Sharing and 2048-bit Feldman VSS."*

---

### 2. Live Cloud Blind Reasoning, Paillier PHE & Lattice RLWE-BFV FHE (0:35 – 1:30)
- **On Screen:**
  1. Click **"💼 15% Bonus Paillier PHE & DB Seal"** → click **"Execute Zero-Trust Pipeline"**.
  2. Point to **Column 2 (External Cloud Wire)** & **Cyan Banner**:
     > *"Here Gemini 2.5 Flash reasons live over blinded tokens: Marcus Vance is an HMAC token, and his \$130,000 salary is a 1024-bit Paillier ciphertext. Without ever decrypting the salary, our evaluator computes $c_1^{15} \bmod n^2$ and $c_1^{115} \bmod n^2$ — decrypting locally to an exact \$19,500.00 bonus and \$149,500.00 total!"*
  3. Click **"🔐 Lattice RLWE-BFV Product & Password Seal"** → click **"Execute Zero-Trust Pipeline"**:
     > *"And for non-linear ciphertext-times-ciphertext math plus free-text passwords: both `password is ...` and `<secret>...</secret>` are scrubbed and sealed in C AES-256, while our compiled C Ring-LWE BFV engine over $R_q = \mathbb{Z}_{2^{60}}[X]/(X^{64}+1)$ multiplies encrypted hours $E(160)$ by encrypted rate $E(225)$ with 4-limb gadget relinearization — yielding \$36,000 with zero plaintext exposure!"*

---

### 3. Live Byzantine Shard Attack & 2048-bit Feldman VSS Defense (1:30 – 2:10)
- **On Screen:**
  1. In **Column 3**, click **"⚡ Corrupt"** on `node-02`. Show the red `TAMPERED` state and the red cross jumping off the $\text{GF}(2^8)$ polynomial curve.
  2. Click **"Execute Zero-Trust Pipeline"** again.
  3. Point to the Enclave Receipt & Bottom SQLite Ledger:
     > *"When an attacker corrupts shard 2 on disk, our 2048-bit RFC 3526 Feldman VSS check $g^{s_i} \equiv \prod C_j^{i^j} \bmod P$ mathematically rejects `node-02`, ejects it from the curve, and automatically fails over to healthy quorum nodes 1, 3, and 4 — reconstructing the Master Key strictly on the C stack and wiping it with C11 `memset_s()`. Corrupting 3 shards drops below $k=3$ and halts execution."*
  4. Click **"↺ Restore Shards"** and **"✔ Verify HMACs in C Enclave"**.

---

### 4. Audit Suite, Terminal TUI & Closing (2:10 – 2:35)
- **On Screen:** Switch to terminal: show `python3 -m unittest tests/test_security_audit.py -v` passing all 9 cryptographic audit tests + `python3 frontend/tui.py`.
- **Say:**
  > *"Every mathematical guarantee — from constant-time $\text{GF}(2^8)$ axioms and 100 random RLWE-BFV ciphertext multiplications to SQLite HMAC tamper detection — is verified by our 9-part audit suite and accessible via both our loopback web UI and Rich TUI. Thanks for watching!"*
