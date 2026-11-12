# VaultMind v2 — Agent Handover & Hackathon Victory Audit Brief

> **Project Root:** `/Users/sem/.gemini/antigravity/scratch/vaultmind`  
> **Private GitHub Repo:** `https://github.com/semscoding/vaultmind` (`main` branch, **PRIVATE**)  
> **Hackathon:** *Mathematics for Systems Security*  
> **Selected Track:** **AI Pipeline Secret Sharing Track** (Participants may enter ONE track only)

---

## 1. Exact Hackathon Challenge & Scoring Rules

### Challenge Summary
> *"Create a cryptographic algorithm that validates secret sharing or create an AI agent that is private where inputs are encrypted, preventing APIs from reading master keys."*

### Track Rules — AI Pipeline Secret Sharing Track (Our Track)
1. **Cloud Host LLM APIs:** Use APIs that grant access to LLMs such as **AWS Bedrock**, **OpenAI**, or **Google Gemini** provided by host providers, and guarantee secure communication with the agent by encrypting/blinding inputs to the agent while keeping the **Master Key completely unknown** to the agent to prevent storing potentially compromised data on the host provider's server.
2. **Low-Level Execution Bonus (+1 Extra Point):**
   - *"PLEASE NOTE THAT TO GAIN AN EXTRA POINT UTILIZE LOW LEVEL LANGUAGES (E.G RUST OR C) TO MINIMIZE PERFORMANCE OVERHEAD AND VULNERABILITY WINDOW. Participants in the AI pipeline track may use high level languages such as Python while maintaining low level execution of mathematical encryption."*
3. **Allowed & Optional Primitives:**
   - Pre-existing cryptographic algorithms and secret sharing mechanisms such as **SSS (Shamir's Secret Sharing)** ARE explicitly allowed in this track.
   - **FHE (Fully Homomorphic Encryption)** is optional/bonus (*"Optional but not enforced, the participant may use FHE"*).
4. **Visual Aesthetic Point:**
   - *"To gain a strong point on visual aesthetic, include a website hosted on the loopback machine (`127.0.0.1`) or include a TUI (Terminal User Interface) to interact with the agent."* (VaultMind includes **both**!)
5. **Submission Deliverables:**
   - Clean LaTeX mathematical explanations + vulnerability windows mitigated (`README.md`).
   - Video demonstration of the agent being fed encrypted inputs and how inputs/keys remain protected (`DEMO_SCRIPT.md`, YouTube upload heavily recommended).

---

## 2. Repository Structure & File Index (6-Layer Architecture)

```text
/Users/sem/.gemini/antigravity/scratch/vaultmind/
├── main.py                          # FastAPI loopback server entrypoint (127.0.0.1:8000)
├── .env.example                     # Template for GEMINI_API_KEY / OPENAI_API_KEY / AWS_BEARER_TOKEN_BEDROCK
├── requirements.txt                 # Python dependencies (venv at ./venv)
├── README.md                        # Submission docs with full KaTeX/LaTeX derivations & threat table
├── DEMO_SCRIPT.md                   # 2.5-minute YouTube hackathon walkthrough script
├── HANDOVER.md                      # This handover & Victory Audit specification
├── frontend/
│   ├── tui.py                       # Rich Terminal User Interface (`python3 frontend/tui.py`)
│   └── static/
│       ├── index.html               # 3-column Zero-Trust Web UI + Dual PHE/FHE Playground + SQLite Ledger
│       ├── style.css                # Cyberpunk/Enterprise dark glassmorphic styling
│       └── app.js                   # XSS-safe (`escapeHtml` + `textContent`) controller + Chart.js GF(2^8) curve
├── backend/
│   ├── native/
│   │   ├── build.py                 # Compiles `vaultcrypto.c` -> `libvaultcrypto.dylib` (`clang -O2 -Wall -Wextra -Werror`)
│   │   └── vaultcrypto.c            # C11 Enclave Core: constant-time GF(2^8), AES-256-CBC+HMAC, memset_s, N=2048 RLWE-BFV FHE
│   └── crypto/
│       ├── zeroize.py               # ctypes bindings for `vault_secure_wipe` + `NativeBufferGuard`
│       ├── shamir.py                # Dual-field Shamir (C GF(2^8) + 2048-bit RFC 3526 Feldman VSS over Z_q)
│       ├── homomorphic.py           # 1024-bit Fixed-Point Paillier Additive Homomorphic Encryption (PHE)
│       ├── bfv_fhe.py               # 128-bit Lattice Security RLWE-BFV FHE (N=2048, q=2^54) + C `SessionSecretVault`
│       └── blind_tokenizer.py       # Single-pass span blinder (PII, Dutch/intl names, IBAN, BSN, passwords, <secret>, FHE)
├── database/
│   ├── schema.sql                   # `sealed_transactions` SQLite DDL
│   ├── ledger.py                    # Encrypted SQLite persistence (`EncryptedLedger`)
│   └── runtime/                     # Git-ignored runtime dir (`shards/node_01..05.json`, `manifest.json`, `vault_ledger.db`)
├── apis/
│   ├── llm_client.py                # Live Gemini 2.5 Flash, OpenAI GPT-4o-mini, AWS Bedrock Converse + Offline ZK Engine + `.env` loader
│   └── routes.py                    # REST endpoints (`/api/process`, `/api/llm-config`, `/api/bfv-fhe-calc`, `/api/homomorphic-calc`, etc.)
├── services/
│   ├── enclave_service.py           # `SecureEnclave`: 0600 disk shard verification, quorum failover & C-stack SQLite sealing
│   └── pipeline_service.py          # `AgentPipeline`: end-to-end 4-phase Zero-Knowledge orchestration
├── monitoring/
│   └── telemetry.py                 # `SecurityMonitor`: real-time latency, blinding, FHE & tamper counters
└── tests/
    └── test_security_audit.py       # 10-part cryptographic, integration & red-team regression test suite
```

---

## 3. Core Cryptographic Architecture & Decisions Made

1. **Zero Master Key Bytes in Python Heap (`vaultcrypto.c` + `shamir.py` + `enclave_service.py`):**
   - `SecureEnclave` stores **zero shares** in `self.__dict__`; shares live on disk in `0600`-permissioned JSON files (`database/runtime/shards/node_01..05.json`).
   - Reconstructing the 256-bit Master Key requires **both** $k=3$ of $n=5$ $\mathbb{F}_{2^8}$ shares (interpolated in constant time on the C stack) **and** $k=3$ of $n=5$ RFC 3526 Group 14 (2048-bit safe prime $P = 2q + 1$) Feldman-verified $\mathbb{Z}_q$ shares:
     $$K_{\text{master}} = \operatorname{HMAC-SHA256}\!\left(K_{\mathbb{F}_{2^8}},\; \operatorname{SHA256}(\alpha_0)\right)$$
   - `K_master` exists strictly inside `uint8_t combined_master[32]` in C (`derive_subkeys`), seals/verifies AES-256-CBC + Encrypt-then-MAC HMAC-SHA256 records via Apple `CommonCrypto`, and is immediately wiped via C11 `memset_s()` + volatile compiler memory fence.
2. **Dual Homomorphic Encryption (`homomorphic.py` + `bfv_fhe.py` + `vaultcrypto.c`):**
   - **1024-bit Paillier PHE ($\mathbb{Z}_{n^2}^*$):** Exact fixed-point ($\times 100$) homomorphic sums and public percentage bonuses ($c^p \bmod n^2$) evaluated using ONLY public modulus $n$.
   - **128-bit Lattice Security Ring-LWE BFV FHE ($R_q = \mathbb{Z}_{2^{54}}[X]/(X^{2048}+1), t = 65536$):** Exact HomomorphicEncryption.org Table 1 standard parameterization in compiled C11 (`__int128` negacyclic convolutions, unbiased rejection-sampled ternary secrets/errors, 4-limb base-$2^{14}$ gadget decomposition relinearization). Uses base-$256$ limb schoolbook multiplication (`multiply_limbs`) so arbitrary 32-bit unsigned products (e.g., $300 \times 300 = 90{,}000$) never suffer $\bmod 65536$ wraparound.
3. **Zero-Retention Arbitrary Secret Sealing (`blind_tokenizer.py` + `SessionSecretVault`):**
   - Scrubs `<secret>...</secret>` tags, free-text passwords/PINs (`password is ...`, `secret key is ...`, `api_key=...`), Bearer/JWT tokens, and raw 128/256-bit hex keys.
   - Seals secrets immediately into C AES-256-CBC + HMAC-SHA256 (`vault_session_seal`), never storing raw secrets in `plaintext_to_token` or `token_to_plaintext`, and redacting them in `audit_trail` / `original_prompt`.

---

## 4. Documented Trade-Offs & Intentional Constraints (Context for Auditor)

- **macOS Native Crypto Headers:** `vaultcrypto.c` uses `<CommonCrypto/CommonCryptor.h>`, `<CommonCrypto/CommonHMAC.h>`, and `arc4random_buf` (native on macOS, where this loopback demo runs; Linux portability would swap in OpenSSL `EVP` + `getrandom`).
- **Demo Shard Restore Folder (`.demo_clean_shards`):** `enclave_service.py` creates a local `.demo_clean_shards` backup directory solely so the interactive UI button `"↺ Restore Shards"` can reset corrupted shards during a live hackathon recording.
- **Unbootstrapped Depth-1 Leveled BFV:** Ring-LWE BFV ($N=2048, q=2^{54}, t=65536$) supports exact depth-1 ciphertext $\times$ ciphertext multiplication + unlimited additions (sufficient for all base-$256$ 32-bit multi-limb products without bootstrapping overhead).

---

## 5. Quick Verification Commands

```bash
cd /Users/sem/.gemini/antigravity/scratch/vaultmind

# 1. Compile C11 Enclave & Lattice FHE Core
./venv/bin/python3 backend/native/build.py

# 2. Run 10-Part Security & Red-Team Audit Suite
./venv/bin/python3 -m unittest tests/test_security_audit.py -v

# 3. Smoke-Test Rich TUI
printf "\nexit\n" | ./venv/bin/python3 frontend/tui.py

# 4. Launch Loopback Web Dashboard (http://127.0.0.1:8000)
./venv/bin/python3 main.py
```
