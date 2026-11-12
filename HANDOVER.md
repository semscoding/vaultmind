# VaultMind v2: Agent Handover & Audit Brief

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
├── main.py                          # FastAPI loopback server (127.0.0.1:8000), TrustedHostMiddleware, reload=False
├── .env.example                     # GEMINI_API_KEY / OPENAI_API_KEY / AWS_BEARER_TOKEN_BEDROCK (+ AWS_REGION, AWS_BEDROCK_MODEL_ID)
├── requirements.txt                 # fastapi, uvicorn, httpx, pydantic, rich, sympy (venv at ./venv)
├── README.md                        # Submission docs: threat model, LaTeX derivations, claim → verification table, known limitations
├── DEMO_SCRIPT.md                   # Video script matching the real UI labels
├── HANDOVER.md                      # This file
├── frontend/
│   ├── tui.py                       # Rich TUI (`python3 frontend/tui.py`; /corrupt <n>, /restore, /verify, /metrics, exit)
│   └── static/
│       ├── index.html               # 3-column UI + Paillier/BFV playground + ledger table; no external scripts or fonts
│       ├── style.css
│       ├── app.js                   # textContent/escapeHtml rendering; shows the real wire request and the computed leak check
│       └── vendor/chart.umd.min.js  # Chart.js 4.4.9, vendored (licence file next to it)
├── backend/
│   ├── native/
│   │   ├── build.py                 # clang -O2 -Wall -Wextra -Werror -fPIC -shared → libvaultcrypto.dylib (also auto-built on first import)
│   │   └── vaultcrypto.c            # C11 core: GF(2^8) Shamir, key generation, enclave seal/unseal, session vault, RLWE-BFV
│   └── crypto/
│       ├── zeroize.py               # ctypes loader, `vault_secure_wipe`, `NativeBufferGuard`
│       ├── shamir.py                # `ShamirSecretSharing` (C bindings) + `FeldmanVSS` over RFC 3526 Group 14
│       ├── homomorphic.py           # `PaillierKeypair` (2048-bit default, Decimal fixed point) + `HomomorphicEvaluator`
│       ├── bfv_fhe.py               # `BFVContext`, `BFVEvaluator` (holds only rlk), `SessionSecretVault`
│       └── blind_tokenizer.py       # Span blinder, overlap merge, per-prompt token key, residual leak scan
├── database/
│   ├── schema.sql                   # `sealed_transactions` (hash-chained)
│   ├── ledger.py                    # `EncryptedLedger`: append with chain position, row_hash, migration of pre-chain tables
│   └── runtime/                     # git-ignored: shards/node_01..05.json, .demo_clean_shards/, manifest.json, vault_ledger.db
├── apis/
│   ├── llm_client.py                # Gemini / OpenAI / Bedrock adapters, offline engine, `LLMProviderError`, tolerant JSON parser
│   └── routes.py                    # /api/process, /api/llm-config, /api/vault-status, /api/tamper-node, /api/restore-nodes,
│                                    # /api/ledger, /api/homomorphic-calc, /api/bfv-fhe-calc, /api/monitoring/{metrics,health}
├── services/
│   ├── enclave_service.py           # `SecureEnclave`: shard inspection, quorum failover, chained sealing, full-chain verification
│   └── pipeline_service.py          # `AgentPipeline`: blinding → LLM → evaluation → enclave, leak flags, llm_output_warnings
├── monitoring/
│   └── telemetry.py                 # `SecurityMonitor`
└── tests/
    ├── test_security_audit.py       # 10 original tests (test_01 … test_10)
    └── test_audit_regressions.py    # 21 regression tests for the Victory Audit findings (temp dirs, mocked HTTP)
```

---

## 3. Core Cryptographic Architecture & Decisions Made

1. **Key generation and reconstruction (`vaultcrypto.c` + `shamir.py` + `enclave_service.py`):**
   - The 256-bit GF(2^8) key is generated in C with `arc4random_buf` and split and wiped in C (`vault_generate_and_split_key`). Shamir coefficients are uniform, including a zero leading coefficient; `total_n` up to 255 works.
   - The Feldman secret $\alpha_0$ and its polynomial are generated in Python (`secrets`), over $\mathbb{Z}_q$ of RFC 3526 Group 14 ($P = 2q+1$, $g = 4$).
   - Seal/unseal: Python reads $k$ shard files, re-interpolates $\alpha_0$, and passes the GF shares plus $\operatorname{SHA256}(\alpha_0)$ to C. In C: $K_{\text{master}} = \operatorname{HMAC\text{-}SHA256}(K_{\mathbb{F}}, \operatorname{SHA256}(\alpha_0))$, subkeys via HMAC with fixed labels, commitment check (rc −10), AES-256-CBC + HMAC-SHA256 over `len64be(aad) || aad || iv || ct`, then `vault_secure_wipe` on every path.
   - `vault_secure_wipe` calls `memset_s` on macOS (`#if defined(__STDC_LIB_EXT1__) || defined(__APPLE__)`), volatile loop elsewhere; `nm -u libvaultcrypto.dylib` shows `_memset_s`.
   - `SecureEnclave` keeps no shares in `self.__dict__`; shards are 0600 JSON files. Malformed files (empty, truncated, JSON list, non-numeric fields) become `TAMPER_REJECTED`. If the commitment check fails, every other k-subset of the Feldman-valid shards is tried.
   - Precisely stated: shares and $\alpha_0$ pass through Python; only the reconstructed key and the subkeys are C-stack-only.
2. **Ledger (`ledger.py`, `schema.sql`):** columns `id, created_at, action, target_token, quorum_nodes, iv_hex, ciphertext_hex, hmac_hex, prev_hash`. `prev_hash` = SHA-256 over the previous row (`id, action, target_token, iv_hex, ciphertext_hex, hmac_hex, prev_hash`), genesis = 64 zeros; AAD = `"{id}:{prev_hash}:{action}:{target_token}"`. `verify_ledger_entries` checks the whole chain and returns `verification_reason` per displayed row plus `chain_errors` and `chain_head_hash`. Not detected: truncation of the newest rows (only against an externally stored `chain_head_hash`); `created_at` and `quorum_nodes` are not authenticated.
3. **Homomorphic layer (`homomorphic.py`, `bfv_fhe.py`, `vaultcrypto.c`):**
   - Paillier, 2048-bit modulus by default (`AgentPipeline(paillier_bits=2048)`; tests pass 1024 for speed). Fixed point via `Decimal`; percentages may be non-integer (up to 4 decimals, 0 to 1000); scalars are integers with |scalar| ≤ 10^6.
   - RLWE-BFV, leveled, multiplicative depth 1: N = 2048, q = 2^54, t = 65536, Δ = 2^38, gadget base 2^14 with 4 limbs, uniform ternary secret and errors. N and log q match the classical 128-bit row of the HE standard, but the errors are ternary (σ ≈ 0.82, not 3.2), so 128 bit is an approximation. BFV functions return int status codes (`VAULT_BFV_ENOMEM`); the multiplication is `vault_bfv_mul_relin` and wipes its workspace before `free`. The `ai == 0` skip in `bfv_poly_mul_exact` is not constant-time.
   - 32-bit products: up to 16 base-256 limb products, each a depth-1 homomorphic product, decrypted separately and recombined in plaintext.
   - Evaluators: `HomomorphicEvaluator` (holds n) and `BFVEvaluator` (holds rlk) run locally in the same process as the secret keys. The cloud LLM only chooses the operation.
4. **Blinding and secrets (`blind_tokenizer.py`, `SessionSecretVault`):**
   - Fresh 32-byte HMAC key per `blind_prompt()` call; tokens `[ID_…]`, `[IBAN_…]`, `[GOV_ID_…]`, `[EMAIL_…]`, `[LOC_…]`, `[PHONE_…]`, `[SECRET_…]`, `[FHE_NUM_n]`. Unicode names, Mc/Mac, Dutch labels (`wachtwoord`, `pincode`, `geheim`), `password … is X` with up to four words between, case-insensitive IBAN, alphanumeric IDs, phone numbers, Dutch postcodes, PEM/AWS/Slack keys. Overlapping spans are merged; an unclosed `<secret>` runs to the end of the prompt.
   - SECRET spans are sealed in C (AES-256-CBC + HMAC, session key from `vault_random_bytes`), never stored in `plaintext_to_token` / `token_to_plaintext` or logs.
   - Residual scan after blinding: `contains_raw_pii`, `contains_raw_secrets` and `leak_check` are computed per request.
   - Remaining gaps (by design, documented): lower-case names, lone first names without a role word, bare integers below 10, percentages, street/city without a label, unlabelled secrets without a pattern.
5. **LLM layer (`llm_client.py`, `routes.py`):** every result carries `wire_request` (method, URL, redacted headers, exact body). All provider failures raise `LLMProviderError` → HTTP 502 with `wire_request`; other errors → 400 / 500 without echoing plaintext. The parser accepts ```` ```json ````, ```` ```JSON ````, bare fences and a trailing bare object, and returns `parse_warning` instead of silently dropping JSON. Non-object `fhe_compute` / `action_intent` are ignored and reported in `llm_output_warnings`. Default Bedrock model: `amazon.nova-lite-v1:0` (override with `AWS_BEDROCK_MODEL_ID`).

---

## 4. Documented Trade-Offs & Intentional Constraints

- **macOS only:** CommonCrypto and `arc4random_buf`. Linux would need OpenSSL EVP + `getrandom`.
- **Demo shard restore folder (`.demo_clean_shards`):** full copies of all five shards, only to power **↺ Restore Shards**. Together with the shards on the same disk this means a disk reader has the key; see the README threat model.
- **Depth-1 leveled BFV, no bootstrapping.**
- **Live cloud path not yet exercised with real keys;** failures are only tested with mocked HTTP.

---

## 5. Quick Verification Commands

```bash
cd /Users/sem/.gemini/antigravity/scratch/vaultmind

# 1. (Re)compile the C core (also happens automatically when the .dylib is missing)
./venv/bin/python3 backend/native/build.py
nm -u backend/native/libvaultcrypto.dylib | grep memset_s

# 2. Full test suite: 36 tests
./venv/bin/python3 -m unittest discover -s tests -v

# 3. Smoke-test the TUI
printf "/verify\nexit\n" | ./venv/bin/python3 frontend/tui.py

# 4. Dashboard (http://127.0.0.1:8000)
./venv/bin/python3 main.py
```

---

## 6. Audit round 3 (Claude, 12 Nov 2026)

Follow-up to the Victory Audit (vault: `Victory Audit (Claude — 12-11-2026).md`). Four agents changed the code; this round aligned the docs with the code, added regression tests and closed three small seams.

**Resolved (verified in code and/or tests)**
- B1 leak flags computed (`residual_scan`), many regex gaps closed, UI shows the leak check. B2 `memset_s` linked. B3 `DEMO_SCRIPT.md` rewritten. B4 middle panel shows the real request (`actual_request` / `wire_request`).
- M1 AAD length field. M2 malformed shard files → failover. M3 provider errors → 502, tolerant parser, type checks. M4 key generated in C, wording made precise. M5 uniform Shamir coefficients. M6/M7 "PQ" and "FHE" claims removed, depth 1 and local evaluation stated. M8 Paillier 2048-bit default. M9 quickstart without local paths, macOS-only note, unused `cryptography` dependency removed. M10 Chart.js vendored, no external fonts. M11 doc errors fixed (session key from C, per-prompt token key, token names, ledger columns, `vault_bfv_mul_relin`, Bedrock default model, evaluator name).
- S3 n = 255, S4 quorum failover on commitment failure, S5 hash chain, S6/S14 percent/scalar bounds, S7 Decimal, S8 span merge, S9 per-prompt key, S11 error count, S12 TrustedHost + reload=False, S13 a11y fixes, S2 BFV return codes.
- This round: `verification_reason` is now read by `app.js` and `tui.py`; `llm_output_warnings` are shown in the UI next to parse warnings; the offline engine reads decimal percentages (`12.5%` was read as 5). `test_07` assertion fixed (the `<secret>` word legitimately appears in `leak_check.note`) and renamed; 21 regression tests added. Suite: 31 tests, OK.

**Still open**
- Shares and $\alpha_0$ pass through Python; reading shard files in C would make the key claim stronger.
- BFV error distribution is uniform ternary; no lattice-estimator run. The `ai == 0` skip in BFV is not constant-time.
- Ledger truncation of the newest rows and unauthenticated `created_at` / `quorum_nodes`.
- Feldman secret $\alpha_0$ is drawn from $[1, q-1]$ while higher polynomial coefficients are uniform over $[0, q-1]$ (`backend/crypto/shamir.py:140, 247`; negligible $1/q$ difference on $\alpha_0$).
- Tests `test_06`, `test_09`, `test_10` and `test_process_route_returns_502_on_provider_failure` use the app singleton backed by `database/runtime/`; `test_06` adds ledger rows there.
- Live runs with real Gemini/OpenAI/Bedrock keys, VoiceOver screen-reader check, and making the repo public (or inviting the jury).

---

## 7. Audit round 4 (Antigravity, 13 Nov 2026)

Peer-review verification (`T-378`) + follow-up fixes on `claude/victory-audit-fixes`:
- **M-R1 (Tokenizer false positives on business prose):** removed generic prose words (`sleutel`, `geheim`, `pin`) from natural-language `_GAP + is/was` sealing (kept under explicit `=`/`:` and numeric/quoted PIN rules), added guards against policy meta-nouns (`password policy was...`) and indefinite/auxiliary reminders (`a password is never...`), excluded storage/power/era/country units (`2048 MB`, `1024 GB`, `1500 MW`, `2026 AD`) from NL postcode matching, excluded standard/protocol/fiscal codes (`ISO27001`, `SOC2TYPE2`, `Q4FY2026`, `OAUTH2`, `RFC3526`, `PYTHON3`) from alphanumeric `GOV_ID`, and prioritized role-prefixed subjects (`employee Marcus Vance`) over Title-Case business nouns (`Annual Bonus`, `Balance Sheet`).
- **M-R2 (TUI LLM warnings):** `frontend/tui.py` now renders `llm_output_warnings` (including `parse_warning` and non-object `fhe_compute`/`action_intent` warnings) alongside the web UI.
- **M-R3 (Docs & Vault sync):** corrected `HANDOVER.md` notes on `parse_warning` and Feldman coefficient sampling, and synchronized the Obsidian project `README.md`.
- **S-R1..S-R4 (UX & Concurrency polish):** `app.js` renders the scrubbed `wire_request` even on HTTP 502 provider errors; ledger verification banner reports `chain_length` and `chain_errors` when older rows outside the 15-row preview fail; `SecureEnclave.execute_privileged_intent` retries `LedgerChainConflict` under concurrent writes and `EncryptedLedger` uses `time.time_ns()` for legacy table migration names; `#apiKeyInput` widened (`min-width: 14.5rem`) so its placeholder no longer clips on `1440x900`.
