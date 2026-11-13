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
│   ├── tui.py                       # Rich TUI (`python3 frontend/tui.py`; /corrupt <n>, /restore, /verify, /metrics, exit); shows "Evaluated by:" under the homomorphic result
│   └── static/
│       ├── index.html               # 3-column UI + Paillier/BFV playground + ledger table; no external scripts or fonts
│       ├── style.css
│       ├── app.js                   # textContent/escapeHtml rendering; shows the real wire request and the computed leak check
│       └── vendor/chart.umd.min.js  # Chart.js 4.4.9, vendored (licence file next to it)
├── backend/
│   ├── native/
│   │   ├── build.py                 # clang -O2 -Wall -Wextra -Werror -fPIC -shared → libvaultcrypto.dylib (also auto-built on first import)
│   │   └── vaultcrypto.c            # C11 core: GF(2^8) Shamir, key generation, share files (vault_*_files, vault_share_file_*), enclave seal/unseal, session vault, RLWE-BFV
│   └── crypto/
│       ├── zeroize.py               # ctypes loader, `vault_secure_wipe`, `NativeBufferGuard`
│       ├── shamir.py                # `ShamirSecretSharing` (C bindings, share-file API, `ShareFileError`) + `FeldmanVSS` over RFC 3526 Group 14
│       ├── homomorphic.py           # `PaillierKeypair` (2048-bit default, Decimal fixed point) + `HomomorphicEvaluator`
│       ├── bfv_fhe.py               # `BFVContext`, `BFVEvaluator` (holds only rlk), `SessionSecretVault`
│       ├── blind_tokenizer.py       # Span blinder, overlap merge, per-prompt token key, residual leak scan, `execute_and_decrypt_fhe`
│       └── gazetteer.py             # Bundled first-name / place / street-word lists and cue words (no model, no downloads)
├── database/
│   ├── schema.sql                   # `sealed_transactions` (hash-chained)
│   ├── ledger.py                    # `EncryptedLedger`: append with chain position, row_hash, migration of pre-chain tables
│   └── runtime/                     # git-ignored: shards/node_01..05.json + node_01..05.gfshare, .demo_clean_shards/, manifest.json, vault_ledger.db
├── apis/
│   ├── llm_client.py                # Gemini / OpenAI / Bedrock adapters, offline engine, `LLMProviderError`, tolerant JSON parser
│   └── routes.py                    # /api/process, /api/llm-config, /api/vault-status, /api/tamper-node, /api/restore-nodes,
│                                    # /api/ledger, /api/homomorphic-calc, /api/bfv-fhe-calc, /api/monitoring/{metrics,health}
├── services/
│   ├── enclave_service.py           # `SecureEnclave`: shard inspection, quorum failover, chained sealing, full-chain verification, legacy re-provisioning
│   ├── evaluator_worker.py          # Separate evaluator process (public n / rlk + ciphertexts, length-prefixed JSON over pipes), restart, fallback
│   └── pipeline_service.py          # `AgentPipeline`: blinding → LLM → evaluation → enclave, leak flags, llm_output_warnings, fhe_evaluated_by
├── monitoring/
│   └── telemetry.py                 # `SecurityMonitor`
└── tests/
    ├── test_security_audit.py       # 10 original tests (test_01 … test_10)
    ├── test_audit_regressions.py    # 37 regression tests for Victory Audit + rounds 3–5 (temp dirs, mocked HTTP)
    ├── test_c_share_files.py        # 16 tests: share-file layout, Python never opens .gfshare, failover, legacy migration
    ├── test_evaluator_process.py    # 14 tests: separate process, no secret material on the wire, restart, fallback, manipulated answers
    └── test_blinding_gazetteer.py   # 15 tests: list-based names, addresses, places, cued organisations, prose, hostile inputs
```

---

## 3. Core Cryptographic Architecture & Decisions Made

1. **Key generation and reconstruction (`vaultcrypto.c` + `shamir.py` + `enclave_service.py`):**
   - The 256-bit GF(2^8) key is generated in C with `arc4random_buf`, split in C and each share written by C to its own file `shards/node_0X.gfshare` (32 raw bytes, 0600, fsync) by `vault_generate_split_key_to_files`. Python only receives the SHA-256 of each share and the key commitment. Shamir coefficients are uniform, including a zero leading coefficient; `total_n` up to 255 works.
   - The Feldman secret $\alpha_0$ and its polynomial are generated in Python (`secrets`), over $\mathbb{Z}_q$ of RFC 3526 Group 14 ($P = 2q+1$, $g = 4$).
   - Seal/unseal: Python reads the $k$ shard JSON files (Feldman shares only), re-interpolates $\alpha_0$, and passes the `.gfshare` paths, the x values, the expected share digests and $\operatorname{SHA256}(\alpha_0)$ to `vault_enclave_seal_files` / `vault_enclave_unseal_files`. C opens each share file with `O_NOFOLLOW`, checks with `fstat` that it is a regular file of exactly 32 bytes, compares its SHA-256 in constant time and wipes the share buffers on every path. Then in C: $K_{\text{master}} = \operatorname{HMAC\text{-}SHA256}(K_{\mathbb{F}}, \operatorname{SHA256}(\alpha_0))$, subkeys via HMAC with fixed labels, commitment check (rc −10), AES-256-CBC + HMAC-SHA256 over `len64be(aad) || aad || iv || ct`, then `vault_secure_wipe` on every path.
   - `vault_secure_wipe` calls `memset_s` on macOS (`#if defined(__STDC_LIB_EXT1__) || defined(__APPLE__)`), volatile loop elsewhere; `nm -u libvaultcrypto.dylib` shows `_memset_s`.
   - Shard format v2 (`manifest.json` has `format_version: 2`): `node_0X.json` (0600) holds `node_id`, `x`, `gf_share_sha256`, `canary_y`, `feldman_y_hex`, no share bytes; `node_0X.gfshare` holds the share. Inspection, demo backup/restore and the demo Corrupt button go through `vault_share_file_check`, `vault_share_file_copy` and `vault_share_file_flip_byte`; Python never opens a `.gfshare` file (guarded by `test_python_never_opens_share_files`). An old-format runtime (shares as hex in JSON, no `format_version`) is re-provisioned at start-up and its ledger table archived; an unparseable manifest raises instead of re-keying.
   - `SecureEnclave` keeps no shares in `self.__dict__`. Malformed files (empty, truncated, JSON list, non-numeric fields, missing/short/long/symlinked/bit-flipped `.gfshare`) become `TAMPER_REJECTED`. If the commitment check fails, or a share file changed after inspection, every other k-subset of the valid shards is tried.
   - Precisely stated: the GF(2^8) shares and $K_{\mathbb{F}}$ never pass through Python; the Feldman shares and $\alpha_0$ do. A Python heap dump alone therefore gives only the Feldman half, not $K_{\text{master}}$. The reconstructed key and the subkeys are C-stack-only.
2. **Ledger (`ledger.py`, `schema.sql`):** columns `id, created_at, action, target_token, quorum_nodes, iv_hex, ciphertext_hex, hmac_hex, prev_hash`. `prev_hash` = SHA-256 over the previous row (`id, action, target_token, iv_hex, ciphertext_hex, hmac_hex, prev_hash`), genesis = 64 zeros; AAD = canonical JSON `[id, prev_hash, action, target_token]` (schema v4; older tables archived automatically). `verify_ledger_entries` checks the whole chain (including `ALLOWED_ACTIONS` policy and strict hex lengths) and returns `verification_reason` per displayed row plus `chain_errors` and `chain_head_hash`. Not detected: truncation of the newest rows (only against an externally stored `chain_head_hash`); `created_at` and `quorum_nodes` are not authenticated.
3. **Homomorphic layer (`homomorphic.py`, `bfv_fhe.py`, `vaultcrypto.c`):**
   - Paillier, 2048-bit modulus by default (`AgentPipeline(paillier_bits=2048)`; tests pass 1024 for speed). Fixed point via `Decimal`; percentages may be non-integer (up to 4 decimals, 0 to 1000); scalars are integers with |scalar| ≤ 10^6.
   - RLWE-BFV, leveled, multiplicative depth 1: N = 2048, q = 2^54, t = 65536, Δ = 2^38, gadget base 2^14 with 4 limbs, uniform ternary secret and errors. N and log q match the classical 128-bit row of the HE standard, but the errors are ternary (σ ≈ 0.82, not 3.2), so 128 bit is an approximation. BFV functions return int status codes (`VAULT_BFV_ENOMEM`); the multiplication is `vault_bfv_mul_relin` and wipes its workspace before `free`. The `ai == 0` skip in `bfv_poly_mul_exact` is not constant-time.
   - 32-bit products: up to 16 base-256 limb products, each a depth-1 homomorphic product, decrypted separately and recombined in plaintext.
   - Evaluators: in the pipeline, `HomomorphicEvaluator` and `BFVEvaluator` run in a separate child process (`services/evaluator_worker.py`, called from `BlindTokenizer.execute_and_decrypt_fhe`) that receives only `n` or `rlk` plus ciphertexts, as length-prefixed JSON over pipes (no pickle). Both sides validate fields, lengths and ranges. The main process decrypts. Results carry `evaluated_by`, `evaluator_pid`, `evaluator_inputs`; the pipeline returns `fhe_evaluated_by`. One restart after a crash or time-out, then `evaluated_by: "in-process fallback"` with `evaluator_warning`. Same machine, no sandbox: a process boundary, not a network or hardware boundary. The playground endpoints still evaluate in the main process. The cloud LLM only chooses the operation.
4. **Blinding and secrets (`blind_tokenizer.py`, `SessionSecretVault`):**
   - Fresh 32-byte HMAC key per `blind_prompt()` call; tokens `[ID_…]`, `[IBAN_…]`, `[GOV_ID_…]`, `[EMAIL_…]`, `[LOC_…]`, `[PHONE_…]`, `[SECRET_…]`, `[FHE_NUM_n]`. Unicode names, Mc/Mac, Dutch labels (`wachtwoord`, `pincode`, `geheim`), `password … is X` with up to four words between, case-insensitive IBAN, alphanumeric IDs, phone numbers, Dutch postcodes, PEM/AWS/Slack keys. Overlapping spans are merged; an unclosed `<secret>` runs to the end of the prompt.
   - SECRET spans are sealed in C (AES-256-CBC + HMAC, session key from `vault_random_bytes`), never stored in `plaintext_to_token` / `token_to_plaintext` or logs.
   - Residual scan after blinding: `contains_raw_pii`, `contains_raw_secrets` and `leak_check` are computed per request.
   - List-based detection (`gazetteer.py`: 859 first names of which 112 ambiguous, 463 places of which 51 ambiguous, street suffixes/words, cue words): single first names, lower-case names after a person word or with a surname particle, addresses as one `[LOC_…]` token with house number, place names, organisations after a cue word (`Pay`, `Invoice from`, `vendor`, …).
   - Remaining gaps (documented): lower-case names without particle and without a person word (`renée müller confirmed`), ambiguous names/places without context (`Will`, `Mark`, `Best`, `Nice`), names/places outside the lists, countries, percentages, bare integers below 10, unlabelled secrets without a pattern. The lists are compiled from general knowledge, not checked against an official source.
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

# 1. (Re)compile the C core (also happens automatically when the .dylib is missing or older than vaultcrypto.c)
./venv/bin/python3 backend/native/build.py
nm -u backend/native/libvaultcrypto.dylib | grep memset_s

# 2. Full test suite: 92 tests (about 20 s; writes to database/runtime/, which is git-ignored)
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
- Shares and $\alpha_0$ pass through Python; reading shard files in C would make the key claim stronger. (GF(2^8) half resolved in section 9.)
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

---

## 8. Audit round 5 (Antigravity PR #1 Review Fixes, 13 Nov 2026)

- **Decimal DoS & underflow hardening (`homomorphic.py`):** bounded exponent/digit lengths via `Decimal.as_tuple()` before `int()` or `normalize()`, preventing `int(Decimal("1e2000000"))` main-thread hangs, `decimal.Overflow` 500s, and `"1e-2000000"` silent underflow to `0%`.
- **Echoed `[SECRET_…]` exfiltration block (`llm_client.py`, `blind_tokenizer.py`):** `SYSTEM_PROMPT` forbids echoing `[SECRET_XXXX]`, and `unblind_response()` keeps echoed secret tokens redacted (`[REDACTED:[SECRET_…]]`) by default unless `include_secrets=True`.
- **Canonical ledger AAD & strict hex validation (`enclave_service.py`, `ledger.py`, `shamir.py`):** replaced colon-delimited AAD with canonical JSON `[seq, prev_hash, action, target]` (auto-migrating pre-v4 tables via `PRAGMA user_version = 4`), checked `ALLOWED_ACTIONS` during verification, and rejected short/malformed hex strings before `ctypes` buffer packing.
- **Tokenizer hardening & O(L) regexes (`blind_tokenizer.py`):** added Unicode NFC normalization, a linear depth-tracking `<secret>` parser (whitespace & nested tags), escaped quotes, mid-word apostrophes in single quotes, mid-token `,`/`;` preservation, partitioned `O(L)` lookaheads eliminating `O(L^2)` ReDoS, and a 65,536-char prompt cap.
- **Build & loopback CSRF guards (`zeroize.py`, `main.py`, `vaultcrypto.c`):** `load_native_lib()` rebuilds when `vaultcrypto.c` is newer than `libvaultcrypto.dylib`; HTTP middleware blocks cross-origin/cross-site browser `POST`s (`403`); `reconstruct_bytes_internal` rejects `k > 255` upfront. Suite: 47 tests, OK.

---

## 9. Hardening round (13 Nov 2026)

Branch `claude/hardening` (retargeted to `main` after PR #2 merged). Three changes, plus a UI/TUI line that shows who ran the homomorphic step, followed by peer-review hardening fixes. Suite: 92 tests, OK.

**Resolved**
- **GF(2^8) shares no longer pass through Python.** Each share lives in `shards/node_0X.gfshare` (32 bytes, 0600) and is written, read, checked, copied and (demo) corrupted only by `libvaultcrypto` (`vault_generate_split_key_to_files`, `vault_enclave_seal_files`, `vault_enclave_unseal_files`, `vault_share_file_check`, `vault_share_file_copy`, `vault_share_file_flip_byte`), staged via `O_CREAT | O_EXCL | O_NOFOLLOW` sibling temp files + `rename` so existing or hard-linked inodes are never truncated or clobbered on failure. Shard JSON (`_read_private_json` / `_write_private_json` with `O_NOFOLLOW`) holds only `x`, `gf_share_sha256`, `canary_y`, `feldman_y_hex` (and `node_id`); manifest `format_version: 2`. Old-format runtimes preserve custom `(threshold_k, total_n)`, clean up stale JSON shards, re-provision first, and archive the old ledger table. Tests: `tests/test_c_share_files.py`.
- **Homomorphic evaluation in a separate process** (`services/evaluator_worker.py`) that holds only `n` or `rlk`; frames carry monotonic request `id`s over `selectors.DefaultSelector` non-blocking pipes, kill the worker on any incomplete exchange or `EvaluatorProtocolError`, validate `VAULTMIND_EVALUATOR_TIMEOUT`, and run off the `asyncio` event loop via `asyncio.to_thread`. Results report `evaluated_by` / `evaluator_pid` / `evaluator_inputs`, the pipeline returns `fhe_evaluated_by`, and the dashboard formula box and the TUI show an "Evaluated by:" line. Tests: `tests/test_evaluator_process.py`.
- **List-based blinding** (`backend/crypto/gazetteer.py`) for first names, places, addresses with house number (including `s-Hertogenbosch` / `s-Gravenhage` with or without leading apostrophe) and cued organisations, with disambiguation for NL/EN homographs (`Anders`, `Houten`, `Weert`, `Duiven`, `Wenen`, `Hulst`, calendar `Jan`, `to peter out`, and role/person-cued city-homograph names like `Austin`, `Sofia`, `Milan`). Tests: `tests/test_blinding_gazetteer.py`. The main session measured 1 remaining leak (a percentage, on purpose) on 66 adversarial prompts and 0 blinded words on five paragraphs of ordinary business prose; that benchmark is not part of the suite.

**Still open**
- Feldman shares and $\alpha_0$ still pass through Python (2048-bit arithmetic).
- All shards on one disk plus the demo backup folder; no secure deletion of old share files on a copy-on-write file system; `O_NOFOLLOW` only covers the last path component; C-stack wiping not measured with a memory dump.
- The evaluator boundary is a local process without sandbox; the playground endpoints (`/api/homomorphic-calc`, `/api/bfv-fhe-calc`) still evaluate in the main process.
- Blinding gaps listed in section 3, point 4; the name and place lists have not been checked against an official source.
- Earlier open points (BFV error distribution and constant time, ledger truncation, live provider runs) are unchanged.
