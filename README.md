# VaultMind v2: Native C Enclave, Dual-Field Verifiable Secret Sharing & Leveled RLWE-BFV AI Pipeline

> **Hackathon:** Mathematics for Systems Security
> **Track:** AI Pipeline Secret Sharing Track
> **Demo video:** `<link to be added>`
> **Stack:** Python 3 (FastAPI loopback dashboard, Rich TUI, cloud LLM adapters) + compiled C11 (`libvaultcrypto.dylib`, built with `clang` against Apple CommonCrypto).
> **Platform:** macOS only (Apple CommonCrypto + `arc4random_buf`).

VaultMind lets a cloud LLM (Gemini, OpenAI or AWS Bedrock) plan actions on enterprise prompts without seeing the names, account numbers, passwords or amounts in them, and without ever holding a share of the master key. Sensitive spans are replaced by tokens or ciphertext handles before the request leaves the machine. Privileged actions are sealed into an encrypted, hash-chained ledger by a C enclave that reconstructs the master key from a $k=3$ of $n=5$ quorum on the C stack and wipes it after each seal.

---

## 1. Threat Model

**Adversaries we defend against**

| Adversary | Capability | What protects the data |
| :--- | :--- | :--- |
| Cloud LLM provider | Reads and logs every request; may return malicious or malformed output | Heuristic blinding + `<secret>` sealing; only tokens and truncated ciphertext previews are sent; LLM output is parsed as untrusted data (type checks, action whitelist, range checks) |
| Reader of fewer than $k$ shard files | Reads up to $k-1 = 2$ shard files | Shamir over $\mathbb{F}_{2^8}$ (information-theoretic) combined with Feldman shares over $\mathbb{Z}_q$ (computational) |
| Writer of shard files | Corrupts, empties, truncates or replaces shard files | Feldman VSS check, SHA-256 share digests, key-commitment check in C, failover over all $k$-subsets |
| Writer of the SQLite ledger | Edits, deletes, duplicates or reorders rows | Encrypt-then-MAC with an AAD length field, row id and hash chain bound into the AAD |

**Out of scope**

- Malware, a debugger or a heap dump of the local Python process. Shares and the Feldman secret $\alpha_0$ pass through Python (see §6); a process-memory attacker who also reads $k$ shards can recompute the key.
- A reader of the whole disk: in this demo all five shards live on one disk, plus a full backup copy in `database/runtime/.demo_clean_shards/` that powers the **↺ Restore Shards** button.
- Secrets that have no label and no recognisable pattern and are not wrapped in `<secret>…</secret>` (blinding is heuristic, see §6).
- Side channels other than those addressed by the constant-time $\mathbb{F}_{2^8}$ arithmetic and MAC comparison (the BFV code is not constant-time).
- Other local users of the machine: the loopback API has no authentication (it only rejects foreign `Host` headers).

---

## 2. Architecture and Trust Boundary

```text
 TRUSTED: local machine (127.0.0.1)                                  |  UNTRUSTED: cloud
                                                                     |
 prompt ──► BlindTokenizer ──► blinded prompt ───────────────────────┼──► LLM (Gemini / OpenAI / Bedrock)
            │  names/IBAN/IDs ──► [ID_…] [IBAN_…] [GOV_ID_…] (HMAC,   |     "blind planner": sees tokens only,
            │                      fresh 32-byte key per prompt)       |     returns text + JSON plan
            │  passwords, <secret> ──► [SECRET_…] (C AES-256 + HMAC)   |       {fhe_compute, action_intent}
            │  amounts ──► [FHE_NUM_i](ENC:0x…preview)                 |                 │
            │              Paillier E(m) and BFV limbs E(m_i)          |                 │
            ▼                                                        |                 │
 Evaluators (same local process; hold public keys n, rlk) ◄──────────┼─────────────────┘
   Paillier: c1·c2, c^p mod n²      BFV: Relin(E(a)⊗E(b))            |
            │ decrypt locally                                        |
            ▼                                                        |
 SecureEnclave ──► libvaultcrypto (C): reconstruct key from k shards,|
                   derive subkeys, AES-256-CBC + HMAC-SHA256, wipe   |
            │                                                        |
            ▼                                                        |
 vault_ledger.db (hash-chained, sealed rows)   shards/node_01..05.json (0600)
```

The cloud LLM never receives a ciphertext it could compute on and never evaluates anything: it only chooses **which** operation to run on which handle. The evaluator classes (`HomomorphicEvaluator`, `BFVEvaluator`) hold only public material ($n$, $n^2$, `rlk`), but they run locally, in the same process that holds the secret keys.

---

## 3. Mathematical Foundations

### 3.1 Shamir Secret Sharing over $\mathbb{F}_{2^8}$ (native C)

Field: $\mathbb{F}_{2^8} \cong \mathbb{F}_2[x]/(x^8 + x^4 + x^3 + x + 1)$ (`0x11B`). The 256-bit key $K_{\mathbb{F}}$ is generated in C with `arc4random_buf` (`vault_generate_and_split_key`) and each byte $s$ is split with a fresh polynomial

$$f(x) = s \oplus a_1 x \oplus \dots \oplus a_{k-1} x^{k-1}, \qquad a_1, \dots, a_{k-1} \xleftarrow{\$} \mathbb{F}_{2^8},$$

with share $y_i = f(i)$ for $i = 1, \dots, n$ ($n \le 255$). All coefficients, including the leading one, are uniform; zero is allowed.

**Security statement.** For any secret $s$ and any $k-1$ distinct nonzero points $x_1, \dots, x_{k-1}$, the map $(a_1, \dots, a_{k-1}) \mapsto (f(x_1), \dots, f(x_{k-1}))$ is a bijection of $\mathbb{F}_{2^8}^{k-1}$ (its matrix $[x_i^j]_{i,j=1}^{k-1}$ is a scaled Vandermonde matrix and therefore invertible). With uniform coefficients, any $k-1$ shares are uniformly distributed and independent of $s$. This is why the code draws the leading coefficient uniformly instead of rejecting zero.

**Reconstruction** (Lagrange at $x=0$; in characteristic 2, $-x_m = x_m$ and $x_j - x_m = x_j \oplus x_m$):

$$s = \bigoplus_{j=1}^{k} y_j \otimes \bigotimes_{m \ne j} x_m \otimes (x_j \oplus x_m)^{-1}$$

**Constant time.** `vault_gf256_mul` is a fixed 8-iteration loop with arithmetic masks, no tables and no secret-dependent branches; `vault_gf256_inv` computes $a^{-1} = a^{254} = a^2 a^4 a^8 a^{16} a^{32} a^{64} a^{128}$. Tag and commitment comparisons use `vault_ct_memeq`. This constant-time claim covers only these functions.

### 3.2 Feldman VSS and dual-field key derivation

Group: RFC 3526 Group 14, safe prime $P = 2q + 1$ (2048 bit), $g = 4$ of prime order $q$. A second polynomial $F(x) = \sum_{j=0}^{k-1} \alpha_j x^j \bmod q$ with $\alpha_0$ uniform in $[1, q-1]$ gives shares $s_i = F(i)$ and public commitments $C_j = g^{\alpha_j} \bmod P$. Before a shard is admitted to a quorum:

$$g^{s_i} \stackrel{?}{\equiv} \prod_{j=0}^{k-1} C_j^{\,(i^j \bmod q)} \pmod P$$

$C_0 = g^{\alpha_0}$ hides $\alpha_0$ only computationally (discrete logarithm in a 2048-bit safe-prime group). That suffices here because $\alpha_0$ is uniform over a set of size about $2^{2047}$, so it cannot be guessed, and because $\alpha_0$ alone is useless without $K_{\mathbb{F}}$, which is information-theoretically hidden by Shamir.

Inside `vault_enclave_seal` / `vault_enclave_unseal` (C), with $\alpha_0$ re-interpolated from the quorum's Feldman shares:

$$K_{\text{master}} = \text{HMAC-SHA256}\!\big(K_{\mathbb{F}},\ \operatorname{SHA256}(\operatorname{I2OSP}_{256}(\alpha_0))\big)$$

$$K_{\text{enc}} = \operatorname{HMAC}(K_{\text{master}}, \texttt{"VAULTMIND\_V2\_AES256\_ENC\_KEY"}), \quad K_{\text{mac}} = \operatorname{HMAC}(K_{\text{master}}, \texttt{"VAULTMIND\_V2\_HMAC\_SHA256\_KEY"})$$

$$\text{commitment} = \operatorname{HMAC}(K_{\text{master}}, \texttt{"VAULTMIND\_V2\_MASTER\_KEY\_COMMITMENT"})$$

The seal aborts (rc −10) if the reconstructed commitment differs from the one in `manifest.json`; the enclave then retries every other $k$-subset of the Feldman-valid shards.

### 3.3 Encrypt-then-MAC with an AAD length field

$$C = \text{AES-256-CBC}_{K_{\text{enc}}}(IV, \operatorname{PKCS7}(M)), \qquad IV \xleftarrow{\$} \{0,1\}^{128}$$

$$T = \text{HMAC-SHA256}_{K_{\text{mac}}}\big(\operatorname{len}_{64}^{\text{BE}}(AAD)\ \|\ AAD\ \|\ IV\ \|\ C\big)$$

The 8-byte big-endian length field fixes the boundary between AAD and IV, so bytes cannot be shifted from the AAD into the IV and ciphertext without changing the MAC input. Unseal checks $T$ in constant time before decrypting.

### 3.4 Hash-chained ledger

Row $i$ stores $(i, \text{action}_i, \text{target}_i, IV_i, C_i, T_i, h_{i-1})$, sealed with

$$AAD_i = \texttt{"}i\texttt{:}h_{i-1}\texttt{:}\text{action}_i\texttt{:}\text{target}_i\texttt{"}, \qquad h_0 = \texttt{0}^{64}$$

$$h_i = \operatorname{SHA256}\big(\operatorname{JSON}[\,i, \text{action}_i, \text{target}_i, IV_i, C_i, T_i, h_{i-1}\,]\big)$$

`verify_ledger_entries` walks the whole chain from row 1 and checks the sequence, the hash links and every MAC. A deleted, duplicated, swapped or edited row fails. Truncating the newest rows is only detectable against an externally recorded `chain_head_hash`; `created_at` and `quorum_nodes` are not authenticated.

### 3.5 Paillier PHE (2048-bit modulus by default)

$n = pq$ with two 1024-bit primes, $g = n+1$, $\lambda = \operatorname{lcm}(p-1, q-1)$, $\mu = \lambda^{-1} \bmod n$. A value $v$ is encoded in fixed point, $m = \operatorname{round}_{\text{half-even}}(100 v)$ (via `Decimal`), and encrypted as

$$E(m) = (1 + m n)\, r^n \bmod n^2, \qquad r \xleftarrow{\$} \mathbb{Z}_n^*.$$

With only $n$, the evaluator computes $c_{\text{sum}} = c_1 c_2 \bmod n^2$ and, for a percentage $p = P/f$ with $f = 10^d$ ($d \le 4$, $0 \le p \le 1000$):

$$c_{\text{bonus}} = c^{P} \bmod n^2, \qquad c_{\text{total}} = c^{100 f + P} \bmod n^2,$$

decrypted with scale $100 \cdot 100 f$. A 2048-bit modulus corresponds to about 112-bit security. The test suite uses 1024-bit keys for speed.

### 3.6 RLWE-BFV, leveled, multiplicative depth 1 (native C)

$$R_q = \mathbb{Z}_q[X]/(X^N + 1), \quad N = 2048,\ q = 2^{54},\ t = 2^{16},\ \Delta = q/t = 2^{38}$$

Secret $s$ and all errors are sampled uniformly from $\{-1, 0, 1\}^N$ by rejection sampling. $N$ and $\log q$ follow the classical 128-bit row (ternary secret) of the HomomorphicEncryption.org standard, but that table assumes errors with $\sigma \approx 3.2$; our error distribution is uniform ternary ($\sigma \approx 0.82$), so 128 bit is an approximation. No lattice estimator was run.

- **Keys** (`vault_bfv_keygen`): $\mathbf{pk} = ([-(a s + e)]_q,\ a)$, and for gadget base $B = 2^{14}$, $\ell = 0..3$: $\mathbf{rlk}_\ell = ([-(a_\ell s + e_\ell) + B^\ell s^2]_q,\ a_\ell)$.
- **Encrypt** (scalar $m$ in coefficient 0): $\mathbf{c} = ([p_0 u + e_1 + \Delta m]_q,\ [p_1 u + e_2]_q)$.
- **Decrypt**: $m = \big[\lfloor \tfrac{t}{q} [c_0 + c_1 s]_q \rceil\big]_t$, correct while the noise $|e_1 + e_2 s - e u| < \Delta/2$.
- **Multiply + relinearize** (`vault_bfv_mul_relin`): exact `__int128` negacyclic products, then
  $h_0 = \lfloor \tfrac{t}{q} c_0 d_0 \rceil_q,\ h_1 = \lfloor \tfrac{t}{q}(c_0 d_1 + c_1 d_0) \rceil_q,\ h_2 = \lfloor \tfrac{t}{q} c_1 d_1 \rceil_q$; signed digits $h_2 = \sum_{\ell=0}^{3} h_2^{(\ell)} B^\ell$ with $h_2^{(\ell)} \in [-B/2, B/2)$;
  $c'_0 = [h_0 + \sum_\ell h_2^{(\ell)} \mathrm{rlk}_{\ell,0}]_q,\ c'_1 = [h_1 + \sum_\ell h_2^{(\ell)} \mathrm{rlk}_{\ell,1}]_q$.

**Depth.** There is no bootstrapping. One ciphertext-ciphertext multiplication followed by additions decrypts correctly; a second multiplication is not supported (the audit measured 40/40 failures at depth 2).

**Measured noise** (coefficient 0, computed with the secret key; 180 random products with $m_1, m_2 \in [0, 65535]$, Apple M4 Pro, script outside the repo): fresh noise at most $\approx 2^{7.2}$ (360 fresh ciphertexts); after one multiplication at most $\approx 2^{32.7}$ (median $2^{30.5}$); decryption bound $\Delta/2 = 2^{37}$; margin $\approx 4.3$ bit. The audit of 12 Nov 2026 measured a maximum of $2^{32.6}$ (margin 4.4 bit) over 180 runs.

**32-bit products.** $A = \sum_i a_i 256^i$, $B = \sum_j b_j 256^j$ with $a_i, b_j \in [0, 255]$ are encrypted limb by limb. Each $E(a_i) \otimes E(b_j)$ is one depth-1 homomorphic product with $a_i b_j \le 65025 < t$, so it never wraps. For two full 32-bit numbers these are 16 products; they are **decrypted separately** and combined in plaintext as $\sum_{i,j} D(E(a_i) \otimes E(b_j))\, 256^{i+j}$. Only the partial products are homomorphic.

### 3.7 Key handling, stated precisely

- The 256-bit $\mathbb{F}_{2^8}$ key is generated in C with `arc4random_buf`, split and wiped in C; it never enters Python.
- The reconstructed key $K_{\mathbb{F}}$, $K_{\text{master}}$ and the AES/HMAC subkeys exist only on the C stack inside `vault_enclave_seal` / `vault_enclave_unseal` and are wiped with `memset_s` on every path (`nm -u libvaultcrypto.dylib` shows `_memset_s`).
- Measured per seal: the whole `vault_enclave_seal` call (reconstruct, derive, encrypt, MAC, wipe) took a median of 3.6 µs and a p99 of 6.3 µs (1000 seals of a 200-byte record, Apple M4 Pro, `time.perf_counter_ns` around the ctypes call, so ctypes overhead is included). This is an upper bound on how long the reconstructed key sits on the C stack per seal.
- **Not** C-only: the $k$ shares are read from disk by Python and pass through Python as hex strings and bytes; the Feldman secret $\alpha_0$ is generated and re-interpolated in Python as an `int`; the BFV and session keys live in ctypes buffers owned by the Python process. The session key for sealing prompt secrets is generated in C (`vault_random_bytes`).

---

## 4. What the cloud actually receives

The middle panel of the dashboard shows the request that left the machine (`cloud_wire_payload.actual_request`: method, URL, headers with the credential redacted, and the exact JSON body including the system prompt). Example of a blinded prompt:

```text
Compute invoice product for client [ID_BCCD4DC5] (hours: [FHE_NUM_1](ENC:0x4aadda9b400f...3db981f7),
rate: [FHE_NUM_2](ENC:0x51127202b0c4...88bc722c), password is [SECRET_536D0360], seed: [SECRET_56A92902])
and commit to database.
```

Tokens: `[ID_…]`, `[IBAN_…]`, `[GOV_ID_…]`, `[EMAIL_…]`, `[LOC_…]`, `[PHONE_…]` (HMAC-SHA256, 32-bit prefix, fresh key per prompt), `[SECRET_…]` (sealed in C with AES-256-CBC + HMAC-SHA256, never stored in plaintext token maps or logs), `[FHE_NUM_n]` (Paillier and, for integers, BFV ciphertexts; only a truncated preview of the Paillier ciphertext is sent: its first 12 and last 8 hex digits).

After blinding, a residual scan checks whether any detected value still appears in the outgoing text (case-insensitive). The result is `contains_raw_pii`, `contains_raw_secrets` and `leak_check` in the response, and is shown above the payload. The scan can only find values the tokenizer detected in the first place.

---

## 5. Claim → how to verify

All commands run from the repository root with the venv active. Test names refer to `tests/test_security_audit.py` (`test_01`…`test_10`) and `tests/test_audit_regressions.py`.

| Claim | How to verify |
| :--- | :--- |
| Key wiping uses `memset_s` | `nm -u backend/native/libvaultcrypto.dylib \| grep memset_s` → `_memset_s`; `test_memset_s_is_linked_into_the_dylib` |
| AAD/IV boundary cannot be shifted | `test_aad_boundary_shift_attack_is_rejected` |
| Shamir coefficients are uniform | `test_shamir_split_coefficients_are_uniform` |
| $n = 255$ works | `test_total_n_255_returns` |
| $\mathbb{F}_{2^8}$ inverse and distributivity | `test_01_native_c_gf256_field_axioms` |
| Feldman rejects corrupted shards, failover, block below $k$ | `test_03_feldman_2048_vss_tamper_failover_and_quorum_block`, `test_three_broken_shards_block_the_enclave` |
| Malformed shard files → TAMPER_REJECTED + failover | `test_empty_and_truncated_shard_files_fail_over`, `test_json_list_and_non_numeric_canary_fail_over` |
| Both fields are bound into the key | `test_10_redteam_audit_v2_regressions` (part 4) |
| Shard files are 0600 | `test_shard_files_are_owner_only` |
| Ledger detects edit, delete, duplicate, swap | `test_05_…` (bit flip), `test_ledger_row_deletion_is_detected`, `test_ledger_row_duplication_is_detected`, `test_ledger_row_swap_is_detected` |
| BFV depth 1 is exact (also followed by addition) | `test_07_native_c_rlwe_bfv_n2048_leveled_multiplication`, `test_depth_1_multiplication_then_addition_is_exact` |
| 32-bit products via limbs are exact | `test_09_dotenv_llm_config_and_bfv_api_endpoints`, `test_10_…` (300 × 300 = 90,000) |
| Depth 2 is not guaranteed | `test_depth_2_is_not_guaranteed` (documents, does not assert correctness) |
| Leak flags are computed, not constants | `test_leak_flags_are_computed` |
| Previously leaking prompts are now blinded | `test_previously_leaking_prompts_are_blinded` |
| Secrets never sit in token maps | `test_08_free_text_passwords_secret_tags_jwts_hex_keys_and_c_session_seal` |
| Provider failures become HTTP 502, key not echoed | `test_gemini_without_candidates_raises_provider_error`, `test_gemini_timeout_raises_provider_error`, `test_process_route_returns_502_on_provider_failure` |
| Malformed LLM plan does not crash | `test_action_intent_as_string_does_not_raise`, `test_action_intent_string_from_llm_is_ignored_with_warning` |
| Non-integer percentages are not truncated | `test_offline_engine_keeps_decimal_percent` |
| Ordinary business prose avoids false-positive sealing | `test_ordinary_business_prose_avoids_false_positives` |
| Concurrent ledger writes preserve hash-chain integrity | `test_concurrent_enclave_seals_succeed_with_valid_hash_chain` |
| Dashboard makes no external requests | `grep -nE "https?://" frontend/static/index.html` → no output (Chart.js is in `frontend/static/vendor/`) |
| Whole suite | `python3 -m unittest discover -s tests -v` → 36 tests, OK |

---

## 6. Known Limitations

- **Blinding is heuristic (regex-based).** Not detected: lower-case names (`jan jansen`), single first names without a role word (`Sem`, `Maria`), bare integers below 10, percentages, street names and cities without a label, company names made only of common business words (`Cloud Reserve`, `Master Audit`), and secrets without a label or a recognisable pattern. After a label such as `password` or `sleutel`, a value is sealed when it looks like a credential (digit mixed with letters, a symbol, or three or more hyphen-joined parts); a plain-word value after a policy word or an indefinite article (`a password is never shared`) is treated as prose and left alone. Wrap such secrets in `<secret>…</secret>`. The residual scan cannot flag what was never detected.
- **Shares and $\alpha_0$ pass through Python** (see §3.7). The claim is limited to the reconstructed key and subkeys.
- **Locally, plaintext is kept for unblinding and display.** The token map, the plaintext numbers and the local audit trail (`original_prompt`, token table) contain names and amounts; only the SECRET category is zero-retention.
- **BFV security is approximate:** uniform ternary errors instead of $\sigma \approx 3.2$; no lattice-estimator run.
- **BFV is not constant-time:** `bfv_poly_mul_exact` skips zero coefficients of its first argument, which can be the secret key or the encryption randomness.
- **BFV is depth 1 only**; 32-bit products are recombined in plaintext after decrypting up to 16 partial products.
- **The LLM is a blind planner**, not an evaluator: it gets no full ciphertexts and computes nothing. Evaluation runs locally in the process that holds the secret keys.
- **Ledger:** truncation of the newest rows is only detectable against an externally stored `chain_head_hash`; `created_at` and `quorum_nodes` are not authenticated.
- **Shard storage:** all shards are on one disk, plus the demo backup copy in `.demo_clean_shards/`. The $\mathbb{F}_{2^8}$ share digest in `manifest.json` is an unkeyed SHA-256; integrity of that half ultimately rests on the key commitment checked in C.
- **macOS only** (CommonCrypto, `arc4random_buf`).
- **Live cloud path:** request bodies and error handling are tested with mocked HTTP responses only; the live Gemini, OpenAI and Bedrock calls have not yet been run with real keys.
- **No API authentication** on the loopback server.

---

## 7. Quickstart

Requirements: macOS with the Xcode Command Line Tools (`clang`), Python 3.9+.

```bash
git clone https://github.com/semscoding/vaultmind.git
cd vaultmind
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Optional: compile the C library explicitly (it is also built automatically on first import)
python3 backend/native/build.py

# Run the test suite (36 tests)
python3 -m unittest discover -s tests -v

# Optional: live cloud provider (otherwise the offline engine is used; nothing leaves the machine)
cp .env.example .env    # then fill in GEMINI_API_KEY, OPENAI_API_KEY or AWS_BEARER_TOKEN_BEDROCK

# Web dashboard on http://127.0.0.1:8000
python3 main.py

# Or the terminal UI (commands: /corrupt <n>, /restore, /verify, /metrics, exit)
python3 frontend/tui.py
```

Runtime state (shards, manifest, ledger) is created in `database/runtime/` (git-ignored). Some tests use the app's shared pipeline and therefore add rows to that ledger; all other tests use temporary directories.

### Repository layout

```text
vaultmind/
├── frontend/      # Loopback dashboard (index.html, app.js, style.css, vendor/chart.umd.min.js) and Rich TUI (tui.py)
├── backend/
│   ├── native/    # vaultcrypto.c (GF(2^8) Shamir, enclave seal/unseal, session vault, RLWE-BFV) and build.py
│   └── crypto/    # shamir.py (Feldman VSS + ctypes), homomorphic.py (Paillier), bfv_fhe.py, blind_tokenizer.py, zeroize.py
├── database/      # schema.sql and ledger.py (hash-chained sealed ledger)
├── apis/          # routes.py (FastAPI) and llm_client.py (Gemini / OpenAI / Bedrock / offline engine)
├── services/      # pipeline_service.py and enclave_service.py
├── monitoring/    # telemetry.py
└── tests/         # test_security_audit.py and test_audit_regressions.py (36 tests)
```
