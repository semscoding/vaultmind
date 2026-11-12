# VaultMind v2: Native C Enclave, Verifiable Secret Sharing & Homomorphic AI Pipeline

> **Hackathon:** Mathematics for Systems Security  
> **Track:** AI Pipeline Secret Sharing Track  
> **Stack:** Python 3 (Orchestration & FastAPI/Rich UI) + **Compiled Native C (`libvaultcrypto.dylib`)** via `clang` & Apple CommonCrypto.

---

## 1. Problem & Zero-Trust Architecture

Giving LLM agents (Google Gemini, OpenAI, AWS Bedrock) direct access to enterprise data and privileged credentials creates two severe attack surfaces:
1. **Plaintext Cloud Exposure:** Sensitive PII, banking IBANs, government IDs (BSN/SSN), and compensation numbers are logged on third-party model host servers.
2. **Master Key Compromise:** Storing database or signing keys in agent memory exposes them to prompt injection, Python heap inspection, and unauthorized tool execution.

**VaultMind v2** eliminates both surfaces mathematically and architecturally:
- **Span-Based Cryptographic Blinding & 1024-bit Fixed-Point Paillier FHE:** Sensitive identifiers are replaced with keyed HMAC-SHA256 tokens (`[ID_XXXX]`, `[IBAN_XXXX]`, `[GOV_ID_XXXX]`), while numbers are encrypted under a **1024-bit Paillier modulus** ($n = p \cdot q$). The cloud agent emits algebraic FHE instructions (e.g., 15% bonus calculation) that are evaluated **directly on ciphertexts modulo $n^2$** without intermediate decryption.
- **2048-bit Feldman Verifiable Secret Sharing (VSS):** Master key shards live strictly in isolated `0600` shard files on disk (`vault_data/shards/`). Before any shard enters a quorum, it is verified against RFC 3526 Group 14 (2048-bit safe prime) polynomial commitments. Corrupted or forged shards are mathematically rejected with automatic fault-tolerant failover to healthy shards.
- **Native C Constant-Time Enclave (`libvaultcrypto.dylib`):** Reconstructing the 256-bit Master Key from $k=3$ of $n=5$ shares over $\mathbb{F}_{2^8}$, encrypting records with AES-256-CBC, signing with Encrypt-then-MAC HMAC-SHA256, and wiping stack buffers via **C11 `memset_s()`** occur strictly inside compiled C. **Zero bytes of the Master Key ever enter the Python heap.**

---

## 2. Mathematical Foundations

### 2.1 Constant-Time Shamir Secret Sharing over $\mathbb{F}_{2^8}$ (Native C)

Each byte $s \in \mathbb{F}_{2^8} \cong \mathbb{F}_2[x] / (x^8 + x^4 + x^3 + x + 1)$ of the 32-byte Master Key is shared via a degree-$(k-1)$ polynomial:
$$f(x) = a_0 \oplus a_1 x \oplus a_2 x^2 \oplus \dots \oplus a_{k-1} x^{k-1} \in \mathbb{F}_{2^8}[x], \quad a_0 = s$$

To prevent cache-timing and branch-prediction side-channel attacks in `native/vaultcrypto.c`:
1. **Table-Free Multiplication (`vault_gf256_mul`):** Executed in a fixed 8-iteration loop using arithmetic bitmasks `-(int8_t)(b & 1)` with reduction polynomial `0x1B` — zero S-boxes/lookup tables and zero secret-dependent branches.
2. **Branchless Multiplicative Inverse (`vault_gf256_inv`):** By Fermat's Little Theorem in $\mathbb{F}_{2^8}^*$, $a^{255} = 1$, hence:
   $$a^{-1} = a^{254} = a^2 \cdot a^4 \cdot a^8 \cdot a^{16} \cdot a^{32} \cdot a^{64} \cdot a^{128}$$
   computed in exactly 7 squarings and 6 multiplications.
3. **Lagrange Interpolation at $x = 0$:** Because $-x_m = x_m$ and $x_j - x_m = x_j \oplus x_m$ in characteristic $2$:
   $$s = f(0) = \bigoplus_{j=1}^{k} y_j \otimes \left( \bigotimes_{\substack{m=1 \\ m \neq j}}^{k} x_m \otimes (x_j \oplus x_m)^{-1} \right)$$

---

### 2.2 Public Share Verification via 2048-bit Feldman VSS

Let $P = 2q + 1$ be the 2048-bit safe prime from RFC 3526 Group 14, where $q = (P-1)/2$ is a 2047-bit prime and $g = 4 \bmod P$ generates the prime-order subgroup $\mathbb{G}_q$ of order $q$.

For verifier polynomial $F(x) = \sum_{j=0}^{k-1} \alpha_j x^j \bmod q$, the dealer publishes commitments:
$$C_j = g^{\alpha_j} \bmod P \quad \text{for } j \in \{0, \dots, k-1\}$$

Before admitting shard $i$ with scalar $s_i = F(i) \bmod q$ into a quorum, `SecureEnclave` verifies:
$$g^{s_i} \stackrel{?}{\equiv} \prod_{j=0}^{k-1} C_j^{(i^j \bmod q)} \pmod P$$

Any bit-flip or malicious share forgery violates this congruence, triggering immediate quarantine of node $i$ and automatic failover to remaining verified shards.

---

### 2.3 1024-bit Fixed-Point Paillier Homomorphic Evaluation

With 512-bit primes $p, q$, modulus $n = p \cdot q$ ($\ge 1024$ bits), $\lambda = \operatorname{lcm}(p-1, q-1)$, $g = n + 1$, and $\mu = \lambda^{-1} \bmod n$, a fixed-point value $v$ (scaled by $S = 100$, $m = \lfloor 100v \rceil$) is encrypted with random $r \in \mathbb{Z}_n^*$ as:
$$c = E(m) = (1 + m \cdot n) \cdot r^n \pmod{n^2}$$

Using **only the public key $n$**, `HomomorphicEvaluator` computes:
- **Homomorphic Sum:**
  $$c_{\text{sum}} = c_1 \cdot c_2 \pmod{n^2} \implies D(c_{\text{sum}}) = m_1 + m_2 \pmod n$$
- **Homomorphic Percentage Bonus ($p\%$ of $m$):**
  $$c_{\text{bonus}} = c_1^{p} \pmod{n^2}, \quad c_{\text{total}} = c_1^{100 + p} \pmod{n^2}$$
  Decrypting at the client with adjusted scale $S' = 100 \cdot S = 10{,}000$ yields the exact bonus and adjusted compensation (e.g., $15\%$ on $\$130{,}000 \implies \$19{,}500.00$ and $\$149{,}500.00$) without the cloud ever seeing the salary!

---

## 3. Vulnerability Windows Mitigated

| Attack Vector | Mitigation in VaultMind v2 | Verified By |
| :--- | :--- | :--- |
| **Python Heap / GC Key Remnants** | Master key reconstructed strictly in a C stack array `uint8_t master_key[32]` and wiped via `memset_s()` + volatile memory fence prior to returning. | `test_02_real_c_memset_s_zeroize...` |
| **Cache-Timing Side Channels** | Branchless, lookup-table-free $\mathbb{F}_{2^8}$ multiplication & Fermat inversion ($a^{254}$) + constant-time MAC check (`vault_ct_memeq`). | `native/vaultcrypto.c`, `test_01` |
| **Corrupted / Byzantine Vault Node** | 2048-bit Feldman VSS rejects forged shares before reconstruction; quorum automatically fails over to healthy nodes ($k=3$ of $n=5$). | `test_03_feldman_2048_vss...` |
| **Cloud Provider Logging & Leaks** | Single-pass span blinder masks API keys, IBANs, BSN/SSNs, emails, names, and encrypts numbers with 1024-bit Paillier. | `test_05_all_scenarios_zero_leaks...` |
| **Database Tampering** | SQLite ledger stores AES-256-CBC ciphertexts with Encrypt-then-MAC HMAC-SHA256 over `action:target || iv || ciphertext`. | `test_05` (SQLite bit-flip check) |
| **Frontend DOM XSS** | Strict HTML entity escaping (`escapeHtml`) and `textContent` DOM builders neutralize script/HTML payloads in prompts. | `ui/static/app.js`, `test_06` |

---

## 4. Repository Architecture & Quickstart

```text
vaultmind/
├── frontend/      # Loopback Web Dashboard (index.html, app.js, style.css) & Rich TUI (tui.py)
├── backend/       # Native C Core (vaultcrypto.c) & Cryptographic Primitives (Shamir, Paillier, Blinder)
├── database/      # Encrypted SQLite Ledger (schema.sql, ledger.py) & isolated runtime shards
├── apis/          # FastAPI REST Routes (routes.py) & Cloud LLM Adapters (Gemini 2.5 Flash / OpenAI)
├── services/      # Zero-Knowledge Pipeline & 2048-bit Feldman VSS Enclave Orchestration
├── monitoring/    # Real-time Security & Cryptographic Latency Telemetry (telemetry.py)
└── tests/         # Automated Cryptographic & Security Audit Suite
```

```bash
cd /Users/sem/.gemini/antigravity/scratch/vaultmind
source venv/bin/activate

# 1. Compile Native C Cryptographic Library (clang)
python3 backend/native/build.py

# 2. Run Full Cryptographic & Security Audit Suite
python3 -m unittest tests/test_security_audit.py -v

# 3A. Start Loopback Web Dashboard (http://127.0.0.1:8000)
python3 main.py

# 3B. Or Launch Rich Terminal User Interface (TUI)
python3 frontend/tui.py
```

### Live Cloud LLM Configuration (Optional)
Select **Google Gemini 2.5 Flash** (`GEMINI_API_KEY`) or **OpenAI GPT-4o-mini** (`OPENAI_API_KEY`) in the header, or use the built-in **Offline Deterministic Zero-Knowledge Engine**.
