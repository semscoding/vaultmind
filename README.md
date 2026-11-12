# VaultMind v2: Native C Enclave, Verifiable Secret Sharing & Dual PHE / Lattice FHE AI Pipeline

> **Hackathon:** Mathematics for Systems Security  
> **Track:** AI Pipeline Secret Sharing Track  
> **Stack:** Python 3 (FastAPI Web Loopback, Rich TUI & Cloud LLM Orchestration) + **Compiled Native C11 (`libvaultcrypto.dylib`)** via `clang` & Apple CommonCrypto.

---

## 1. Problem & Zero-Trust Architecture

Giving host-provider LLM APIs (**Google Gemini 2.5 Flash**, **OpenAI GPT-4o-mini**, **AWS Bedrock**) direct access to enterprise prompts and privileged credentials creates two critical attack surfaces:
1. **Plaintext Cloud Exposure:** Sensitive PII, banking IBANs, government IDs (BSN/SSN), passwords, raw keys, and financial numbers are transmitted to and potentially retained on host-provider servers.
2. **Master Key Compromise:** Storing database or signing master keys in Python/agent memory exposes them to prompt injection, garbage-collector heap remnants, and unauthorized tool execution.

**VaultMind v2** eliminates both surfaces mathematically and architecturally:
- **Arbitrary Secret & PII Blinding + C AES-256 Session Sealing:** Explicit `<secret>...</secret>` spans, free-text passwords/passphrases/PINs, Bearer/JWT tokens, raw 128/256-bit hex keys, IBANs, BSN/SSNs, emails, and names are scrubbed before any API call. All `[SECRET_XXXX]` tokens are immediately sealed in C memory via **AES-256-CBC + HMAC-SHA256** (`vault_session_seal`), never kept in plaintext dictionaries.
- **Dual Homomorphic Encryption (1024-bit Paillier PHE + Native C Lattice RLWE-BFV FHE):**
  - **1024-bit Fixed-Point Paillier PHE** ($\mathbb{Z}_{n^2}^*$) evaluates blind financial sums and public percentage policy scalars ($c^k \bmod n^2$) with exact 2-decimal precision.
  - **Compiled C Ring-LWE Brakerski-Fan-Vercauteren (BFV) FHE** over $R_q = \mathbb{Z}_{2^{60}}[X]/(X^{64}+1)$ evaluates **both** homomorphic addition $E(m_1) \oplus E(m_2)$ **and** non-linear ciphertext $\times$ ciphertext multiplication $E(m_1) \otimes E(m_2)$ with **4-limb gadget relinearization** using 128-bit C integers (`__int128`).
- **2048-bit Feldman Verifiable Secret Sharing (VSS) & Native C Enclave (`libvaultcrypto.dylib`):** The 256-bit Master Key is split into $n=5$ isolated `0600` disk shards ($k=3$ threshold) verified via RFC 3526 Group 14 (2048-bit safe prime) commitments. Reconstruction over $\mathbb{F}_{2^8}$, AES-256-CBC + HMAC-SHA256 ledger sealing, and **C11 `memset_s()`** stack zeroization happen strictly inside compiled C — **zero bytes of the Master Key ever enter Python RAM**.

---

## 2. Mathematical Foundations

### 2.1 Constant-Time Shamir Secret Sharing over $\mathbb{F}_{2^8}$ (Native C)

Each byte $s \in \mathbb{F}_{2^8} \cong \mathbb{F}_2[x] / (x^8 + x^4 + x^3 + x + 1)$ of the 32-byte Master Key is shared via a degree-$(k-1)$ polynomial:
$$f(x) = a_0 \oplus a_1 x \oplus a_2 x^2 \oplus \dots \oplus a_{k-1} x^{k-1} \in \mathbb{F}_{2^8}[x], \quad a_0 = s$$

To prevent cache-timing and branch-prediction side channels in `backend/native/vaultcrypto.c`:
1. **Table-Free Multiplication (`vault_gf256_mul`):** Fixed 8-iteration loop using arithmetic bitmasks `-(int8_t)(b & 1)` with reduction polynomial `0x1B` — zero lookup tables and zero secret-dependent branches.
2. **Branchless Multiplicative Inverse (`vault_gf256_inv`):** By Fermat's Little Theorem in $\mathbb{F}_{2^8}^*$, $a^{255} = 1$:
   $$a^{-1} = a^{254} = a^2 \cdot a^4 \cdot a^8 \cdot a^{16} \cdot a^{32} \cdot a^{64} \cdot a^{128}$$
3. **Lagrange Interpolation at $x = 0$:** Since $-x_m = x_m$ and $x_j - x_m = x_j \oplus x_m$ in characteristic $2$:
   $$s = f(0) = \bigoplus_{j=1}^{k} y_j \otimes \left( \bigotimes_{\substack{m=1 \\ m \neq j}}^{k} x_m \otimes (x_j \oplus x_m)^{-1} \right)$$

---

### 2.2 Public Share Verification via 2048-bit Feldman VSS

Let $P = 2q + 1$ be the 2048-bit safe prime from RFC 3526 Group 14, where $q = (P-1)/2$ is prime and $g = 4 \bmod P$ generates the prime-order subgroup $\mathbb{G}_q$ of order $q$. For verifier polynomial $F(x) = \sum_{j=0}^{k-1} \alpha_j x^j \bmod q$, public commitments are $C_j = g^{\alpha_j} \bmod P$. Before admitting shard $i$ with scalar $s_i = F(i) \bmod q$ into a quorum, `SecureEnclave` checks:
$$g^{s_i} \stackrel{?}{\equiv} \prod_{j=0}^{k-1} C_j^{(i^j \bmod q)} \pmod P$$

---

### 2.3 1024-bit Fixed-Point Paillier Additive Homomorphic Encryption (PHE)

With 512-bit primes $p, q$, modulus $n = p \cdot q$ ($\ge 1024$ bits), $\lambda = \operatorname{lcm}(p-1, q-1)$, $g = n + 1$, and $\mu = \lambda^{-1} \bmod n$, a fixed-point value $v$ ($m = \lfloor 100v \rceil$) is encrypted with random $r \in \mathbb{Z}_n^*$ as:
$$c = E(m) = (1 + m \cdot n) \cdot r^n \pmod{n^2}$$

Using **only public key $n$**, `HomomorphicEvaluator` computes:
$$c_{\text{sum}} = c_1 \cdot c_2 \pmod{n^2}, \qquad c_{\text{bonus}} = c_1^{p} \pmod{n^2}, \qquad c_{\text{total}} = c_1^{100 + p} \pmod{n^2}$$

---

### 2.4 Native C Lattice Ring-LWE BFV Homomorphic Encryption (Non-Linear Multiplication)

To evaluate non-linear products of **two encrypted values** $E(m_1) \otimes E(m_2)$ without secret keys, `backend/native/vaultcrypto.c` implements the **Brakerski-Fan-Vercauteren (BFV)** lattice scheme over the negacyclic cyclotomic polynomial ring:
$$R_q = \mathbb{Z}_q[X] / (X^N + 1), \quad N = 64, \quad q = 2^{60}, \quad t = 2^{16} = 65536, \quad \Delta = \lfloor q / t \rfloor = 2^{44}$$

- **Key Generation (`vault_bfv_keygen`):** Sample ternary secret $s \leftarrow \{-1, 0, 1\}^N$, uniform $a \leftarrow R_q$, error $e \leftarrow \{-1, 0, 1\}^N$, setting $\mathbf{pk} = ([-(a \cdot s + e)]_q, a)$. For gadget base $B = 2^{15}$ ($L = 4$ limbs, $B^4 = q$), publish relinearization keys encrypting $B^\ell \cdot s^2$:
  $$\mathbf{rlk}_\ell = \left( \left[ -(a_\ell \cdot s + e_\ell) + B^\ell \cdot s^2 \right]_q,\; a_\ell \right), \quad \ell \in \{0, 1, 2, 3\}$$
- **Encryption (`vault_bfv_encrypt`):** For $m \in \mathbb{Z}_t$ and ephemeral ternary $u, e_1, e_2$:
  $$\mathbf{ct} = (c_0, c_1) = \left( [\text{pk}_0 \cdot u + e_1 + \Delta m]_q,\; [\text{pk}_1 \cdot u + e_2]_q \right)$$
- **Homomorphic Multiplication & Gadget Relinearization (`vault_bfv_mul_relin`):** Compute exact 128-bit polynomial convolutions in $\mathbb{Z}[X]/(X^{64}+1)$ and scale by $t/q$:
  $$h_0 = \left\lfloor \frac{t}{q} (c_0 d_0) \right\rceil_q, \quad h_1 = \left\lfloor \frac{t}{q} (c_0 d_1 + c_1 d_0) \right\rceil_q, \quad h_2 = \left\lfloor \frac{t}{q} (c_1 d_1) \right\rceil_q$$
  Decompose $h_2 = \sum_{\ell=0}^{3} h_2^{(\ell)} B^\ell$ with signed digits $h_2^{(\ell)} \in [-B/2, B/2)$ and project degree-2 $s^2$ back to a standard 2-element ciphertext using **only $\mathbf{rlk}$**:
  $$c'_0 = \left[ h_0 + \sum_{\ell=0}^{3} h_2^{(\ell)} \cdot \text{rlk}_{\ell,0} \right]_q, \qquad c'_1 = \left[ h_1 + \sum_{\ell=0}^{3} h_2^{(\ell)} \cdot \text{rlk}_{\ell,1} \right]_q$$
- **Decryption (`vault_bfv_decrypt`):**
  $$m = \left\lfloor \frac{t}{q} \cdot [c'_0 + c'_1 \cdot s]_q \right\rceil \bmod t$$

---

## 3. Vulnerability Windows Mitigated

| Attack Vector | Mitigation in VaultMind v2 | Verified By |
| :--- | :--- | :--- |
| **Python Heap / GC Key Remnants** | Master key reconstructed strictly on C stack `uint8_t master_key[32]` and wiped via `memset_s()` + volatile memory fence. | `test_02` |
| **Cache-Timing Side Channels** | Branchless, lookup-table-free $\mathbb{F}_{2^8}$ arithmetic (`vault_gf256_mul`, `vault_gf256_inv`) + constant-time MAC check (`vault_ct_memeq`). | `vaultcrypto.c`, `test_01` |
| **Byzantine / Corrupted Disk Shards** | 2048-bit Feldman VSS rejects forged shares before reconstruction; automatic $k=3$ of $n=5$ quorum failover. | `test_03` |
| **Arbitrary Password & Key Leaks** | Scrubs `<secret>...</secret>`, free-text passwords/PINs, JWTs, API keys & raw hex keys; seals in C AES-256 (`SessionSecretVault`). | `test_08` |
| **Non-Linear Encrypted Compute** | Native C Lattice RLWE-BFV evaluates $E(m_1) \otimes E(m_2)$ with 4-limb relinearization without secret keys. | `test_07`, `test_09` |
| **Database Tampering & DOM XSS** | SQLite Encrypt-then-MAC HMAC-SHA256 verification (`vault_enclave_unseal`) + strict `escapeHtml` / `textContent` UI rendering. | `test_05`, `test_06` |

---

## 4. Repository Architecture & Quickstart

```text
vaultmind/
├── frontend/      # Loopback Web Dashboard (index.html, app.js, style.css) & Rich TUI (tui.py)
├── backend/       # Native C Core (vaultcrypto.c) & Crypto Primitives (Shamir, Paillier PHE, RLWE-BFV FHE, Blinder)
├── database/      # Encrypted SQLite Ledger (schema.sql, ledger.py) & isolated runtime shards
├── apis/          # FastAPI REST Routes (routes.py) & Cloud LLM Adapters (Gemini 2.5 / OpenAI / AWS Bedrock)
├── services/      # Zero-Knowledge Pipeline & 2048-bit Feldman VSS Enclave Orchestration
├── monitoring/    # Real-time Security & Cryptographic Latency Telemetry (telemetry.py)
└── tests/         # 9-Part Automated Cryptographic & Security Audit Suite
```

```bash
cd /Users/sem/.gemini/antigravity/scratch/vaultmind
source venv/bin/activate

# 1. Optional: Configure Live Cloud Host API Key (Gemini / OpenAI / AWS Bedrock)
cp .env.example .env
# Add GEMINI_API_KEY=... (or OPENAI_API_KEY / AWS_BEARER_TOKEN_BEDROCK) in .env

# 2. Compile Native C Cryptographic & Lattice FHE Library (clang)
python3 backend/native/build.py

# 3. Run Full 9-Test Cryptographic & Security Audit Suite
python3 -m unittest tests/test_security_audit.py -v

# 4A. Start Loopback Web Dashboard (http://127.0.0.1:8000)
python3 main.py

# 4B. Or Launch Rich Terminal User Interface (TUI)
python3 frontend/tui.py
```
