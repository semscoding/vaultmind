# VaultMind v2: Native C Enclave, Dual-Field Verifiable Secret Sharing & 128-bit Lattice FHE AI Pipeline

> **Hackathon:** Mathematics for Systems Security  
> **Track:** AI Pipeline Secret Sharing Track  
> **Stack:** Python 3 (FastAPI Web Loopback, Rich TUI & Cloud LLM Orchestration) + **Compiled Native C11 (`libvaultcrypto.dylib`)** via `clang` & Apple CommonCrypto.

---

## 1. Problem & Zero-Trust Architecture

Giving host-provider LLM APIs (**Google Gemini 2.5 Flash**, **OpenAI GPT-4o-mini**, **AWS Bedrock**) direct access to enterprise prompts and privileged credentials creates two critical attack surfaces:
1. **Plaintext Cloud Exposure:** Sensitive PII, banking IBANs, government IDs (BSN/SSN), passwords, raw keys, and financial numbers are transmitted to and potentially retained on host-provider servers.
2. **Master Key Compromise:** Storing database or signing master keys in Python/agent memory exposes them to prompt injection, garbage-collector heap remnants, and unauthorized tool execution.

**VaultMind v2** eliminates both surfaces mathematically and architecturally:
- **Zero-Retention Arbitrary Secret & PII Blinding + C AES-256 Session Sealing:** Explicit `<secret>...</secret>` spans, free-text passwords/passphrases/PINs, compound key phrases (`secret key is ...`, `api_key=...`), Bearer/JWT tokens, raw 128/256-bit hex keys, IBANs, BSN/SSNs, emails, and international/Dutch names (`Jan van Dijk`, `Maria de Vries`, `O'Connor`, `Jean-Luc Picard`) are scrubbed before any API call. All `[SECRET_XXXX]` tokens are immediately sealed in C memory via **AES-256-CBC + HMAC-SHA256** (`vault_session_seal`) — never kept in plaintext Python dictionaries (neither keys nor values) and redacted from JSON audit logs.
- **Dual Homomorphic Encryption (1024-bit Paillier PHE + 128-bit Lattice Security RLWE-BFV FHE):**
  - **1024-bit Fixed-Point Paillier PHE** ($\mathbb{Z}_{n^2}^*$) evaluates blind financial sums and public percentage policy scalars ($c^k \bmod n^2$) with exact 2-decimal precision.
  - **Compiled C Ring-LWE Brakerski-Fan-Vercauteren (BFV) FHE** parameterized per the **HomomorphicEncryption.org 128-bit Lattice Security Standard (Table 1)** over $R_q = \mathbb{Z}_{2^{54}}[X]/(X^{2048}+1)$ evaluates **both** homomorphic addition $E(m_1) \oplus E(m_2)$ **and** non-linear ciphertext $\times$ ciphertext multiplication $E(m_1) \otimes E(m_2)$ with **4-limb gadget relinearization**, unbiased rejection sampling, and overflow-free base-256 limb decomposition for arbitrary 32-bit products.
- **Dual-Field 2048-bit Feldman VSS & Native C Enclave (`libvaultcrypto.dylib`):** Reconstructing the 256-bit Master Key mathematically requires **both** a threshold quorum ($k=3$ of $n=5$) of constant-time $\mathbb{F}_{2^8}$ shares on the C stack **and** a threshold quorum of RFC 3526 Group 14 (2048-bit safe prime) Feldman-verified $\mathbb{Z}_q$ shares ($K_{\text{master}} = \text{HMAC-SHA256}(K_{\mathbb{F}_{2^8}}, \text{SHA256}(\alpha_0))$), followed by **C11 `memset_s()`** stack zeroization — **zero bytes of the Master Key ever enter Python RAM**. *(Note: for live hackathon demonstration, `enclave_service.py` keeps a local loopback `.demo_clean_shards` snapshot solely to power the UI `"↺ Restore Shards"` reset button after demonstrating Byzantine shard corruption.)*

---

## 2. Mathematical Foundations

### 2.1 Constant-Time Shamir Secret Sharing over $\mathbb{F}_{2^8}$ (Native C)

Each byte $s \in \mathbb{F}_{2^8} \cong \mathbb{F}_2[x] / (x^8 + x^4 + x^3 + x + 1)$ of the 32-byte C-stack share $K_{\mathbb{F}_{2^8}}$ is split via a degree-$(k-1)$ polynomial:
$$f(x) = a_0 \oplus a_1 x \oplus a_2 x^2 \oplus \dots \oplus a_{k-1} x^{k-1} \in \mathbb{F}_{2^8}[x], \quad a_0 = s$$

To prevent cache-timing and branch-prediction side channels in `backend/native/vaultcrypto.c`:
1. **Table-Free Multiplication (`vault_gf256_mul`):** Fixed 8-iteration loop using arithmetic bitmasks `-(int8_t)(b & 1)` with reduction polynomial `0x1B` — zero lookup tables and zero secret-dependent branches.
2. **Branchless Multiplicative Inverse (`vault_gf256_inv`):** By Fermat's Little Theorem in $\mathbb{F}_{2^8}^*$, $a^{255} = 1$:
   $$a^{-1} = a^{254} = a^2 \cdot a^4 \cdot a^8 \cdot a^{16} \cdot a^{32} \cdot a^{64} \cdot a^{128}$$
3. **Lagrange Interpolation at $x = 0$:** Since $-x_m = x_m$ and $x_j - x_m = x_j \oplus x_m$ in characteristic $2$:
   $$s = f(0) = \bigoplus_{j=1}^{k} y_j \otimes \left( \bigotimes_{\substack{m=1 \\ m \neq j}}^{k} x_m \otimes (x_j \oplus x_m)^{-1} \right)$$

---

### 2.2 Dual-Field Key Derivation & 2048-bit Feldman VSS

Let $P = 2q + 1$ be the 2048-bit safe prime from RFC 3526 Group 14, where $q = (P-1)/2$ is prime and $g = 4 \bmod P$ generates the prime-order subgroup $\mathbb{G}_q$ of order $q$. For polynomial $F(x) = \sum_{j=0}^{k-1} \alpha_j x^j \bmod q$, public commitments are $C_j = g^{\alpha_j} \bmod P$. Before admitting shard $i$ with scalar $s_i = F(i) \bmod q$ into a quorum, `SecureEnclave` checks:
$$g^{s_i} \stackrel{?}{\equiv} \prod_{j=0}^{k-1} C_j^{(i^j \bmod q)} \pmod P$$

Inside `vault_enclave_seal` / `vault_enclave_unseal`, the effective 256-bit Master Key is derived strictly on the C stack by cryptographically binding both threshold reconstructions:
$$K_{\text{master}} = \operatorname{HMAC-SHA256}\!\left(K_{\mathbb{F}_{2^8}},\; \operatorname{SHA256}(\alpha_0)\right)$$

---

### 2.3 1024-bit Fixed-Point Paillier Additive Homomorphic Encryption (PHE)

With 512-bit primes $p, q$, modulus $n = p \cdot q$ ($\ge 1024$ bits), $\lambda = \operatorname{lcm}(p-1, q-1)$, $g = n + 1$, and $\mu = \lambda^{-1} \bmod n$, a fixed-point value $v$ ($m = \lfloor 100v \rceil$) is encrypted with random $r \in \mathbb{Z}_n^*$ as:
$$c = E(m) = (1 + m \cdot n) \cdot r^n \pmod{n^2}$$

Using **only public key $n$**, `HomomorphicEvaluator` computes:
$$c_{\text{sum}} = c_1 \cdot c_2 \pmod{n^2}, \qquad c_{\text{bonus}} = c_1^{p} \pmod{n^2}, \qquad c_{\text{total}} = c_1^{100 + p} \pmod{n^2}$$

---

### 2.4 128-bit Lattice Security Ring-LWE BFV Homomorphic Encryption (Native C)

To evaluate non-linear products of **two encrypted values** $E(m_1) \otimes E(m_2)$ without secret keys, `backend/native/vaultcrypto.c` implements **Brakerski-Fan-Vercauteren (BFV)** over the HomomorphicEncryption.org 128-bit standard cyclotomic polynomial ring:
$$R_q = \mathbb{Z}_q[X] / (X^N + 1), \quad N = 2048, \quad q = 2^{54}, \quad t = 2^{16} = 65536, \quad \Delta = \lfloor q / t \rfloor = 2^{38}$$

- **Key Generation (`vault_bfv_keygen`):** Sample unbiased rejection-sampled ternary secret $s \leftarrow \{-1, 0, 1\}^N$, uniform $a \leftarrow R_q$, error $e \leftarrow \{-1, 0, 1\}^N$, setting $\mathbf{pk} = ([-(a \cdot s + e)]_q, a)$. For gadget base $B = 2^{14}$ ($L = 4$ limbs, $B^4 = 2^{56} > q$), publish relinearization keys encrypting $B^\ell \cdot s^2$:
  $$\mathbf{rlk}_\ell = \left( \left[ -(a_\ell \cdot s + e_\ell) + B^\ell \cdot s^2 \right]_q,\; a_\ell \right), \quad \ell \in \{0, 1, 2, 3\}$$
- **Homomorphic Multiplication & Gadget Relinearization (`vault_bfv_mul_relin`):** Compute exact 128-bit negacyclic convolutions in $\mathbb{Z}[X]/(X^{2048}+1)$ and scale by $t/q$:
  $$h_0 = \left\lfloor \frac{t}{q} (c_0 d_0) \right\rceil_q, \quad h_1 = \left\lfloor \frac{t}{q} (c_0 d_1 + c_1 d_0) \right\rceil_q, \quad h_2 = \left\lfloor \frac{t}{q} (c_1 d_1) \right\rceil_q$$
  Decompose $h_2 = \sum_{\ell=0}^{3} h_2^{(\ell)} B^\ell$ with signed digits $h_2^{(\ell)} \in [-B/2, B/2)$ and project $s^2$ back to a 2-element ciphertext using **only $\mathbf{rlk}$**:
  $$c'_0 = \left[ h_0 + \sum_{\ell=0}^{3} h_2^{(\ell)} \cdot \text{rlk}_{\ell,0} \right]_q, \qquad c'_1 = \left[ h_1 + \sum_{\ell=0}^{3} h_2^{(\ell)} \cdot \text{rlk}_{\ell,1} \right]_q$$
- **Overflow-Free 32-bit Multi-Limb Evaluation (`BFVEvaluator.multiply_limbs`):** Unsigned integers $A = \sum_i a_i 256^i$ and $B = \sum_j b_j 256^j$ ($a_i, b_j \in [0, 255]$) satisfy $a_i b_j \le 65{,}025 < t = 65{,}536$, guaranteeing exact 32-bit homomorphic multiplication without modular wraparound.

---

## 3. Vulnerability Windows Mitigated

| Attack Vector | Mitigation in VaultMind v2 | Verified By |
| :--- | :--- | :--- |
| **Python Heap / GC Key Remnants** | Dual-field Master Key reconstructed strictly on C stack `uint8_t combined_master[32]` and wiped via `memset_s()` + volatile fence. | `test_02`, `ASan/UBSan` |
| **Cache-Timing Side Channels** | Branchless, lookup-table-free $\mathbb{F}_{2^8}$ arithmetic (`vault_gf256_mul`, `vault_gf256_inv`) + constant-time MAC check (`vault_ct_memeq`). | `vaultcrypto.c`, `test_01` |
| **Byzantine / Corrupted Disk Shards** | Dual-field 2048-bit Feldman VSS ($\mathbb{Z}_q$) + $\mathbb{F}_{2^8}$ commitment rejects forged shares; automatic $k=3$ of $n=5$ failover. | `test_03`, `test_10` |
| **Secret Retention in Dicts / Logs** | `<secret>...</secret>`, passwords, compound key phrases, JWTs & hex keys sealed in C AES-256 (`SessionSecretVault`) — zero dict keys/values or JSON echoes. | `test_08`, `test_10` |
| **128-bit Lattice Non-Linear Compute** | $N=2048, q=2^{54}$ Ring-LWE BFV evaluates $E(m_1) \otimes E(m_2)$ with base-256 limbs (zero $\bmod 65536$ overflow). | `test_07`, `test_09`, `test_10` |
| **Database Tampering & DOM XSS** | SQLite Encrypt-then-MAC HMAC-SHA256 verification (`vault_enclave_unseal`) + strict `escapeHtml` / `textContent` UI rendering. | `test_05`, `test_06` |

---

## 4. Repository Architecture & Quickstart

```text
vaultmind/
├── frontend/      # Loopback Web Dashboard (index.html, app.js, style.css) & Rich TUI (tui.py)
├── backend/       # Native C Core (vaultcrypto.c) & Crypto Primitives (Shamir/VSS, Paillier PHE, N=2048 BFV FHE, Blinder)
├── database/      # Encrypted SQLite Ledger (schema.sql, ledger.py) & isolated runtime shards
├── apis/          # FastAPI REST Routes (routes.py) & Cloud LLM Adapters (Gemini 2.5 / OpenAI / AWS Bedrock)
├── services/      # Zero-Knowledge Pipeline & Dual-Field 2048-bit Feldman VSS Enclave Orchestration
├── monitoring/    # Real-time Security & Cryptographic Latency Telemetry (telemetry.py)
└── tests/         # 10-Part Automated Cryptographic & Red-Team Audit Suite
```

```bash
cd /Users/sem/.gemini/antigravity/scratch/vaultmind
source venv/bin/activate

# 1. Optional: Configure Live Cloud Host API Key (Gemini / OpenAI / AWS Bedrock)
cp .env.example .env

# 2. Compile Native C Cryptographic & N=2048 Lattice FHE Library (clang)
python3 backend/native/build.py

# 3. Run Full 10-Test Cryptographic & Red-Team Security Audit Suite
python3 -m unittest tests/test_security_audit.py -v

# 4A. Start Loopback Web Dashboard (http://127.0.0.1:8000)
python3 main.py

# 4B. Or Launch Rich Terminal User Interface (TUI)
python3 frontend/tui.py
```
