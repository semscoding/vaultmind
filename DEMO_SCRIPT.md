# VaultMind v2: Demo Video Script (about 2:45)

> **Hackathon:** Mathematics for Systems Security
> **Track:** AI Pipeline Secret Sharing Track
> **Rule for the voice-over:** say only what the screen shows at that moment. If a live run does not produce the blue formula banner or the enclave receipt mentioned below, re-run or cut; do not narrate it anyway.
> All button labels, preset names and panel titles below match `frontend/static/index.html` and `frontend/static/app.js` on `main` @ `7d9a1b9`.

## Before recording

1. Ensure `ANTHROPIC_API_KEY` is set in `.env` (git-ignored). Never open, print, or show `.env` or terminal history containing keys on screen.
2. Start the server if not already running (`./venv/bin/python3 main.py`) and open `http://127.0.0.1:8000` in a `1920×1080` browser window with notifications muted. Verify **LLM Host** automatically selects **Anthropic Claude (Live API)** and the key field placeholder reads `✔ ANTHROPIC key loaded from .env` (clipped to `.e` in the narrow box; value stays empty).
3. Click **↺ Restore Shards** and reload `http://127.0.0.1:8000` once so all five nodes (`node-01`..`node-05`) show **Verified**, the telemetry bar shows `k=3 of n=5 (5 VSS Valid)`, and all output panels show their clean initial state.
4. Keep an editor open on `backend/native/vaultcrypto.c` (ready at lines `69–104` for `vault_secure_wipe` + `vault_gf256_mul`, and line `358` for `cleanup:` in `vault_enclave_seal`), and a clean terminal in `/Users/sem/.gemini/antigravity/scratch/vaultmind` with `./venv` ready.

---

## Scene 1: Intro (0:00 – 0:20)

**On screen:** `http://127.0.0.1:8000` at `1920×1080`. Header badge `127.0.0.1:8000 · libvaultcrypto.dylib ACTIVE`; dropdown **LLM Host** shows **Anthropic Claude (Live API)**. Telemetry bar: **Reconstructed master key** · `C stack only · wiped after each seal`, **Verifiable secret sharing** · `k=3 of n=5 (5 VSS Valid)`, **Homomorphic crypto** · `Paillier PHE + RLWE-BFV (leveled, depth 1)`, **Key zeroization** · `C11 memset_s() + CommonCrypto`. All five shards in the right column show **Verified**.

**Say:**
> "This is VaultMind, built for the AI Pipeline Secret Sharing track of the Mathematics for Systems Security hackathon. A cloud LLM plans actions on enterprise prompts, while only ever seeing blinded tokens. The master key is split across five shard files with Shamir secret sharing and Feldman VSS, and is only ever reconstructed on the C stack."

---

## Scene 2: Blinded prompt and the real Anthropic request (0:20 – 1:00)

**On screen:**
1. Click the preset **15% Bonus Paillier PHE & DB Seal**, then click **Execute Zero-Trust Pipeline** (~3 s live call).
2. In the middle column (**EXTERNAL CLOUD WIRE** · **What the Host Provider Sees**), point at **Transmitted payload**:
   - `POST https://api.anthropic.com/v1/messages`
   - `x-api-key: <redacted>` and `anthropic-version: 2023-06-01`
   - JSON body with `model` (`"claude-haiku-5-5"`), `max_tokens`, `system`, `messages` (containing the blinded prompt with `[ID_…]`, `[FHE_NUM_1](ENC:0x…)` and `[FHE_NUM_2](ENC:0x…)`), `tools` (`emit_plan`) and `tool_choice`.
   *(If another `.env` provider is selected instead, this panel shows that provider's URL, redacted auth header and JSON body.)*
3. Point at **✔ 0 residual matches (heuristic)** (`Leak check: 3 spans blinded, 0 residual matches`) and at **Token map (kept locally)** (`[ID_…] ⟷ "Marcus Vance"`, `[FHE_NUM_1] "$130,000" → 2048-bit PHE …`).
4. In the left column, point at the blue formula banner:
   `[2048-bit Paillier PHE] c_bonus = [FHE_NUM_1]^15 mod n², c_total = [FHE_NUM_1]^115 mod n²  ⟹  [FHE_COMPUTED_BONUS] → $19,500.00  |  [FHE_COMPUTED_TOTAL] → $149,500.00`
   and the line directly underneath:
   `Evaluated by: untrusted evaluator process (pid …; holds only n)`.
   *(If `in-process fallback` or a yellow warning appears, re-run before continuing.)*
5. Point briefly at **Native C Enclave Seal Receipt** in the right column (`Status: SEALED_IN_SQLITE`, the action proposed in the receipt — `claude-haiku-5-5` chooses either `GRANT_COMPLIANCE_BONUS` or `DB_WRITE_RECORD` — and `Quorum: vault-node-01, vault-node-02, vault-node-03`, with those three nodes marked **In quorum**).

**Say:**
> "Here is a payroll prompt sent live to Anthropic Claude. The middle panel shows the exact HTTP request that left this machine, with the API key redacted. The employee name became an HMAC token, the salary became a 2048-bit Paillier ciphertext handle, and the heuristic leak check reports zero residual matches. Claude returns its plan via the `emit_plan` tool: a fifteen percent bonus on `FHE_NUM_1`, plus the ledger action shown in the receipt. A separate local process on this machine, holding only the public modulus `n`, evaluates the bonus on the ciphertext, and the main process decrypts 19,500 and 149,500 dollars."

---

## Scene 3: Leveled BFV product and sealed password (1:00 – 1:30)

**On screen:**
1. Click **RLWE-BFV Product & Password Seal**, then **Execute Zero-Trust Pipeline** (~2.5 s live call).
2. In **Transmitted payload**, point at `[FHE_NUM_1](ENC:0x…)`, `[FHE_NUM_2](ENC:0x…)`, `password is [SECRET_…]` and `seed: [SECRET_…]`. In **Token map (kept locally)**, point out that `[SECRET_…]` shows `[C-AES256 Sealed: 0x…]` — never plaintext.
3. In the left column, point at the blue formula banner:
   `[Native C RLWE-BFV (leveled, depth 1; R_q = Z_{2^54}[X]/(X^2048+1))] c_prod = Relin(round((t/q) · ([FHE_NUM_1] ⊗ [FHE_NUM_2]))) in R_q (N=2048)  ⟹  [FHE_COMPUTED_PRODUCT] → $36,000`
   and underneath:
   `Evaluated by: untrusted evaluator process (pid …; holds only rlk)`.
4. Optional (if desired, ~4 s): scroll to **Homomorphic Playground: Paillier PHE & RLWE-BFV (leveled, depth 1)** at the bottom left, enter `300` and `300` (or keep `160` and `225`), and click **C RLWE-BFV Product (in R_q)** to show `✔ D(Relin(E(300) ⊗ E(300))) = 90,000 (exact, 0 overflow)` (note: the playground runs in the main process).

**Say:**
> "In the second preset, the password and the tagged seed are sealed in C with AES-256 and HMAC before anything leaves the machine, and never enter the token map in plaintext. Hours times rate is evaluated in leveled BFV, depth one — not fully homomorphic — over degree-2048 polynomials modulo 2 to the 54. Claude selects `BFV_MULTIPLY`; the separate local evaluator process computes the relinearised product using only the public relinearisation key, and the main process decrypts 36,000 dollars."

---

## Scene 4: Typing a prompt live (1:30 – 1:50)

**On screen:**
1. Clear **Confidential prompt** and paste or type:
   `Pay vendor Acronis Corp 4,250 EUR to IBAN NL91 ABNA 0417 1643 00, approval code <secret>blue-otter-42</secret>.`
2. Click **Execute Zero-Trust Pipeline** (~2.5 s live call).
3. Point at `Pay vendor [ID_…] [FHE_NUM_1](ENC:0x…) to IBAN [IBAN_…], approval code [SECRET_…].` in **Transmitted payload** (`4,250 EUR` is absorbed together into `[FHE_NUM_1]`), and at **✔ 0 residual matches (heuristic)** (`Leak check: 4 spans blinded, 0 residual matches`).

**Say:**
> "Blinding uses patterns and bundled lists of names and places, so an unlabelled secret without a pattern goes inside a `<secret>` tag. All four spans — vendor, amount, IBAN and secret — are replaced, with zero residual matches."

---

## Scene 5: Corrupted shards, failover and refusal (1:50 – 2:20)

**On screen:**
1. In the right column (**NATIVE C ENCLAVE & FELDMAN VSS**), click **Corrupt** on `node-02`. The row gets a red cross, `node-02` is struck through, its status becomes **Rejected**, the telemetry bar updates to `k=3 of n=5 (4 VSS Valid)`, and a red cross moves off the `GF(2⁸) canary polynomial f(x) vs. disk shards` curve at `x = 2`.
2. Click **15% Bonus Paillier PHE & DB Seal**, then **Execute Zero-Trust Pipeline** (~3.2 s). Point at the receipt rows:
   - **Rejected**: `vault-node-02 (Feldman VSS failed)`
   - **Quorum**: `vault-node-01, vault-node-03, vault-node-04` (marked **In quorum**).
3. Click **Corrupt** on `node-01` and `node-03` as well (`k=3 of n=5 (2 VSS Valid)`). Click **Execute Zero-Trust Pipeline** (~3.3 s). Point at **Enclave blocked the write** (`Threshold Quorum Failed: Only 2 valid shards available (need k=3). Rejected nodes: ['vault-node-01', 'vault-node-02', 'vault-node-03']`).
4. Click **↺ Restore Shards** (all five return to **Verified**), then click **Verify HMACs in C Enclave** at the bottom right: the green banner reads `✔ C Enclave Constant-Time HMAC-SHA256 Verified across … row(s)` and every row shows **✔ VALID**.

**Say:**
> "Every shard is verified against 2048-bit Feldman commitments. Corrupting `node-02` rejects that shard, and the enclave fails over to nodes 1, 3 and 4. When three of five shards are corrupted, fewer than three valid shards remain and the enclave blocks the write. After restoring the clean demo shards, the C enclave verifies the entire hash-chained SQLite ledger."

---

## Scene 6: The C code and the binary (2:20 – 2:35)

**On screen:**
1. Switch to the editor open on `backend/native/vaultcrypto.c`:
   - Lines `69–104`: `vault_secure_wipe` calling `memset_s` (line `74`) and `vault_gf256_mul` (lines `94–104`, fixed 8-step loop with masks, no lookup tables).
   - Lines `358–364`: the `cleanup:` block of `vault_enclave_seal` wiping `gf_key`, `enc_key`, `mac_key` and `actual_id`.
2. Switch to the terminal and run:
   `nm -u backend/native/libvaultcrypto.dylib | grep memset_s` → `_memset_s`.

**Say:**
> "In `vaultcrypto.c`, `GF(2^8)` multiplication is branchless and table-free, and every exit path wipes key material with `memset_s`, which is genuinely linked into the compiled `.dylib`. C reads the `GF(2^8)` share files directly; only the Feldman half passes through Python."

---

## Scene 7: Tests and close (2:35 – 2:50)

**On screen:**
In the terminal, run `./venv/bin/python3 -m unittest discover -s tests -v` *(tip: trigger right after `nm -u` at ~2:28 so the ~19 s run finishes on screen with `Ran 102 tests` and `OK` right before 2:50)*.

**Say:**
> "One hundred and two tests cover field arithmetic, uniform sharing, AAD length framing, shard failover, C-only share files, the separate evaluator process, leveled BFV at depth one, provider error scrubbing, list-based blinding, prose guards and the leak check. All known limitations are documented in the README. Thanks for watching."
