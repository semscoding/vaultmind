# VaultMind v2: Demo Video Script (about 2:45)

> **Track:** AI Pipeline Secret Sharing Track
> **Rule for the voice-over:** say only what the screen shows at that moment. If a live run does not produce the banner or receipt mentioned below, re-run or cut; do not narrate it anyway.
> All button labels, preset names and panel titles below are copied from `frontend/static/index.html` and `frontend/static/app.js`. The interface has no emoji in buttons or presets; with the offline engine the payload panel reads **Local only: nothing left this machine**.

## Before recording

1. `cp .env.example .env` and fill in `GEMINI_API_KEY` (or `OPENAI_API_KEY` / `AWS_BEARER_TOKEN_BEDROCK`). Never show `.env` on screen.
2. Do at least ten successful live runs with the presets before recording. If the live provider fails, record with **Offline Deterministic Engine (nothing leaves this machine)** and say so on screen.
3. Start the server: `python3 main.py`, open `http://127.0.0.1:8000`.
4. Click **↺ Restore Shards** so all five nodes show **Verified**.
5. Have a terminal ready in the repo root with the venv active, and an editor open on `backend/native/vaultcrypto.c`.

---

## Scene 1: Intro (0:00 – 0:20)

**On screen:** the dashboard. Header dropdown **LLM Host** shows **Google Gemini 2.5 Flash (Live API)** (selected automatically when a key is in `.env`). Telemetry bar: **Reconstructed master key** · *C stack only · wiped after each seal*, **Verifiable secret sharing** · *k=3 of n=5 (2048-bit Feldman VSS)*, **Key zeroization** · *C11 memset_s() + CommonCrypto*.

**Say:**
> "This is VaultMind, for the AI Pipeline Secret Sharing track. A cloud LLM plans actions on enterprise prompts, but it only ever sees tokens. The master key is split over five shard files with Shamir secret sharing and Feldman VSS, and it is only ever reconstructed inside a small C library, on the C stack."

---

## Scene 2: Blinded prompt and the real request (0:20 – 1:00)

**On screen:**
1. Click the preset **15% Bonus Paillier PHE & DB Seal**, then **Execute Zero-Trust Pipeline**.
2. Middle column **EXTERNAL CLOUD WIRE · What Host Provider (Gemini/OpenAI/Bedrock) Sees**: zoom into **Transmitted payload**. It shows `POST https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent`, the headers with `x-goog-api-key: <redacted>`, and the JSON body with `systemInstruction` and the blinded prompt.
3. Point at the leak-check verdict next to the heading (**✔ 0 residual matches (heuristic)**) and at the token map below it (`[ID_…] ⟷ "Marcus Vance"`, `[FHE_NUM_1] … "$130,000" → 2048-bit PHE`).
4. If the blue formula box appears in the left column, point at it: `c_bonus = [FHE_NUM_1]^15 mod n², c_total = [FHE_NUM_1]^115 mod n²` and the left column output with **$19,500.00** and **$149,500.00**.
5. In the same blue box, point at the line under the formula: `Evaluated by: untrusted evaluator process (pid …; holds only n)`. If it reads `in-process fallback` with a warning instead, re-run or cut; do not narrate the process separation for that run.

**Say:**
> "This panel is the exact request body that went to Gemini, without the API key. The name became an HMAC token, the salary became a Paillier ciphertext handle, and a leak check confirms that none of the detected values is still in the payload. Gemini only answers with a plan: a fifteen percent bonus on FHE_NUM_1. The bonus is computed on the ciphertext with only the public key, and decrypted locally."
> "That computation ran in a separate local process that only received the public modulus n and the ciphertext, never the secret key."

---

## Scene 3: Leveled BFV product and sealed password (1:00 – 1:25)

**On screen:**
1. Click **RLWE-BFV Product & Password Seal**, then **Execute Zero-Trust Pipeline**.
2. Show in the payload: `[FHE_NUM_1](ENC:0x…)`, `[FHE_NUM_2](ENC:0x…)`, `password is [SECRET_…]`, `seed: [SECRET_…]`.
3. If the blue formula box appears: `c_prod = Relin(round((t/q) · ([FHE_NUM_1] ⊗ [FHE_NUM_2]))) in R_q (N=2048)` and **$36,000**; the line under it reads `Evaluated by: untrusted evaluator process (pid …; holds only rlk)`.
4. Optional: in the playground at the bottom click **C RLWE-BFV Product (in R_q)** with m₁ = 160, m₂ = 225.

**Say:**
> "The password and the tagged seed are sealed with AES-256 and HMAC inside the C library before anything is sent. Hours times rate is a ciphertext-times-ciphertext product in leveled BFV, depth one, with N equals 2048 and a 54-bit modulus. The cloud picks the operation; a separate local process that holds only the public relinearisation key evaluates the product, and the main process decrypts it."

---

## Scene 4: Typing a prompt live (1:25 – 1:40)

**On screen:** clear the prompt box and type, for example:
`Pay vendor Acronis Corp 4,250 EUR to IBAN NL91 ABNA 0417 1643 00, approval code <secret>blue-otter-42</secret>.`
Run it. Show `[ID_…]`, `[FHE_NUM_1]`, `[IBAN_…]`, `[SECRET_…]` in the payload and the leak-check verdict.

**Say:**
> "Blinding uses patterns and a bundled list of names and places, so a secret without a label goes in a secret tag. Everything detected is replaced, and the leak check is computed on every run."

(Rehearse this exact prompt before recording; if the verdict shows a residual match, use a different prompt.)

---

## Scene 5: Corrupted shards, failover and refusal (1:40 – 2:15)

**On screen:**
1. Right column **NATIVE C ENCLAVE & FELDMAN VSS**: click **Corrupt** on node-02. The row shows a red cross, the node name is struck through and the state reads **Rejected**; a red cross also leaves the GF(2⁸) curve.
2. Run the bonus preset again. The receipt shows the row **Rejected** `vault-node-02 (Feldman VSS failed)` and the row **Quorum** `vault-node-01, vault-node-03, vault-node-04`.
3. Click **Corrupt** on node-01 and node-03 as well (three shards broken). Run again. The receipt shows **Enclave blocked the write** with `Threshold Quorum Failed: Only 2 valid shards available (need k=3)`.
4. Click **↺ Restore Shards**, then **Verify HMACs in C Enclave**: the ledger banner and the table rows show **✔ VALID**.

**Say:**
> "Each shard is checked against public Feldman commitments in a 2048-bit group. One corrupted shard is rejected and the enclave uses another quorum. With three of five broken, fewer than three valid shards remain, and the enclave refuses to seal anything. Every sealed row is chained to the previous one, and verification runs over the whole chain."

---

## Scene 6: The C code and the binary (2:15 – 2:30)

**On screen (about ten seconds of code):**
1. `vaultcrypto.c`: `vault_gf256_mul` (fixed loop, masks, no tables).
2. The `cleanup:` block of `vault_enclave_seal` with the `vault_secure_wipe` calls, and `vault_secure_wipe` calling `memset_s`.
3. Terminal: `nm -u backend/native/libvaultcrypto.dylib | grep memset_s` → `_memset_s`.

**Say:**
> "Field arithmetic is branch-free and table-free. The reconstructed key and its subkeys are wiped with memset_s on every exit path, and the binary really links memset_s. The GF(2⁸) shares are read from their files by the C library itself; only the Feldman half passes through Python, and the reconstructed key never does."

---

## Scene 7: Tests and close (2:30 – 2:45)

**On screen:** terminal: `python3 -m unittest discover -s tests -v`, scroll to `Ran 91 tests` and `OK`.

**Say:**
> "Ninety-one tests cover the field arithmetic, uniform sharing, canonical AAD and length framing, shard failover, C-only share files, the separate evaluator process, concurrent ledger writes, BFV at depth one, provider errors, name and address blinding, prose false-positive guards and the leak check. The known limitations are listed in the README. Thanks for watching."
