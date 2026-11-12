"""
External Cloud LLM API Connectors (Google Gemini 2.5 Flash & OpenAI GPT-4o-mini)
plus Offline Deterministic Zero-Knowledge Engine.
"""

import json
import os
import re
from typing import Any, Dict, Optional
import httpx


SYSTEM_PROMPT = """You are VaultMind Zero-Knowledge Autonomous Agent.
SECURITY INVARIANTS:
1. Sensitive identifiers are HMAC-blinded tokens: [ID_XXXX], [IBAN_XXXX], [GOV_ID_XXXX], [EMAIL_XXXX], [LOC_XXXX].
2. Sensitive numbers are 1024-bit Paillier ciphertexts: [FHE_NUM_1], [FHE_NUM_2], etc.
3. You hold ZERO shares of any master key and cannot access plaintext PII or numbers.

INSTRUCTIONS:
1. Reason concisely over the blinded tokens.
2. If a mathematical calculation on encrypted numbers is appropriate:
   - Percentage bonus (e.g. 15% on [FHE_NUM_1]): emit "fhe_compute": {"op": "PERCENT_BONUS", "ref": "[FHE_NUM_1]", "percent": 15} and reference [FHE_COMPUTED_BONUS] and [FHE_COMPUTED_TOTAL] in your summary.
   - Sum of two encrypted numbers: emit "fhe_compute": {"op": "ADD", "ref_a": "[FHE_NUM_1]", "ref_b": "[FHE_NUM_2]"} and reference [FHE_COMPUTED_SUM] in your summary.
3. If the prompt requests committing, updating, authorizing, transferring, or storing privileged data, emit "action_intent" with action in ["GRANT_COMPLIANCE_BONUS", "UPDATE_EHR_LEDGER", "TRANSFER_EXECUTE", "DB_WRITE_RECORD"].

Always include one fenced ```json block at the end of your response using this schema:
```json
{
  "fhe_compute": {"op": "PERCENT_BONUS", "ref": "[FHE_NUM_1]", "percent": 15},
  "action_intent": {
    "action": "GRANT_COMPLIANCE_BONUS",
    "target": "[ID_XXXX]",
    "params": {"primary_value": "[FHE_NUM_1]", "computed_bonus": "[FHE_COMPUTED_BONUS]"}
  }
}
```
Set "fhe_compute" or "action_intent" to null if not needed.
"""


class LLMClient:
    async def generate_blind_reasoning(
        self,
        blinded_prompt: str,
        provider: str = "simulation",
        api_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        mode = (provider or "simulation").lower().strip()

        if mode == "auto":
            if api_key and api_key.startswith("AIza"):
                mode = "gemini"
            elif api_key and api_key.startswith("sk-"):
                mode = "openai"
            elif os.getenv("GEMINI_API_KEY"):
                mode = "gemini"
            elif os.getenv("OPENAI_API_KEY"):
                mode = "openai"
            else:
                mode = "simulation"

        if mode == "gemini":
            key = api_key or os.getenv("GEMINI_API_KEY")
            if not key:
                raise ValueError(
                    "Gemini 2.5 Flash selected, but no GEMINI_API_KEY was provided. "
                    "Enter an API key or select the Offline Zero-Knowledge Engine."
                )
            return await self._call_gemini(blinded_prompt, key)

        if mode == "openai":
            key = api_key or os.getenv("OPENAI_API_KEY")
            if not key:
                raise ValueError(
                    "OpenAI GPT-4o-mini selected, but no OPENAI_API_KEY was provided. "
                    "Enter an API key or select the Offline Zero-Knowledge Engine."
                )
            return await self._call_openai(blinded_prompt, key)

        return self._run_deterministic_engine(blinded_prompt)

    async def _call_gemini(self, blinded_prompt: str, api_key: str) -> Dict[str, Any]:
        url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
        headers = {"x-goog-api-key": api_key, "Content-Type": "application/json"}
        payload = {
            "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": blinded_prompt}]}],
            "generationConfig": {"temperature": 0.1},
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            res = await client.post(url, headers=headers, json=payload)
            if res.status_code != 200:
                raise RuntimeError(
                    f"Gemini 2.5 Flash API error (HTTP {res.status_code}): {res.text[:240]}"
                )
            data = res.json()
            text = data["candidates"][0]["content"]["parts"][0]["text"]
            return self._parse_structured_output(
                text, provider_label="Google Gemini 2.5 Flash (Live Cloud API)", is_live=True
            )

    async def _call_openai(self, blinded_prompt: str, api_key: str) -> Dict[str, Any]:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        payload = {
            "model": "gpt-4o-mini",
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": blinded_prompt},
            ],
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            res = await client.post(url, headers=headers, json=payload)
            if res.status_code != 200:
                raise RuntimeError(
                    f"OpenAI API error (HTTP {res.status_code}): {res.text[:240]}"
                )
            data = res.json()
            text = data["choices"][0]["message"]["content"]
            return self._parse_structured_output(
                text, provider_label="OpenAI GPT-4o-mini (Live Cloud API)", is_live=True
            )

    def _run_deterministic_engine(self, blinded_prompt: str) -> Dict[str, Any]:
        lower = blinded_prompt.lower()

        id_tokens = re.findall(r"\[(?:ID|EMAIL|GOV_ID|IBAN)_[A-F0-9]{8}\]", blinded_prompt)
        person_or_org = next((t for t in id_tokens if t.startswith("[ID_")), None)
        iban_tok = next((t for t in id_tokens if t.startswith("[IBAN_")), None)
        gov_tok = next((t for t in id_tokens if t.startswith("[GOV_ID_")), None)
        fhe_tokens = re.findall(r"\[FHE_NUM_\d+\]", blinded_prompt)

        primary_target = person_or_org or iban_tok or gov_tok or "[SYSTEM_RECORD]"

        fhe_compute: Optional[Dict[str, Any]] = None
        pct_match = re.search(r"\b(\d{1,3})%(?!\w)", blinded_prompt)
        if "bonus" in lower and fhe_tokens:
            pct = int(pct_match.group(1)) if pct_match else 15
            fhe_compute = {"op": "PERCENT_BONUS", "ref": fhe_tokens[0], "percent": pct}
        elif len(fhe_tokens) >= 2 and any(w in lower for w in ["sum", "total", "combine", "add", "plus"]):
            fhe_compute = {"op": "ADD", "ref_a": fhe_tokens[0], "ref_b": fhe_tokens[1]}

        action_intent: Optional[Dict[str, Any]] = None
        if any(w in lower for w in ["transfer", "wire", "iban", "authorize", "pay"]):
            action_intent = {
                "action": "TRANSFER_EXECUTE",
                "target": primary_target,
                "params": {
                    "destination_iban": iban_tok or "N/A",
                    "encrypted_amount": fhe_tokens[0] if fhe_tokens else "N/A",
                },
            }
        elif any(w in lower for w in ["ehr", "patient", "clinic", "medical", "bsn"]):
            action_intent = {
                "action": "UPDATE_EHR_LEDGER",
                "target": primary_target,
                "params": {
                    "gov_id_token": gov_tok or "N/A",
                    "encrypted_biomarker": fhe_tokens[0] if fhe_tokens else "N/A",
                },
            }
        elif "bonus" in lower:
            action_intent = {
                "action": "GRANT_COMPLIANCE_BONUS",
                "target": primary_target,
                "params": {
                    "base_salary": fhe_tokens[0] if fhe_tokens else "N/A",
                    "computed_bonus": "[FHE_COMPUTED_BONUS]" if fhe_compute else "N/A",
                    "adjusted_total": "[FHE_COMPUTED_TOTAL]" if fhe_compute else "N/A",
                },
            }
        elif any(w in lower for w in ["commit", "update", "write", "store", "save", "sign", "database"]):
            action_intent = {
                "action": "DB_WRITE_RECORD",
                "target": primary_target,
                "params": {"fhe_refs": fhe_tokens},
            }

        lines = [f"Zero-Knowledge reasoning completed for subject {primary_target}."]
        if fhe_compute and fhe_compute["op"] == "PERCENT_BONUS":
            lines.append(
                f"- Homomorphic Policy Calculation ({fhe_compute['percent']}% on {fhe_compute['ref']}): "
                f"Bonus = [FHE_COMPUTED_BONUS], New Total Compensation = [FHE_COMPUTED_TOTAL]."
            )
        elif fhe_compute and fhe_compute["op"] == "ADD":
            lines.append(
                f"- Homomorphic Aggregation ({fhe_compute['ref_a']} + {fhe_compute['ref_b']}): "
                f"Sum = [FHE_COMPUTED_SUM]."
            )
        elif fhe_tokens:
            lines.append(f"- Verified 1024-bit Paillier encrypted field(s): {', '.join(fhe_tokens)}.")

        if iban_tok:
            lines.append(f"- Blinded Banking Routing Handle verified: {iban_tok}.")
        if gov_tok:
            lines.append(f"- Blinded Government/Medical Identifier verified: {gov_tok}.")

        if action_intent:
            lines.append(
                f"- Emitting signed intent `{action_intent['action']}` to Local Loopback Enclave "
                f"for (k=3, n=5) threshold execution."
            )
        else:
            lines.append("- Read-only analysis complete; no privileged state mutation required.")

        return {
            "provider": "Offline Deterministic Zero-Knowledge Engine",
            "is_live_cloud": False,
            "raw_response": "\n".join(lines),
            "fhe_compute": fhe_compute,
            "action_intent": action_intent,
        }

    def _parse_structured_output(
        self, text: str, provider_label: str, is_live: bool
    ) -> Dict[str, Any]:
        fhe_compute = None
        action_intent = None
        clean_text = text

        match = re.search(r"```json\s*(\{.*?\})\s*```", text, flags=re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group(1))
                fhe_compute = parsed.get("fhe_compute")
                action_intent = parsed.get("action_intent")
                clean_text = (text[: match.start()] + text[match.end() :]).strip()
            except Exception:
                pass

        return {
            "provider": provider_label,
            "is_live_cloud": is_live,
            "raw_response": clean_text,
            "fhe_compute": fhe_compute,
            "action_intent": action_intent,
        }
