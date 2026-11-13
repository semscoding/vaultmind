"""
External Cloud LLM API Connectors:
- Google Gemini 2.5 Flash (`GEMINI_API_KEY`)
- OpenAI GPT-4o-mini (`OPENAI_API_KEY`)
- AWS Bedrock Converse API (`AWS_BEARER_TOKEN_BEDROCK`); default model
  `amazon.nova-lite-v1:0` (Amazon Nova Lite), override with `AWS_BEDROCK_MODEL_ID`
  (e.g. a Claude model ID enabled in your Bedrock account)
- Anthropic Messages API (`ANTHROPIC_API_KEY`); default model `claude-haiku-5-5`,
  override with `ANTHROPIC_MODEL`
- Offline Deterministic Zero-Knowledge Engine (air-gapped fallback / CI testing)

Every result carries `wire_request`: the request that actually left this machine
(method, URL, headers with the credential redacted, exact JSON body incl. system prompt).
All provider failures (network, HTTP status, malformed/blocked responses) raise
`LLMProviderError`, whose message never contains the API key.

Automatically loads project-root `.env` on import without external dependencies.
"""

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple
import httpx


class LLMProviderError(RuntimeError):
    """A cloud LLM provider call failed (network, HTTP status, or unusable response)."""

    def __init__(self, message: str, wire_request: Optional[Dict[str, Any]] = None,
                 status_code: Optional[int] = None):
        super().__init__(message)
        self.wire_request = wire_request
        self.status_code = status_code


OFFLINE_WIRE_REQUEST: Dict[str, Any] = {
    "method": None,
    "url": None,
    "body": None,
    "note": "Offline deterministic engine: nothing left this machine.",
}

HTTP_TIMEOUT_SECONDS = 30.0


def load_dotenv_if_present(dotenv_path: Optional[str] = None) -> None:
    """Minimal, dependency-free `.env` loader that preserves existing environment variables."""
    if dotenv_path is None:
        dotenv_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env"))
    if not os.path.isfile(dotenv_path):
        return
    try:
        with open(dotenv_path, "r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and val and key not in os.environ:
                    os.environ[key] = val
    except OSError:
        pass


load_dotenv_if_present()


SYSTEM_PROMPT = """You are VaultMind Zero-Knowledge Autonomous Agent.
SECURITY INVARIANTS:
1. Sensitive identifiers and secrets are blinded tokens: [ID_XXXX], [IBAN_XXXX], [GOV_ID_XXXX], [EMAIL_XXXX], [LOC_XXXX], [PHONE_XXXX], [SECRET_XXXX].
2. Sensitive numbers are encrypted ciphertexts: [FHE_NUM_1], [FHE_NUM_2], etc. (Paillier additive HE + RLWE-BFV, leveled, depth 1).
3. You hold ZERO shares of any master key and cannot access plaintext PII, passwords, or numbers.

INSTRUCTIONS:
1. Reason concisely over the blinded tokens. Keep non-secret identifier tokens ([ID_XXXX], [IBAN_XXXX], [GOV_ID_XXXX], [EMAIL_XXXX], [LOC_XXXX], [PHONE_XXXX]) intact so the client can unblind them locally, but NEVER echo [SECRET_XXXX] tokens in your prose summary or action_intent.
2. If a mathematical calculation on encrypted numbers is appropriate:
   - Percentage bonus (e.g. 15% on [FHE_NUM_1]): emit "fhe_compute": {"op": "PERCENT_BONUS", "ref": "[FHE_NUM_1]", "percent": 15} and reference [FHE_COMPUTED_BONUS] and [FHE_COMPUTED_TOTAL] in your summary.
   - Sum of two encrypted numbers: emit "fhe_compute": {"op": "ADD", "ref_a": "[FHE_NUM_1]", "ref_b": "[FHE_NUM_2]"} and reference [FHE_COMPUTED_SUM] in your summary.
   - Non-linear product of two encrypted integers (e.g. hours * rate or units * price): emit "fhe_compute": {"op": "BFV_MULTIPLY", "ref_a": "[FHE_NUM_1]", "ref_b": "[FHE_NUM_2]"} and reference [FHE_COMPUTED_PRODUCT] in your summary.
3. If the prompt requests committing, updating, authorizing, transferring, or storing privileged data, emit "action_intent" with action in ["GRANT_COMPLIANCE_BONUS", "UPDATE_EHR_LEDGER", "TRANSFER_EXECUTE", "DB_WRITE_RECORD"].
   Emitting "action_intent" is a proposal, not the action itself: the local enclave validates it against its whitelist and executes it with its own key quorum. You never need a key to propose it, so always emit it when such a change is requested, even though you hold no key shares.

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


DEFAULT_ANTHROPIC_MODEL = "claude-haiku-5-5"
ANTHROPIC_PLAN_TOOL = {
    "name": "emit_plan",
    "description": (
        "Return your answer for the client: a concise summary over the blinded tokens, plus the "
        "optional homomorphic computation and the optional privileged action, exactly as specified "
        "in the system prompt. Use null for a part that is not needed."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "summary": {"type": "string", "description": "Concise reasoning over the blinded tokens."},
            "fhe_compute": {"type": ["object", "null"], "description": "Homomorphic operation or null."},
            "action_intent": {"type": ["object", "null"], "description": "Privileged action or null."},
        },
        "required": ["summary", "fhe_compute", "action_intent"],
    },
}
_MASKED_KEY_RE = re.compile(r"[A-Za-z0-9_\-]{0,24}\*{4,}[A-Za-z0-9_\-*]{0,160}")


class LLMClient:
    @staticmethod
    def get_env_config() -> Dict[str, Any]:
        """Return safe boolean availability of live host-provider API keys (never exposes key values)."""
        load_dotenv_if_present()
        has_gemini = bool(os.getenv("GEMINI_API_KEY", "").strip())
        has_openai = bool(os.getenv("OPENAI_API_KEY", "").strip())
        has_bedrock = bool(os.getenv("AWS_BEARER_TOKEN_BEDROCK", "").strip())
        has_anthropic = bool(os.getenv("ANTHROPIC_API_KEY", "").strip())

        if has_gemini:
            recommended = "gemini"
        elif has_openai:
            recommended = "openai"
        elif has_bedrock:
            recommended = "bedrock"
        elif has_anthropic:
            recommended = "anthropic"
        else:
            recommended = "simulation"

        return {
            "gemini_configured": has_gemini,
            "openai_configured": has_openai,
            "bedrock_configured": has_bedrock,
            "anthropic_configured": has_anthropic,
            "anthropic_model": os.getenv("ANTHROPIC_MODEL", DEFAULT_ANTHROPIC_MODEL),
            "any_live_configured": has_gemini or has_openai or has_bedrock or has_anthropic,
            "recommended_default": recommended,
            "bedrock_region": os.getenv("AWS_REGION", "us-east-1"),
            "bedrock_model": os.getenv("AWS_BEDROCK_MODEL_ID", "amazon.nova-lite-v1:0"),
        }

    async def generate_blind_reasoning(
        self,
        blinded_prompt: str,
        provider: str = "simulation",
        api_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        load_dotenv_if_present()
        mode = (provider or "simulation").lower().strip()

        if mode == "auto":
            if api_key and api_key.startswith("AIza"):
                mode = "gemini"
            elif api_key and api_key.startswith("sk-ant-"):
                mode = "anthropic"  # must be tested before the generic OpenAI "sk-" prefix
            elif api_key and api_key.startswith("sk-"):
                mode = "openai"
            elif api_key and api_key.startswith("ABSK"):
                mode = "bedrock"
            else:
                mode = self.get_env_config()["recommended_default"]

        if mode == "anthropic":
            key = (api_key or os.getenv("ANTHROPIC_API_KEY") or "").strip()
            if not key:
                raise ValueError(
                    "Anthropic selected, but no ANTHROPIC_API_KEY was provided in the UI or `.env`."
                )
            return await self._call_anthropic(blinded_prompt, key)

        # Never send a credential to a provider it does not belong to: an Anthropic key in the
        # Gemini/OpenAI/Bedrock slot is refused locally instead of being posted to that provider.
        if mode in ("gemini", "openai", "bedrock"):
            wrong_slot = {
                "gemini": "GEMINI_API_KEY",
                "openai": "OPENAI_API_KEY",
                "bedrock": "AWS_BEARER_TOKEN_BEDROCK",
            }[mode]
            candidate = (api_key or os.getenv(wrong_slot) or "").strip()
            if candidate.startswith("sk-ant-"):
                raise ValueError(
                    f"The key configured for {mode} looks like an Anthropic key (sk-ant-…). It was NOT sent. "
                    "Put it in ANTHROPIC_API_KEY and select Anthropic, or use a key for the selected provider."
                )

        if mode == "gemini":
            key = (api_key or os.getenv("GEMINI_API_KEY") or "").strip()
            if not key:
                raise ValueError(
                    "Gemini 2.5 Flash selected, but no GEMINI_API_KEY was provided in the UI or `.env`."
                )
            return await self._call_gemini(blinded_prompt, key)

        if mode == "openai":
            key = (api_key or os.getenv("OPENAI_API_KEY") or "").strip()
            if not key:
                raise ValueError(
                    "OpenAI GPT-4o-mini selected, but no OPENAI_API_KEY was provided in the UI or `.env`."
                )
            return await self._call_openai(blinded_prompt, key)

        if mode == "bedrock":
            key = (api_key or os.getenv("AWS_BEARER_TOKEN_BEDROCK") or "").strip()
            if not key:
                raise ValueError(
                    "AWS Bedrock selected, but no AWS_BEARER_TOKEN_BEDROCK was provided in the UI or `.env`."
                )
            return await self._call_bedrock(blinded_prompt, key)

        return self._run_deterministic_engine(blinded_prompt)

    # ------------------------------------------------------------------
    # Provider transport
    # ------------------------------------------------------------------
    @staticmethod
    def _wire_request(url: str, headers: Dict[str, str], payload: Dict[str, Any],
                      secret_header: str) -> Dict[str, Any]:
        redacted = {
            k: ("<redacted>" if k.lower() == secret_header.lower() else v) for k, v in headers.items()
        }
        return {"method": "POST", "url": url, "headers_redacted": redacted, "body": payload}

    @staticmethod
    def _scrub(text: str, secret: str) -> str:
        text = str(text)
        if secret:
            text = text.replace(secret, "<redacted>")
        # Providers echo a partially masked key in auth errors ("sk-abc*********wxyz"). The exact
        # replacement above cannot catch that, so any run of asterisks with key-like characters
        # around it is removed as well.
        return _MASKED_KEY_RE.sub("<redacted>", text)

    async def _post_json(self, label: str, url: str, headers: Dict[str, str],
                         payload: Dict[str, Any], secret: str,
                         wire: Dict[str, Any]) -> Any:
        """POST `payload`; return parsed JSON or raise LLMProviderError (never leaks `secret`)."""
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
                res = await client.post(url, headers=headers, json=payload)
        except httpx.TimeoutException as exc:
            raise LLMProviderError(
                f"{label}: request timed out after {HTTP_TIMEOUT_SECONDS:.0f}s ({type(exc).__name__}).",
                wire_request=wire,
            ) from None
        except httpx.HTTPError as exc:
            raise LLMProviderError(
                f"{label}: network error ({type(exc).__name__}: {self._scrub(exc, secret)[:200]}).",
                wire_request=wire,
            ) from None

        if res.status_code != 200:
            hint = " (rate limited / quota exceeded)" if res.status_code == 429 else ""
            raise LLMProviderError(
                f"{label} API error (HTTP {res.status_code}){hint}: {self._scrub(res.text, secret)[:240]}",
                wire_request=wire,
                status_code=res.status_code,
            )
        try:
            return res.json()
        except ValueError:
            raise LLMProviderError(
                f"{label}: response body is not valid JSON: {self._scrub(res.text, secret)[:160]}",
                wire_request=wire,
                status_code=res.status_code,
            ) from None

    @staticmethod
    def _extract_gemini_text(data: Any) -> str:
        if not isinstance(data, dict):
            raise LLMProviderError("Gemini 2.5 Flash: response is not a JSON object.")
        candidates = data.get("candidates")
        feedback = data.get("promptFeedback") or {}
        if not candidates:
            block = feedback.get("blockReason") if isinstance(feedback, dict) else None
            if block:
                raise LLMProviderError(f"Gemini 2.5 Flash blocked the prompt (promptFeedback.blockReason={block}).")
            raise LLMProviderError("Gemini 2.5 Flash returned no candidates.")
        try:
            cand = candidates[0]
            finish = cand.get("finishReason")
            parts = (cand.get("content") or {}).get("parts") or []
            texts = [p.get("text", "") for p in parts if isinstance(p, dict) and isinstance(p.get("text"), str)]
        except (KeyError, IndexError, TypeError, AttributeError) as exc:
            raise LLMProviderError(f"Gemini 2.5 Flash: unexpected response shape ({type(exc).__name__}).") from None
        text = "".join(texts)
        if not text.strip():
            if finish and finish != "STOP":
                why = " (blocked by Gemini safety filters)" if finish in ("SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST", "SPII") else ""
                raise LLMProviderError(f"Gemini 2.5 Flash returned no text: finishReason={finish}{why}.")
            raise LLMProviderError("Gemini 2.5 Flash returned an empty candidate (no content.parts text).")
        return text

    async def _call_gemini(self, blinded_prompt: str, api_key: str) -> Dict[str, Any]:
        label = "Gemini 2.5 Flash"
        url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
        headers = {"x-goog-api-key": api_key, "Content-Type": "application/json"}
        payload = {
            "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": blinded_prompt}]}],
            "generationConfig": {"temperature": 0.1},
        }
        wire = self._wire_request(url, headers, payload, "x-goog-api-key")
        data = await self._post_json(label, url, headers, payload, api_key, wire)
        try:
            text = self._extract_gemini_text(data)
        except LLMProviderError as exc:
            exc.wire_request = wire
            raise
        result = self._parse_structured_output(
            text, provider_label="Google Gemini 2.5 Flash (Live Cloud API)", is_live=True
        )
        result["wire_request"] = wire
        return result

    async def _call_openai(self, blinded_prompt: str, api_key: str) -> Dict[str, Any]:
        label = "OpenAI GPT-4o-mini"
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
        wire = self._wire_request(url, headers, payload, "Authorization")
        data = await self._post_json(label, url, headers, payload, api_key, wire)
        try:
            choice = data["choices"][0]
            text = choice["message"]["content"]
            if not isinstance(text, str) or not text.strip():
                raise TypeError(f"empty content (finish_reason={choice.get('finish_reason')})")
        except (KeyError, IndexError, TypeError, AttributeError) as exc:
            raise LLMProviderError(
                f"{label}: unusable response ({type(exc).__name__}: {self._scrub(exc, api_key)[:160]}).",
                wire_request=wire,
            ) from None
        result = self._parse_structured_output(
            text, provider_label="OpenAI GPT-4o-mini (Live Cloud API)", is_live=True
        )
        result["wire_request"] = wire
        return result

    async def _call_anthropic(self, blinded_prompt: str, api_key: str) -> Dict[str, Any]:
        model_id = (os.getenv("ANTHROPIC_MODEL") or DEFAULT_ANTHROPIC_MODEL).strip()
        label = f"Anthropic ({model_id})"
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model_id,
            "max_tokens": 1024,
            # No `temperature`: current Claude models reject the parameter as deprecated.
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": blinded_prompt}],
            # The plan is requested as a forced tool call, so the structured part cannot be
            # omitted or malformed the way a free-text JSON block can (temperature is not settable).
            "tools": [ANTHROPIC_PLAN_TOOL],
            "tool_choice": {"type": "tool", "name": ANTHROPIC_PLAN_TOOL["name"]},
        }
        wire = self._wire_request(url, headers, payload, "x-api-key")
        data = await self._post_json(label, url, headers, payload, api_key, wire)
        try:
            blocks = data["content"]
            plan = next(
                (
                    b.get("input")
                    for b in blocks
                    if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("name") == ANTHROPIC_PLAN_TOOL["name"]
                ),
                None,
            )
            if isinstance(plan, dict):
                summary = plan.get("summary")
                summary = summary if isinstance(summary, str) else ""
                structured = {
                    "fhe_compute": plan.get("fhe_compute"),
                    "action_intent": plan.get("action_intent"),
                }
                # Re-use the one validated parser: the tool input is untrusted model output too.
                text = f"{summary}\n```json\n{json.dumps(structured)}\n```"
            else:
                text = "".join(
                    b["text"] for b in blocks if isinstance(b, dict) and b.get("type") == "text" and "text" in b
                )
            if not text.strip():
                raise TypeError(f"empty content (stop_reason={data.get('stop_reason')})")
        except (KeyError, IndexError, TypeError, AttributeError) as exc:
            raise LLMProviderError(
                f"{label}: unusable response ({type(exc).__name__}: {self._scrub(exc, api_key)[:160]}).",
                wire_request=wire,
            ) from None
        result = self._parse_structured_output(
            text, provider_label=f"Anthropic ({model_id} Live Cloud API)", is_live=True
        )
        result["wire_request"] = wire
        return result

    async def _call_bedrock(self, blinded_prompt: str, bearer_token: str) -> Dict[str, Any]:
        region = os.getenv("AWS_REGION", "us-east-1").strip()
        model_id = os.getenv("AWS_BEDROCK_MODEL_ID", "amazon.nova-lite-v1:0").strip()
        label = f"AWS Bedrock ({model_id})"
        url = f"https://bedrock-runtime.{region}.amazonaws.com/model/{model_id}/converse"
        headers = {"Authorization": f"Bearer {bearer_token}", "Content-Type": "application/json"}
        payload = {
            "system": [{"text": SYSTEM_PROMPT}],
            "messages": [{"role": "user", "content": [{"text": blinded_prompt}]}],
            "inferenceConfig": {"temperature": 0.1},
        }
        wire = self._wire_request(url, headers, payload, "Authorization")
        data = await self._post_json(label, url, headers, payload, bearer_token, wire)
        try:
            blocks = data["output"]["message"]["content"]
            text = "".join(b["text"] for b in blocks if isinstance(b, dict) and "text" in b)
            if not text.strip():
                raise TypeError(f"empty content (stopReason={data.get('stopReason')})")
        except (KeyError, IndexError, TypeError, AttributeError) as exc:
            raise LLMProviderError(
                f"{label}: unusable response ({type(exc).__name__}: {self._scrub(exc, bearer_token)[:160]}).",
                wire_request=wire,
            ) from None
        result = self._parse_structured_output(
            text, provider_label=f"AWS Bedrock ({model_id} Live Cloud API)", is_live=True
        )
        result["wire_request"] = wire
        return result

    def _run_deterministic_engine(self, blinded_prompt: str) -> Dict[str, Any]:
        lower = blinded_prompt.lower()

        id_tokens = re.findall(r"\[(?:ID|EMAIL|GOV_ID|IBAN)_[A-F0-9]{8}\]", blinded_prompt)
        secret_tokens = re.findall(r"\[SECRET_[A-F0-9]{8}\]", blinded_prompt)
        person_or_org = next((t for t in id_tokens if t.startswith("[ID_")), None)
        iban_tok = next((t for t in id_tokens if t.startswith("[IBAN_")), None)
        gov_tok = next((t for t in id_tokens if t.startswith("[GOV_ID_")), None)
        fhe_tokens = re.findall(r"\[FHE_NUM_\d+\]", blinded_prompt)

        primary_target = person_or_org or iban_tok or gov_tok or "[SYSTEM_RECORD]"

        fhe_compute: Optional[Dict[str, Any]] = None
        # Accepts integer and decimal percentages ("15%", "12.5%", "12,5%"); the evaluator
        # takes non-integer percents, so the value is passed as a number, not truncated.
        pct_match = re.search(r"(?<![\d.,])(\d{1,3}(?:[.,]\d{1,4})?)\s?%(?!\w)", blinded_prompt)
        if "bonus" in lower and fhe_tokens:
            pct: Any = 15
            if pct_match:
                pct_text = pct_match.group(1).replace(",", ".")
                pct = float(pct_text) if "." in pct_text else int(pct_text)
            fhe_compute = {"op": "PERCENT_BONUS", "ref": fhe_tokens[0], "percent": pct}
        elif len(fhe_tokens) >= 2 and any(
            w in lower for w in ["multiply", "product", "invoice", "hours", "units", "rate"]
        ):
            fhe_compute = {"op": "BFV_MULTIPLY", "ref_a": fhe_tokens[0], "ref_b": fhe_tokens[1]}
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
                "params": {
                    "fhe_refs": fhe_tokens,
                    "computed_product": "[FHE_COMPUTED_PRODUCT]"
                    if (fhe_compute and fhe_compute["op"] == "BFV_MULTIPLY")
                    else "N/A",
                },
            }

        lines = [f"Zero-Knowledge reasoning completed for subject {primary_target}."]
        if fhe_compute and fhe_compute["op"] == "PERCENT_BONUS":
            lines.append(
                f"- Paillier PHE Policy Calculation ({fhe_compute['percent']}% on {fhe_compute['ref']}): "
                f"Bonus = [FHE_COMPUTED_BONUS], New Total Compensation = [FHE_COMPUTED_TOTAL]."
            )
        elif fhe_compute and fhe_compute["op"] == "BFV_MULTIPLY":
            lines.append(
                f"- Native C RLWE-BFV (leveled, depth 1) Product ({fhe_compute['ref_a']} × {fhe_compute['ref_b']} in R_q): "
                f"Product = [FHE_COMPUTED_PRODUCT]."
            )
        elif fhe_compute and fhe_compute["op"] == "ADD":
            lines.append(
                f"- Paillier PHE Aggregation ({fhe_compute['ref_a']} + {fhe_compute['ref_b']}): "
                f"Sum = [FHE_COMPUTED_SUM]."
            )
        elif fhe_tokens:
            lines.append(f"- Verified homomorphically encrypted field(s): {', '.join(fhe_tokens)}.")

        if secret_tokens:
            lines.append(
                f"- Scrubbed & C-AES256 sealed {len(secret_tokens)} secret credential token(s) prior to wire transmission (zero plaintext exposure)."
            )
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
            "parse_warning": None,
            "wire_request": dict(OFFLINE_WIRE_REQUEST),
        }

    _FENCE_RE = re.compile(r"```[ \t]*([A-Za-z0-9_-]*)[ \t]*\r?\n?(.*?)```", re.DOTALL)

    @staticmethod
    def _trailing_json_object(text: str) -> Optional[Tuple[int, Any]]:
        """Find a JSON object that ends the text without a fence; return (start, obj)."""
        decoder = json.JSONDecoder()
        stripped_len = len(text.rstrip())
        for start in [m.start() for m in re.finditer(r"\{", text)]:
            try:
                obj, end = decoder.raw_decode(text, start)
            except ValueError:
                continue
            if end == stripped_len and isinstance(obj, dict):
                return start, obj
        return None

    def _parse_structured_output(
        self, text: str, provider_label: str, is_live: bool
    ) -> Dict[str, Any]:
        """
        Accepts ```json / ```JSON / bare ``` fences, or a bare JSON object at the end.
        Never silently drops unusable JSON: returns `parse_warning` instead.
        Only dicts are accepted for `fhe_compute` / `action_intent`.
        """
        fhe_compute: Any = None
        action_intent: Any = None
        clean_text = text if isinstance(text, str) else str(text)
        warnings: List[str] = []

        parsed: Any = None
        span: Optional[Tuple[int, int]] = None
        fence_errors: List[str] = []
        fences = [
            m for m in self._FENCE_RE.finditer(clean_text)
            if m.group(1).lower() in ("", "json", "json5", "jsonc")
        ]
        for m in reversed(fences):  # the schema asks for the block at the end
            body = m.group(2).strip()
            if not body.startswith(("{", "[")):
                continue
            try:
                parsed = json.loads(body)
                span = (m.start(), m.end())
                break
            except ValueError as exc:
                fence_errors.append(f"{exc.msg} at line {exc.lineno} col {exc.colno}")

        if span is None:
            tail = self._trailing_json_object(clean_text)
            if tail is not None:
                parsed = tail[1]
                span = (tail[0], len(clean_text))

        if span is None:
            if fence_errors:
                warnings.append(
                    f"Structured JSON block is invalid ({fence_errors[0]}); no computation or action was executed."
                )
            else:
                warnings.append("No structured JSON block found in model output; no computation or action was executed.")
        elif not isinstance(parsed, dict):
            warnings.append(
                f"Structured JSON is a {type(parsed).__name__}, expected an object; ignored."
            )
        else:
            clean_text = (clean_text[: span[0]] + clean_text[span[1] :]).strip()
            fhe_compute = parsed.get("fhe_compute")
            action_intent = parsed.get("action_intent")
            if fhe_compute is not None and not isinstance(fhe_compute, dict):
                warnings.append(
                    f"fhe_compute ignored: expected an object, got {type(fhe_compute).__name__}."
                )
                fhe_compute = None
            if action_intent is not None and not isinstance(action_intent, dict):
                warnings.append(
                    f"action_intent ignored: expected an object, got {type(action_intent).__name__}."
                )
                action_intent = None

        return {
            "provider": provider_label,
            "is_live_cloud": is_live,
            "raw_response": clean_text,
            "fhe_compute": fhe_compute,
            "action_intent": action_intent,
            "parse_warning": " ".join(warnings) if warnings else None,
        }
