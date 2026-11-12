"""
Pipeline Service: Orchestrates Blinding, Zero-Retention C AES-256 Secret Sealing,
Cloud/ZK LLM Reasoning, Paillier PHE (2048-bit default) + RLWE-BFV (leveled, depth 1) Math,
Dual-Field Enclave Sealing, and Security Telemetry.

The cloud-wire leak flags are computed by a post-blinding scan of the detected spans (B1);
the blinding itself is regex/heuristic, which `wire_payload["leak_check"]` states explicitly.
"""

import time
from typing import Any, Dict, List, Optional

from apis.llm_client import LLMClient
from backend.crypto.blind_tokenizer import BlindTokenizer
from monitoring.telemetry import SecurityMonitor
from .enclave_service import SecureEnclave


class AgentPipeline:
    def __init__(
        self,
        storage_dir: Optional[str] = None,
        paillier_bits: int = 2048,
        reset_vault: bool = False,
        monitor: Optional[SecurityMonitor] = None,
    ):
        self.tokenizer = BlindTokenizer(paillier_bits=paillier_bits)
        self.llm = LLMClient()
        self.enclave = SecureEnclave(
            storage_dir=storage_dir,
            threshold=3,
            total_shares=5,
            reset_on_init=reset_vault,
        )
        self.monitor = monitor or SecurityMonitor()

    async def process_prompt(
        self,
        user_prompt: str,
        provider: str = "simulation",
        api_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        start_time = time.time()
        audit_trail: List[Dict[str, Any]] = []

        blinded_text, ctx = self.tokenizer.blind_prompt(user_prompt)
        scan = self.tokenizer.residual_scan(blinded_text, ctx)

        wire_payload = {
            "provider_mode": provider,
            "transmitted_prompt": blinded_text,
            "paillier_phe_modulus_bits": self.tokenizer.paillier.n.bit_length(),
            "bfv_fhe_ring": (
                "Z_{2^54}[X]/(X^2048 + 1) [RLWE-BFV (leveled, depth 1): N=2048, log q=54, "
                "HE-standard classical-128 size row, ternary errors]"
            ),
            # The master key never enters the pipeline process (it is reconstructed only inside the C enclave).
            "contains_master_key": False,
            "contains_raw_pii": scan["residual_pii_matches"] > 0,
            "contains_raw_secrets": scan["residual_secret_matches"] > 0,
            "leak_check": {
                "method": "post-blinding scan of detected spans",
                "detected_spans": scan["detected_spans"],
                "residual_matches": scan["residual_matches"],
                "heuristic": True,
                "note": (
                    "Regex/heuristic blinding: unmarked secrets without a recognizable pattern are not "
                    "detected. Wrap them in <secret>...</secret>."
                ),
            },
            # Filled in after the LLM call (B4): the request that actually left this machine, without API key.
            "actual_request": None,
        }
        audit_trail.append(
            {
                "phase": "PHASE_2_CLOUD_WIRE",
                "name": "External Cloud Wire Payload",
                "details": wire_payload,
            }
        )

        llm_result = await self.llm.generate_blind_reasoning(
            blinded_prompt=blinded_text,
            provider=provider,
            api_key=api_key,
        )
        if not isinstance(llm_result, dict):
            llm_result = {}
        wire_payload["actual_request"] = llm_result.get("wire_request")

        # M3: the LLM output is untrusted; only dicts are accepted for fhe_compute / action_intent.
        llm_output_warnings: List[str] = []
        parse_warning = llm_result.get("parse_warning")
        if parse_warning:
            llm_output_warnings.append(str(parse_warning))
        fhe_spec = llm_result.get("fhe_compute")
        if fhe_spec is not None and not isinstance(fhe_spec, dict):
            llm_output_warnings.append(
                f"Ignored fhe_compute from LLM: expected an object, got {type(fhe_spec).__name__}."
            )
            fhe_spec = None
        action_intent = llm_result.get("action_intent")
        if action_intent is not None and not isinstance(action_intent, dict):
            llm_output_warnings.append(
                f"Ignored action_intent from LLM: expected an object, got {type(action_intent).__name__}."
            )
            action_intent = None
        raw_response = llm_result.get("raw_response")
        if raw_response is None:
            raw_response = ""
        elif not isinstance(raw_response, str):
            raw_response = str(raw_response)

        fhe_computation_report = None
        if fhe_spec:
            try:
                fhe_computation_report = self.tokenizer.execute_and_decrypt_fhe(fhe_spec, ctx)
            except Exception as exc:
                fhe_computation_report = {"error": str(exc)}

        hmac_map = {
            k: v for k, v in ctx.token_to_plaintext.items() if not k.startswith("[FHE_")
        }
        for sec_tok, blob in ctx.sealed_secrets.items():
            hmac_map[sec_tok] = f"[C-AES256 Sealed: {blob['preview']}]"

        audit_trail.append(
            {
                "phase": "PHASE_1_BLINDING",
                "name": "Local Cryptographic Masking, C Secret Sealing & Dual PHE/FHE",
                "details": {
                    "original_input": ctx.redacted_prompt,
                    "blinded_output": blinded_text,
                    "hmac_tokens": hmac_map,
                    "sealed_secret_count": len(ctx.sealed_secrets),
                    "homomorphic_ciphertexts": [
                        {
                            "token": k,
                            "raw_text": v["raw_text"],
                            "scale": v["scale"],
                            "hex_preview": v["hex_preview"],
                            "bfv_preview": v.get("bfv_preview"),
                            "modulus_n_bits": ctx.paillier.n.bit_length(),
                        }
                        for k, v in ctx.encrypted_numbers.items()
                    ],
                    "homomorphic_computed": fhe_computation_report,
                    "logs": ctx.logs,
                },
            }
        )

        audit_trail.append(
            {
                "phase": "PHASE_3_LLM_REASONING",
                "name": "Zero-Knowledge Agent Reasoning",
                "details": {
                    "provider": llm_result.get("provider"),
                    "is_live_cloud": llm_result.get("is_live_cloud", False),
                    "raw_reasoning": raw_response,
                    "fhe_compute": fhe_spec,
                    "action_intent_proposed": action_intent,
                    "llm_output_warnings": llm_output_warnings,
                },
            }
        )

        enclave_result = None
        active_quorum: List[str] = []
        if action_intent:
            enclave_result = self.enclave.execute_privileged_intent(action_intent)
            if enclave_result.get("success") and enclave_result.get("receipt"):
                active_quorum = enclave_result["receipt"].get("quorum_nodes", [])

        vault_status = self.enclave.get_public_vault_status(active_quorum=active_quorum)

        audit_trail.append(
            {
                "phase": "PHASE_4_ENCLAVE_SSS",
                "name": "Dual-Field 2048-bit Feldman VSS & Native C Enclave Execution",
                "details": {
                    "executed": bool(enclave_result and enclave_result.get("success")),
                    "enclave_result": enclave_result,
                    "vault_status": vault_status,
                },
            }
        )

        raw_final = raw_response
        overall_status = "SUCCESS"
        sealed_ok = False
        blocked_flag = False
        if enclave_result:
            if enclave_result.get("success"):
                sealed_ok = True
                rcpt = enclave_result["receipt"]
                rejected = rcpt.get("rejected_tampered_nodes", [])
                failover_note = (
                    f" | Ignored tampered node(s): {', '.join(rejected)}" if rejected else ""
                )
                raw_final += (
                    f"\n\n[Native C Enclave Sealed -> SQLite Row #{rcpt['ledger_row_id']} | "
                    f"Action: {rcpt['action']} | Quorum: {', '.join(rcpt['quorum_nodes'])}{failover_note} | "
                    f"HMAC-SHA256: {rcpt['hmac_sha256_tag']}]"
                )
            else:
                blocked_flag = True
                overall_status = "ENCLAVE_REJECTED"
                raw_final += f"\n\n[ENCLAVE SECURITY BLOCK: {enclave_result.get('error')}]"

        unblinded_output = self.tokenizer.unblind_response(raw_final, ctx)
        duration_ms = round((time.time() - start_time) * 1000, 2)

        self.monitor.record_pipeline_run(
            duration_ms=duration_ms,
            hmac_count=len(hmac_map),
            fhe_enc_count=len(ctx.encrypted_numbers),
            fhe_computed=bool(fhe_computation_report and "error" not in fhe_computation_report),
            sealed=sealed_ok,
            blocked=blocked_flag,
            rejected_nodes_count=len(vault_status.get("rejected_nodes", [])),
        )

        return {
            "status": overall_status,
            "provider_used": llm_result.get("provider"),
            "is_live_cloud": llm_result.get("is_live_cloud", False),
            "duration_ms": duration_ms,
            "original_prompt": ctx.redacted_prompt,
            "blinded_prompt": blinded_text,
            "cloud_wire_payload": wire_payload,
            "fhe_computation": fhe_computation_report,
            "llm_output_warnings": llm_output_warnings,
            "enclave_receipt": enclave_result.get("receipt") if enclave_result else None,
            "enclave_error": enclave_result.get("error") if enclave_result and not enclave_result.get("success") else None,
            "unblinded_result": unblinded_output,
            "audit_trail": audit_trail,
            "vault_topology": vault_status,
            "paillier_public_key": self.tokenizer.paillier.public_key_dict,
            "bfv_parameters": self.tokenizer.bfv.parameters_dict,
            "recent_ledger": self.enclave.ledger.list_entries(limit=10),
            "monitoring": self.monitor.snapshot(),
        }
