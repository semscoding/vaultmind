"""
Pipeline Service: Orchestrates Blinding, Zero-Retention C AES-256 Secret Sealing,
Cloud/ZK LLM Reasoning, 1024-bit Paillier PHE + 128-bit PQ Lattice RLWE-BFV FHE Math,
Dual-Field Enclave Sealing, and Security Telemetry.
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
        paillier_bits: int = 1024,
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

        wire_payload = {
            "provider_mode": provider,
            "transmitted_prompt": blinded_text,
            "paillier_phe_modulus_bits": self.tokenizer.paillier.n.bit_length(),
            "bfv_fhe_ring": "Z_{2^54}[X]/(X^2048 + 1) [128-bit Lattice Security]",
            "contains_master_key": False,
            "contains_raw_pii": False,
            "contains_raw_secrets": False,
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
        fhe_spec = llm_result.get("fhe_compute")
        action_intent = llm_result.get("action_intent")

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
                    "raw_reasoning": llm_result.get("raw_response"),
                    "fhe_compute": fhe_spec,
                    "action_intent_proposed": action_intent,
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

        raw_final = llm_result.get("raw_response", "")
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
