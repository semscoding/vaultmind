"""
API Router Module (`apis/routes.py`).
Exposes REST endpoints for Zero-Knowledge Pipeline execution, Host LLM Config detection,
Dual-Field 2048-bit Feldman VSS shard inspection/tampering, Paillier additive HE math,
Native C RLWE-BFV (leveled, depth 1; N=2048, log q=54) multiplication,
hash-chained SQLite HMAC verification, and real-time Security Telemetry Monitoring.

Error contract for /api/process: missing API key / bad input -> 400,
cloud provider failure -> 502, anything else -> 500. `detail` is always a string;
502 adds `error`, `provider_status_code` and `wire_request` (credential redacted).
"""

from typing import Optional
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from apis.llm_client import LLMClient, LLMProviderError
from backend.crypto.bfv_fhe import BFV_T
from services.pipeline_service import AgentPipeline

router = APIRouter(prefix="/api")

# Shared service singleton for the FastAPI worker
pipeline = AgentPipeline()


class ProcessPromptRequest(BaseModel):
    prompt: str
    api_key: Optional[str] = None
    provider: Optional[str] = "auto"


class HomomorphicCalcRequest(BaseModel):
    val1: float
    val2: float


class BFVCalcRequest(BaseModel):
    m1: int
    m2: int


class TamperNodeRequest(BaseModel):
    node_index: int


@router.get("/llm-config")
async def get_llm_config():
    """Return which live cloud LLM host API keys are configured in `.env` / environment."""
    return LLMClient.get_env_config()


@router.get("/vault-status")
async def get_vault_status():
    return pipeline.enclave.get_public_vault_status()


@router.post("/tamper-node")
async def tamper_node_endpoint(req: TamperNodeRequest):
    try:
        res = pipeline.enclave.tamper_shard_for_demo(req.node_index)
        pipeline.monitor.record_tamper_simulation(req.node_index)
        return res
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/restore-nodes")
async def restore_nodes_endpoint():
    res = pipeline.enclave.restore_all_shards()
    pipeline.monitor.record_event("INFO", "enclave", "Restored all 5 disk shards to verified state.")
    return res


@router.get("/ledger")
async def get_verified_ledger():
    return pipeline.enclave.verify_ledger_entries(limit=15)


@router.post("/process")
async def process_prompt_endpoint(req: ProcessPromptRequest):
    try:
        return await pipeline.process_prompt(
            user_prompt=req.prompt,
            provider=req.provider or "auto",
            api_key=req.api_key,
        )
    except LLMProviderError as exc:
        pipeline.monitor.record_event("WARNING", "llm_provider", f"Cloud provider call failed: {exc}"[:300])
        return JSONResponse(
            status_code=502,
            content={
                "detail": str(exc),
                "error": "LLM_PROVIDER_ERROR",
                "provider_status_code": exc.status_code,
                "wire_request": exc.wire_request,
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # noqa: BLE001 - last-resort net: never a bare 500
        pipeline.monitor.record_event(
            "CRITICAL", "pipeline", f"Unhandled pipeline error ({type(exc).__name__})."
        )
        return JSONResponse(
            status_code=500,
            content={
                "detail": f"Local pipeline error ({type(exc).__name__}); details withheld to avoid echoing plaintext.",
                "error": "PIPELINE_INTERNAL_ERROR",
                "type": type(exc).__name__,
            },
        )


@router.post("/homomorphic-calc")
async def homomorphic_calc_endpoint(req: HomomorphicCalcRequest):
    """Paillier Additive Homomorphic Encryption (PHE) over Z_{n^2}^* (modulus size: see `modulus_bits`)."""
    paillier = pipeline.tokenizer.paillier
    evaluator = pipeline.tokenizer.evaluator

    try:
        c1, s1 = paillier.encrypt_fixed(req.val1)
        c2, s2 = paillier.encrypt_fixed(req.val2)
        c_sum, s_sum = evaluator.add_scaled(c1, s1, c2, s2)
        decrypted_sum = paillier.decrypt_fixed(c_sum, s_sum)
    except (ValueError, OverflowError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    n_bits = paillier.n.bit_length()
    pipeline.monitor.record_homomorphic_computation(
        "paillier_phe",
        f"Evaluated {n_bits}-bit Paillier PHE ciphertext addition (operands not logged).",
    )

    return {
        "scheme": f"{n_bits}-bit Paillier Additive Homomorphic Encryption (PHE)",
        "modulus_bits": paillier.n.bit_length(),
        "val1": req.val1,
        "val2": req.val2,
        "c1_hex": f"{hex(c1)[:20]}...{hex(c1)[-8:]}",
        "c2_hex": f"{hex(c2)[:20]}...{hex(c2)[-8:]}",
        "c_sum_hex": f"{hex(c_sum)[:20]}...{hex(c_sum)[-8:]}",
        "operation": f"c_sum = (c1 · c2) mod n^2  [{n_bits}-bit Paillier PHE]",
        "decrypted_sum": round(decrypted_sum, 4),
        "mathematical_proof": f"D(E({req.val1}) · E({req.val2}) mod n^2) = {decrypted_sum:g}",
    }


@router.post("/bfv-fhe-calc")
async def bfv_fhe_calc_endpoint(req: BFVCalcRequest):
    """
    RLWE-BFV (leveled, depth 1) in Native C (`libvaultcrypto.dylib`)
    over R_q = Z_{2^54}[X] / (X^2048 + 1): N=2048, log q=54 (HE-standard classical-128
    size row), ternary errors.
    Uses overflow-free base-256 limb multiplication for arbitrary 32-bit integers [0, 2^32 - 1].
    """
    if not (0 <= req.m1 <= 0xFFFFFFFF and 0 <= req.m2 <= 0xFFFFFFFF):
        raise HTTPException(
            status_code=400,
            detail="BFV plaintext integers must be non-negative 32-bit integers [0, 4294967295].",
        )

    bfv = pipeline.tokenizer.bfv
    limbs1 = bfv.encrypt_limbs_u32(req.m1)
    limbs2 = bfv.encrypt_limbs_u32(req.m2)
    prod_terms = bfv.evaluator.multiply_limbs(limbs1, limbs2)
    dec_mul_exact = bfv.decrypt_limbs_product(prod_terms)

    # Also compute single-ring Z_65536 addition on mod-65536 projections
    ct1_single = bfv.encrypt_int(req.m1 % BFV_T)
    ct2_single = bfv.encrypt_int(req.m2 % BFV_T)
    ct_add = bfv.evaluator.add(ct1_single, ct2_single)
    dec_add = bfv.decrypt_int(ct_add)

    pipeline.monitor.record_homomorphic_computation(
        "bfv_rlwe",
        "Evaluated N=2048 RLWE-BFV (leveled, depth 1) ciphertext × ciphertext product (operands not logged).",
    )

    return {
        "scheme": "Native C RLWE-BFV (leveled, depth 1)",
        "ring": "R_q = Z_{2^54}[X] / (X^2048 + 1), t = 65536",
        "m1": req.m1,
        "m2": req.m2,
        "ct1_preview": bfv.ciphertext_preview(limbs1[0]),
        "ct2_preview": bfv.ciphertext_preview(limbs2[0]),
        "ct_mul_preview": bfv.ciphertext_preview(prod_terms[0][1]),
        "decrypted_sum_mod_t": dec_add,
        "decrypted_product_exact": dec_mul_exact,
        "decrypted_product_mod_t": dec_mul_exact % BFV_T,
        "mathematical_proof": (
            f"D(Relin(E({req.m1}) ⊗ E({req.m2}))) = {dec_mul_exact:,} (exact, 0 overflow)  |  "
            f"D(E({req.m1 % BFV_T}) ⊕ E({req.m2 % BFV_T})) = {dec_add} (mod 65536)"
        ),
    }


@router.get("/monitoring/metrics")
async def get_monitoring_metrics():
    return pipeline.monitor.snapshot()


@router.get("/monitoring/health")
async def get_monitoring_health():
    vault_st = pipeline.enclave.get_public_vault_status()
    return {
        "status": "HEALTHY" if vault_st["quorum_healthy"] else "DEGRADED_QUORUM",
        "native_c_enclave": "ACTIVE",
        "quorum_healthy": vault_st["quorum_healthy"],
        "paillier_phe_modulus_bits": pipeline.tokenizer.paillier.n.bit_length(),
        "bfv_fhe_ring": (
            "Z_{2^54}[X]/(X^2048 + 1) [RLWE-BFV (leveled, depth 1); N=2048, log q=54, "
            "HE-standard classical-128 size row, ternary errors]"
        ),
        "llm_env": LLMClient.get_env_config(),
        "telemetry": pipeline.monitor.snapshot(),
    }
