"""
API Router Module (`apis/routes.py`).
Exposes REST endpoints for Zero-Knowledge Pipeline execution, Host LLM Config detection,
Dual-Field 2048-bit Feldman VSS shard inspection/tampering, 1024-bit Paillier PHE math,
128-bit Lattice Security Native C RLWE-BFV FHE (N=2048) multiplication,
SQLite HMAC verification, and real-time Security Telemetry Monitoring.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from apis.llm_client import LLMClient
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
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/homomorphic-calc")
async def homomorphic_calc_endpoint(req: HomomorphicCalcRequest):
    """1024-bit Paillier Additive Homomorphic Encryption (PHE) over Z_{n^2}^*."""
    paillier = pipeline.tokenizer.paillier
    evaluator = pipeline.tokenizer.evaluator

    try:
        c1, s1 = paillier.encrypt_fixed(req.val1)
        c2, s2 = paillier.encrypt_fixed(req.val2)
        c_sum, s_sum = evaluator.add_scaled(c1, s1, c2, s2)
        decrypted_sum = paillier.decrypt_fixed(c_sum, s_sum)
    except (ValueError, OverflowError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    pipeline.monitor.total_fhe_computations += 1
    pipeline.monitor.record_event(
        "INFO",
        "paillier_phe",
        f"Evaluated 1024-bit Paillier PHE ciphertext addition ({paillier.n.bit_length()} bits).",
    )

    return {
        "scheme": "1024-bit Paillier Additive Homomorphic Encryption (PHE)",
        "modulus_bits": paillier.n.bit_length(),
        "val1": req.val1,
        "val2": req.val2,
        "c1_hex": f"{hex(c1)[:20]}...{hex(c1)[-8:]}",
        "c2_hex": f"{hex(c2)[:20]}...{hex(c2)[-8:]}",
        "c_sum_hex": f"{hex(c_sum)[:20]}...{hex(c_sum)[-8:]}",
        "operation": "c_sum = (c1 · c2) mod n^2  [1024-bit Paillier PHE]",
        "decrypted_sum": round(decrypted_sum, 4),
        "mathematical_proof": f"D(E({req.val1}) · E({req.val2}) mod n^2) = {decrypted_sum:g}",
    }


@router.post("/bfv-fhe-calc")
async def bfv_fhe_calc_endpoint(req: BFVCalcRequest):
    """
    128-bit Lattice Security Ring-LWE BFV FHE in Native C (`libvaultcrypto.dylib`)
    over R_q = Z_{2^54}[X] / (X^2048 + 1) (HomomorphicEncryption.org Table 1).
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

    pipeline.monitor.total_fhe_computations += 1
    pipeline.monitor.record_event(
        "INFO",
        "bfv_lattice_fhe",
        f"Evaluated N=2048 128-bit PQ RLWE-BFV ciphertext × ciphertext product ({req.m1} * {req.m2} = {dec_mul_exact}).",
    )

    return {
        "scheme": "Native C 128-bit Lattice Security Ring-LWE BFV FHE",
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
        "bfv_fhe_ring": "Z_{2^54}[X]/(X^2048 + 1) [128-bit Lattice Security]",
        "llm_env": LLMClient.get_env_config(),
        "telemetry": pipeline.monitor.snapshot(),
    }
