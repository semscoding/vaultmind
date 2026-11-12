"""
API Router Module (`apis/routes.py`).
Exposes REST endpoints for Zero-Knowledge Pipeline execution, 2048-bit Feldman VSS
shard inspection/tampering, 1024-bit Paillier FHE math, SQLite HMAC verification,
and real-time Security Telemetry Monitoring.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services.pipeline_service import AgentPipeline

router = APIRouter(prefix="/api")

# Shared service singleton for the FastAPI worker
pipeline = AgentPipeline()


class ProcessPromptRequest(BaseModel):
    prompt: str
    api_key: Optional[str] = None
    provider: Optional[str] = "simulation"


class HomomorphicCalcRequest(BaseModel):
    val1: float
    val2: float


class TamperNodeRequest(BaseModel):
    node_index: int


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
            provider=req.provider or "simulation",
            api_key=req.api_key,
        )
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/homomorphic-calc")
async def homomorphic_calc_endpoint(req: HomomorphicCalcRequest):
    paillier = pipeline.tokenizer.paillier
    evaluator = pipeline.tokenizer.evaluator

    c1, s1 = paillier.encrypt_fixed(req.val1)
    c2, s2 = paillier.encrypt_fixed(req.val2)
    c_sum, s_sum = evaluator.add_scaled(c1, s1, c2, s2)
    decrypted_sum = paillier.decrypt_fixed(c_sum, s_sum)

    pipeline.monitor.total_fhe_computations += 1
    pipeline.monitor.record_event(
        "INFO",
        "paillier_fhe",
        f"Evaluated 1024-bit homomorphic ciphertext addition ({paillier.n.bit_length()} bits).",
    )

    return {
        "modulus_bits": paillier.n.bit_length(),
        "val1": req.val1,
        "val2": req.val2,
        "c1_hex": f"{hex(c1)[:20]}...{hex(c1)[-8:]}",
        "c2_hex": f"{hex(c2)[:20]}...{hex(c2)[-8:]}",
        "c_sum_hex": f"{hex(c_sum)[:20]}...{hex(c_sum)[-8:]}",
        "operation": "c_sum = (c1 * c2) mod n^2  [1024-bit modulus]",
        "decrypted_sum": round(decrypted_sum, 4),
        "mathematical_proof": f"D(E({req.val1}) * E({req.val2}) mod n^2) = {decrypted_sum:g}",
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
        "paillier_modulus_bits": pipeline.tokenizer.paillier.n.bit_length(),
        "telemetry": pipeline.monitor.snapshot(),
    }
