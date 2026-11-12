"""
Security & Cryptographic Telemetry Monitoring Module.
Tracks blinding metrics, 1024-bit Paillier FHE latencies, C-enclave seals,
and 2048-bit Feldman VSS tamper alerts in real time without logging any plaintext secrets.
"""

from collections import deque
import time
from typing import Any, Deque, Dict, List


class SecurityMonitor:
    def __init__(self, max_events: int = 50):
        self.started_at = time.time()
        self.total_requests = 0
        self.total_hmac_tokens_masked = 0
        self.total_fhe_encryptions = 0
        self.total_fhe_computations = 0
        self.total_enclave_seals = 0
        self.tamper_alerts_detected = 0
        self.blocked_enclave_actions = 0
        self._latencies_ms: Deque[float] = deque(maxlen=100)
        self._events: Deque[Dict[str, Any]] = deque(maxlen=max_events)

    def record_event(self, level: str, component: str, message: str) -> None:
        self._events.appendleft(
            {
                "timestamp": time.time(),
                "level": level.upper(),
                "component": component,
                "message": message,
            }
        )

    def record_pipeline_run(
        self,
        duration_ms: float,
        hmac_count: int,
        fhe_enc_count: int,
        fhe_computed: bool,
        sealed: bool,
        blocked: bool,
        rejected_nodes_count: int,
    ) -> None:
        self.total_requests += 1
        self.total_hmac_tokens_masked += hmac_count
        self.total_fhe_encryptions += fhe_enc_count
        if fhe_computed:
            self.total_fhe_computations += 1
        if sealed:
            self.total_enclave_seals += 1
        if blocked:
            self.blocked_enclave_actions += 1
        if rejected_nodes_count > 0:
            self.tamper_alerts_detected += rejected_nodes_count

        self._latencies_ms.append(duration_ms)

        if blocked:
            self.record_event(
                "CRITICAL",
                "enclave",
                f"Blocked privileged execution ({rejected_nodes_count} tampered shard(s)).",
            )
        elif rejected_nodes_count > 0:
            self.record_event(
                "WARNING",
                "feldman_vss",
                f"Detected {rejected_nodes_count} tampered shard(s); quorum failover succeeded.",
            )
        else:
            self.record_event(
                "INFO",
                "pipeline",
                f"Processed zero-knowledge request in {duration_ms:.2f} ms (masked={hmac_count}, fhe={fhe_enc_count}).",
            )

    def record_tamper_simulation(self, node_index: int) -> None:
        self.tamper_alerts_detected += 1
        self.record_event(
            "WARNING",
            "feldman_vss",
            f"Disk shard node_0{node_index}.json mutated; 2048-bit Feldman VSS quarantine armed.",
        )

    def snapshot(self) -> Dict[str, Any]:
        avg_ms = (
            round(sum(self._latencies_ms) / len(self._latencies_ms), 2)
            if self._latencies_ms
            else 0.0
        )
        return {
            "uptime_seconds": round(time.time() - self.started_at, 1),
            "counters": {
                "total_requests": self.total_requests,
                "total_hmac_tokens_masked": self.total_hmac_tokens_masked,
                "total_fhe_encryptions": self.total_fhe_encryptions,
                "total_fhe_computations": self.total_fhe_computations,
                "total_enclave_seals": self.total_enclave_seals,
                "tamper_alerts_detected": self.tamper_alerts_detected,
                "blocked_enclave_actions": self.blocked_enclave_actions,
            },
            "performance": {
                "average_pipeline_latency_ms": avg_ms,
                "samples": len(self._latencies_ms),
            },
            "recent_events": list(self._events)[:15],
        }
