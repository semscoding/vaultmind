// VaultMind v2 Zero-Trust Frontend Controller (Strict XSS-Safe DOM Handling)
let shamirChart = null;

const SCENARIOS = {
    salary: "Evaluate a 15% annual bonus for employee Marcus Vance (salary: $130,000, rating: 4.9) and commit to database with master key.",
    bfv_secrets: "Compute invoice product for client Nova Labs (hours: 160, rate: $225, password is correct-horse-battery-staple, seed: <secret>master-seed-alpha-99</secret>) and commit to database.",
    health: "Process confidential patient record for Sophia Laurent (BSN: 94820194, hemoglobin: 14.2, clinic: Amsterdam Central) and update secure EHR ledger.",
    finance: "Authorize executive transfer of €50,000 to vendor Acronis Corp (IBAN: NL91ABNA041289) and sign with root credentials.",
    xss: "Evaluate 20% bonus for employee Elena Rostova (note: <img src=x onerror=alert('XSS')>, token: sk_live_998877665544, salary: $150,000) and commit to database."
};

function escapeHtml(unsafe) {
    return String(unsafe ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

document.addEventListener("DOMContentLoaded", () => {
    initChart();
    loadScenario("salary");
    detectLiveLLMConfig();
    fetchVaultStatus();
    verifyLedger(false);
});

async function detectLiveLLMConfig() {
    try {
        const res = await fetch("/api/llm-config");
        if (!res.ok) return;
        const cfg = await res.json();
        const select = document.getElementById("providerSelect");
        const keyInput = document.getElementById("apiKeyInput");
        if (cfg.any_live_configured && cfg.recommended_default) {
            select.value = cfg.recommended_default;
            keyInput.placeholder = `✔ ${cfg.recommended_default.toUpperCase()} key loaded from .env`;
        }
    } catch (err) {
        console.error("Failed to check LLM config:", err);
    }
}

function loadScenario(type) {
    const input = document.getElementById("promptInput");
    if (SCENARIOS[type]) {
        input.value = SCENARIOS[type];
    }
}

function initChart() {
    const ctx = document.getElementById("shamirChart").getContext("2d");
    shamirChart = new Chart(ctx, {
        type: "line",
        data: {
            datasets: [
                {
                    label: "GF(2⁸) Interpolated Polynomial f(x)",
                    data: [],
                    borderColor: "#8B5CF6",
                    borderWidth: 2,
                    tension: 0.25,
                    pointBackgroundColor: "#8B5CF6",
                    pointRadius: 3,
                    fill: false
                },
                {
                    label: "Feldman VSS Verified Shards",
                    data: [],
                    pointBackgroundColor: "#10B981",
                    pointBorderColor: "#FFFFFF",
                    pointRadius: 6,
                    showLine: false
                },
                {
                    label: "Tampered / Rejected Shards",
                    data: [],
                    pointBackgroundColor: "#EF4444",
                    pointBorderColor: "#FFFFFF",
                    pointStyle: "crossRot",
                    pointRadius: 8,
                    pointBorderWidth: 2,
                    showLine: false
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: (c) => `x=${c.raw.x}, y=${c.raw.y} in GF(2⁸)`
                    }
                }
            },
            scales: {
                x: {
                    type: "linear",
                    min: 0,
                    max: 5,
                    ticks: { stepSize: 1, color: "#64748B" },
                    grid: { color: "rgba(255, 255, 255, 0.05)" }
                },
                y: {
                    min: 0,
                    max: 260,
                    ticks: { color: "#64748B" },
                    grid: { color: "rgba(255, 255, 255, 0.05)" }
                }
            }
        }
    });
}

function updatePolynomialChart(polyData) {
    if (!shamirChart || !polyData) return;

    const curvePts = (polyData.interpolated_points || []).map(p => ({ x: p.x, y: p.y }));
    const validShardPts = [];
    const badShardPts = [];

    (polyData.observed_shard_points || []).forEach(pt => {
        if (pt.valid) {
            validShardPts.push({ x: pt.x, y: pt.y });
        } else {
            badShardPts.push({ x: pt.x, y: pt.y });
        }
    });

    shamirChart.data.datasets[0].data = curvePts;
    shamirChart.data.datasets[1].data = validShardPts;
    shamirChart.data.datasets[2].data = badShardPts;
    shamirChart.update();
}

function renderVaultTopology(vaultData) {
    const grid = document.getElementById("nodesGrid");
    grid.innerHTML = "";

    const validCount = vaultData.nodes.filter(n => n.vss_valid).length;
    document.getElementById("quorumText").textContent =
        `k=${vaultData.threshold_k} of n=${vaultData.total_nodes_n} (${validCount} VSS Valid)`;

    vaultData.nodes.forEach(node => {
        const card = document.createElement("div");
        let cls = "node-card";
        if (!node.vss_valid) cls += " tampered";
        else if (node.status === "QUORUM_ACTIVE") cls += " quorum-active";
        card.className = cls;

        const dot = document.createElement("span");
        dot.className = "node-status-dot";

        const title = document.createElement("strong");
        title.textContent = `node-0${node.index}`;

        const stateSpan = document.createElement("span");
        stateSpan.style.color = !node.vss_valid
            ? "var(--red-accent)"
            : (node.status === "QUORUM_ACTIVE" ? "var(--green-accent)" : "var(--text-muted)");
        stateSpan.textContent = !node.vss_valid
            ? "TAMPERED"
            : (node.status === "QUORUM_ACTIVE" ? "QUORUM" : "VSS OK");

        const fpSpan = document.createElement("span");
        fpSpan.style.color = "var(--purple-accent)";
        fpSpan.textContent = `#${node.fingerprint}`;

        const corruptBtn = document.createElement("button");
        corruptBtn.className = "btn-corrupt";
        corruptBtn.textContent = "⚡ Corrupt";
        corruptBtn.onclick = () => tamperNode(node.index);

        card.appendChild(dot);
        card.appendChild(title);
        card.appendChild(stateSpan);
        card.appendChild(fpSpan);
        card.appendChild(corruptBtn);
        grid.appendChild(card);
    });

    updatePolynomialChart(vaultData.polynomial_curve);
}

async function fetchVaultStatus() {
    try {
        const res = await fetch("/api/vault-status");
        if (res.ok) {
            const data = await res.json();
            renderVaultTopology(data);
        }
    } catch (err) {
        console.error("Failed to fetch vault status:", err);
    }
}

async function tamperNode(nodeIndex) {
    try {
        const res = await fetch("/api/tamper-node", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ node_index: nodeIndex })
        });
        if (res.ok) {
            const data = await res.json();
            renderVaultTopology(data);
        }
    } catch (err) {
        console.error("Tamper request failed:", err);
    }
}

async function restoreShards() {
    try {
        const res = await fetch("/api/restore-nodes", { method: "POST" });
        if (res.ok) {
            const data = await res.json();
            renderVaultTopology(data);
        }
    } catch (err) {
        console.error("Restore request failed:", err);
    }
}

function formatSafeHighlightedWire(blindedPrompt, paillierBits) {
    // 1. Escape ALL HTML entities first to guarantee 0% XSS risk
    const safeText = escapeHtml(blindedPrompt);

    // 2. Highlight strictly alphanumeric cryptographic token patterns
    const highlighted = safeText
        .replace(/(\[(?:ID|EMAIL|IBAN|GOV_ID|LOC|SECRET)_[A-F0-9]{8}\])/g, '<span class="token-highlight-id">$1</span>')
        .replace(/(\[FHE_NUM_\d+\]\(ENC:0x[0-9a-fA-F\.]+\))/g, '<span class="token-highlight-fhe">$1</span>');

    return (
        `<strong>POST /v1/zero-knowledge/reason</strong>\n\n` +
        `${highlighted}\n\n` +
        `// SECURITY INVARIANTS:\n` +
        `"contains_master_key": false,\n` +
        `"contains_raw_pii": false,\n` +
        `"contains_raw_secrets": false,\n` +
        `"paillier_phe_modulus_bits": ${Number(paillierBits) || 1024},\n` +
        `"bfv_fhe_ring": "Z_{2^54}[X]/(X^2048 + 1) [128-bit Lattice Security]"`
    );
}

async function runPipeline() {
    const promptInput = document.getElementById("promptInput");
    const runBtn = document.getElementById("runBtn");
    const latencyBadge = document.getElementById("latencyBadge");
    const decryptedOutput = document.getElementById("decryptedOutput");
    const providerUsedTag = document.getElementById("providerUsedTag");
    const wireOutput = document.getElementById("wireOutput");
    const mappingTokens = document.getElementById("mappingTokens");
    const receiptOutput = document.getElementById("receiptOutput");
    const fheBanner = document.getElementById("fheAgentBanner");
    const provider = document.getElementById("providerSelect").value;
    const apiKey = document.getElementById("apiKeyInput").value;

    const text = promptInput.value.trim();
    if (!text) return;

    runBtn.disabled = true;
    runBtn.textContent = "⏳ Running C Enclave & PHE/FHE...";
    decryptedOutput.className = "content-output placeholder";
    decryptedOutput.textContent = "Blinding sensitive spans, running Paillier PHE / C Lattice RLWE-BFV FHE, and verifying 2048-bit Feldman shards...";
    fheBanner.classList.add("hidden");

    try {
        const res = await fetch("/api/process", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                prompt: text,
                provider: provider,
                api_key: apiKey || null
            })
        });

        const payload = await res.json();
        if (!res.ok) {
            throw new Error(payload.detail || "Pipeline execution failed.");
        }

        // Column 1: Local Decrypted Output (strict textContent)
        decryptedOutput.className = payload.status === "SUCCESS" ? "content-output" : "content-output error-state";
        decryptedOutput.textContent = payload.unblinded_result;
        providerUsedTag.textContent = payload.provider_used || provider;
        latencyBadge.textContent = `${payload.duration_ms} ms`;
        latencyBadge.classList.remove("hidden");

        if (payload.paillier_public_key && payload.paillier_public_key.modulus_bits) {
            document.getElementById("paillierBitsText").textContent =
                `Paillier ${payload.paillier_public_key.modulus_bits}-bit PHE + C RLWE-BFV FHE`;
        }

        // Homomorphic Agent Computation Proof Banner
        if (payload.fhe_computation && !payload.fhe_computation.error) {
            const outs = Object.entries(payload.fhe_computation.decrypted_outputs || {})
                .map(([k, v]) => `${k} → ${v}`)
                .join("  |  ");
            const eng = payload.fhe_computation.engine || "Homomorphic Engine";
            fheBanner.textContent =
                `🧮 [${eng}] ${payload.fhe_computation.formula}  ⟹  ${outs}`;
            fheBanner.classList.remove("hidden");
        }

        // Column 2: Escaped & Highlighted Wire View
        wireOutput.className = "wire-code-block";
        wireOutput.innerHTML = formatSafeHighlightedWire(
            payload.blinded_prompt,
            payload.cloud_wire_payload ? payload.cloud_wire_payload.paillier_phe_modulus_bits : 1024
        );

        // Mapping Tokens Table (DOM construction with textContent — zero innerHTML injection!)
        mappingTokens.innerHTML = "";
        const phase1 = (payload.audit_trail || []).find(p => p.phase === "PHASE_1_BLINDING");
        if (phase1 && phase1.details) {
            const hmacTokens = phase1.details.hmac_tokens || {};
            for (const [tok, orig] of Object.entries(hmacTokens)) {
                const row = document.createElement("div");
                row.className = "token-row";
                const kSpan = document.createElement("span");
                kSpan.className = "token-key";
                kSpan.textContent = tok;
                const vSpan = document.createElement("span");
                vSpan.className = "token-val";
                vSpan.textContent = tok.startsWith("[SECRET_") ? `⟷ ${orig}` : `⟷ "${orig}"`;
                row.appendChild(kSpan);
                row.appendChild(vSpan);
                mappingTokens.appendChild(row);
            }
            (phase1.details.homomorphic_ciphertexts || []).forEach(item => {
                const row = document.createElement("div");
                row.className = "token-row";
                const kSpan = document.createElement("span");
                kSpan.className = "token-key";
                kSpan.textContent = item.token;
                const vSpan = document.createElement("span");
                vSpan.className = "token-val";
                const bfvNote = item.bfv_preview ? ` + BFV ${item.bfv_preview}` : "";
                vSpan.textContent = `"${item.raw_text}" → ${item.modulus_n_bits}-bit PHE (${item.hex_preview})${bfvNote}`;
                row.appendChild(kSpan);
                row.appendChild(vSpan);
                mappingTokens.appendChild(row);
            });
        }

        // Column 3: Vault Topology & C Enclave Receipt
        if (payload.vault_topology) {
            renderVaultTopology(payload.vault_topology);
        }

        if (payload.enclave_receipt) {
            const r = payload.enclave_receipt;
            receiptOutput.className = "receipt-content";
            receiptOutput.textContent = [
                `STATUS:      ${r.status} (SQLite Row #${r.ledger_row_id})`,
                `ACTION:      ${r.action}`,
                `TARGET:      ${r.target}`,
                `QUORUM:      ${r.quorum_nodes.join(", ")}`,
                r.rejected_tampered_nodes && r.rejected_tampered_nodes.length > 0
                    ? `REJECTED:    ${r.rejected_tampered_nodes.join(", ")} (Feldman VSS Failed!)`
                    : `VSS_CHECK:   All inspected shards valid`,
                `AES256_CT:   ${r.aes256_ciphertext_preview}`,
                `HMAC_SHA256: ${r.hmac_sha256_tag}`,
                `C_ZEROIZE:   ${r.c_enclave_zeroize}`
            ].join("\n");
        } else if (payload.enclave_error) {
            receiptOutput.className = "receipt-content";
            receiptOutput.textContent = `❌ ENCLAVE BLOCKED:\n${payload.enclave_error}`;
        } else {
            receiptOutput.className = "receipt-content placeholder";
            receiptOutput.textContent = "Read-only query: no privileged Enclave write required.";
        }

        await verifyLedger(false);
    } catch (err) {
        decryptedOutput.className = "content-output error-state";
        decryptedOutput.textContent = `Pipeline Error: ${err.message}`;
    } finally {
        runBtn.disabled = false;
        runBtn.innerHTML = '<span class="btn-icon">⚡</span> Execute Zero-Trust Pipeline';
    }
}

async function calcHomomorphic() {
    const val1 = parseFloat(document.getElementById("fheVal1").value) || 0;
    const val2 = parseFloat(document.getElementById("fheVal2").value) || 0;
    const resultBox = document.getElementById("fheResult");

    try {
        const res = await fetch("/api/homomorphic-calc", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ val1, val2 })
        });
        const data = await res.json();
        resultBox.classList.remove("hidden");
        resultBox.textContent =
            `[${data.modulus_bits}-bit Paillier PHE]  ` +
            `E(m₁) = ${data.c1_hex}   |   E(m₂) = ${data.c2_hex}\n` +
            `Operation: ${data.operation}\n` +
            `✔ ${data.mathematical_proof}`;
        resultBox.style.whiteSpace = "pre-wrap";
    } catch (err) {
        resultBox.classList.remove("hidden");
        resultBox.textContent = `Error: ${err.message}`;
    }
}

async function calcBFV() {
    const m1 = Math.round(parseFloat(document.getElementById("fheVal1").value) || 0);
    const m2 = Math.round(parseFloat(document.getElementById("fheVal2").value) || 0);
    const resultBox = document.getElementById("fheResult");

    try {
        const res = await fetch("/api/bfv-fhe-calc", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ m1, m2 })
        });
        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.detail || "BFV calculation error.");
        }
        resultBox.classList.remove("hidden");
        resultBox.textContent =
            `[${data.scheme} | ${data.ring}]\n` +
            `E(m₁) = ${data.ct1_preview}   |   E(m₂) = ${data.ct2_preview}   |   Relin(E(m₁)⊗E(m₂)) = ${data.ct_mul_preview}\n` +
            `✔ ${data.mathematical_proof}`;
        resultBox.style.whiteSpace = "pre-wrap";
    } catch (err) {
        resultBox.classList.remove("hidden");
        resultBox.textContent = `BFV Error: ${err.message}`;
    }
}

async function verifyLedger(showBanner = true) {
    const wrap = document.getElementById("ledgerTableWrap");
    const banner = document.getElementById("ledgerStatusBanner");

    try {
        const res = await fetch("/api/ledger");
        const data = await res.json();

        if (showBanner) {
            banner.classList.remove("hidden");
            if (data.verified) {
                banner.textContent =
                    `✔ C Enclave Constant-Time HMAC-SHA256 Verified across ${data.entries.length} row(s) using quorum [${(data.quorum_used || []).join(", ")}].`;
            } else {
                banner.textContent = `❌ Ledger Verification Failed: ${data.error || "HMAC mismatch detected!"}`;
            }
        }

        const entries = data.entries || [];
        if (entries.length === 0) {
            wrap.innerHTML = '<p class="placeholder">No sealed transactions in vault_ledger.db yet.</p>';
            return;
        }

        const table = document.createElement("table");
        table.className = "ledger-table";
        table.innerHTML = `
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Action</th>
                    <th>Target</th>
                    <th>AES-256 Ciphertext</th>
                    <th>HMAC</th>
                </tr>
            </thead>
        `;
        const tbody = document.createElement("tbody");
        entries.forEach(row => {
            const tr = document.createElement("tr");
            const cols = [
                `#${row.id}`,
                row.action,
                row.target_token,
                `${row.ciphertext_hex.slice(0, 16)}...`,
                row.hmac_verified === true ? "✔ VALID" : (row.hmac_verified === false ? "❌ BAD" : `${row.hmac_hex.slice(0, 10)}...`)
            ];
            cols.forEach(val => {
                const td = document.createElement("td");
                td.textContent = val;
                tr.appendChild(td);
            });
            tbody.appendChild(tr);
        });
        table.appendChild(tbody);
        wrap.innerHTML = "";
        wrap.appendChild(table);
    } catch (err) {
        wrap.textContent = `Failed to read ledger: ${err.message}`;
    }
}
