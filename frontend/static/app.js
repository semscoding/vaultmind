// VaultMind v2 Zero-Trust Frontend Controller (Strict XSS-Safe DOM Handling)
let shamirChart = null;
// Last known VSS state per node index, so a node that has just been rejected can be marked once.
const lastNodeValid = {};
const REDUCED_MOTION = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// Chart colours mirror the CSS tokens in style.css (ink, ok, bad).
const CHART_COLORS = {
    curve: "#3D4553",
    ok: "#0B6E37",
    bad: "#B42318",
    ring: "#FCFCFD",
    tick: "#555E6D",
    grid: "rgba(18, 22, 29, 0.08)"
};

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
    if (typeof Chart === "undefined") {
        console.error("Chart.js failed to load from /static/vendor/chart.umd.min.js");
        return;
    }
    const ctx = document.getElementById("shamirChart").getContext("2d");
    shamirChart = new Chart(ctx, {
        type: "line",
        data: {
            datasets: [
                {
                    label: "GF(2⁸) Interpolated Polynomial f(x)",
                    data: [],
                    borderColor: CHART_COLORS.curve,
                    borderWidth: 1.5,
                    tension: 0.25,
                    pointBackgroundColor: CHART_COLORS.curve,
                    pointRadius: 2.5,
                    fill: false
                },
                {
                    label: "Feldman VSS Verified Shards",
                    data: [],
                    pointBackgroundColor: CHART_COLORS.ok,
                    pointBorderColor: CHART_COLORS.ring,
                    pointBorderWidth: 2,
                    pointRadius: 6,
                    showLine: false
                },
                {
                    label: "Tampered / Rejected Shards",
                    data: [],
                    pointBackgroundColor: CHART_COLORS.bad,
                    pointBorderColor: CHART_COLORS.bad,
                    pointStyle: "crossRot",
                    pointRadius: 8,
                    pointBorderWidth: 2.5,
                    showLine: false
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: REDUCED_MOTION ? false : { duration: 250 },
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
                    ticks: { stepSize: 1, color: CHART_COLORS.tick, font: { size: 12 } },
                    grid: { color: CHART_COLORS.grid }
                },
                y: {
                    min: 0,
                    max: 260,
                    ticks: { color: CHART_COLORS.tick, font: { size: 12 } },
                    grid: { color: CHART_COLORS.grid }
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
        // Mark a shard that was valid on the previous render and is now rejected (one short jolt).
        if (!node.vss_valid && lastNodeValid[node.index] === true && !REDUCED_MOTION) cls += " just-rejected";
        lastNodeValid[node.index] = !!node.vss_valid;
        card.className = cls;

        const dot = document.createElement("span");
        dot.className = "node-status-dot";
        dot.setAttribute("aria-hidden", "true");

        const nodeName = `node-0${node.index}`;
        const title = document.createElement("strong");
        title.textContent = nodeName;

        const stateSpan = document.createElement("span");
        stateSpan.className = "node-state";
        stateSpan.textContent = !node.vss_valid
            ? "TAMPERED"
            : (node.status === "QUORUM_ACTIVE" ? "QUORUM" : "VSS OK");

        const fpSpan = document.createElement("span");
        fpSpan.className = "node-fp";
        fpSpan.textContent = `#${node.fingerprint}`;

        const corruptBtn = document.createElement("button");
        corruptBtn.type = "button";
        corruptBtn.className = "btn-corrupt";
        corruptBtn.textContent = "Corrupt";
        // Visible label stays "Corrupt"; the accessible name also says which node.
        corruptBtn.setAttribute("aria-label", `Corrupt ${nodeName}`);
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

// Highlight blinded tokens. Input MUST already be HTML-escaped; the regexes only
// match fixed alphanumeric token shapes, so no user data is turned into markup.
function highlightTokens(escapedText) {
    return escapedText
        .replace(/(\[(?:ID|EMAIL|IBAN|GOV_ID|LOC|SECRET|PHONE|PERSON)_[A-Za-z0-9]{1,16}\])/g, '<span class="token-highlight-id">$1</span>')
        .replace(/(\[FHE_NUM_\d+\]\(ENC:0x[0-9a-fA-F\.]+\))/g, '<span class="token-highlight-fhe">$1</span>');
}

function prettyBody(body) {
    if (body === null || body === undefined) return "";
    if (typeof body === "string") {
        try {
            return JSON.stringify(JSON.parse(body), null, 2);
        } catch (_) {
            return body;
        }
    }
    try {
        return JSON.stringify(body, null, 2);
    } catch (_) {
        return String(body);
    }
}

// B4: show the request that was actually sent to the provider (no API key),
// never a made-up endpoint. Returns an HTML string in which every dynamic value
// is escaped with escapeHtml() before token highlighting.
function formatSafeHighlightedWire(payload) {
    const wire = (payload && payload.cloud_wire_payload) || {};
    const req = wire.actual_request;
    const blinded = (payload && payload.blinded_prompt) || wire.transmitted_prompt || "";
    const parts = [];

    if (req && req.url) {
        const method = escapeHtml(req.method || "POST");
        // Defence in depth: never display a key that slipped into the query string.
        const shownUrl = String(req.url).replace(/([?&](?:key|api_key|apikey|access_token)=)[^&#]*/gi, "$1[REDACTED]");
        parts.push(`<strong class="wire-request-line">${method} ${escapeHtml(shownUrl)}</strong>`);
        if (req.headers_redacted && typeof req.headers_redacted === "object") {
            const hdrs = Object.entries(req.headers_redacted)
                .map(([k, v]) => `${escapeHtml(k)}: ${escapeHtml(v)}`)
                .join("\n");
            if (hdrs) parts.push(`<span class="wire-headers">${hdrs}</span>`);
        }
        parts.push(highlightTokens(escapeHtml(prettyBody(req.body))));
    } else if (req) {
        // Offline engine: backend reports method/url/body = null.
        parts.push('<strong class="wire-local-only">Local only: nothing left this machine</strong>');
        if (req.note) parts.push(`<span class="wire-note">${escapeHtml(req.note)}</span>`);
        parts.push('<span class="wire-section-label">Blinded prompt, processed locally</span>');
        parts.push(highlightTokens(escapeHtml(blinded)));
    } else {
        // Older backend without actual_request: show only the blinded prompt.
        parts.push('<span class="wire-section-label">Blinded prompt (backend did not report the exact request)</span>');
        parts.push(highlightTokens(escapeHtml(blinded)));
    }
    return parts.join("\n\n");
}

function countOf(v) {
    if (Array.isArray(v)) return v.length;
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
}

// B1: show the computed leak check instead of an absolute promise.
function renderLeakCheck(payload) {
    const badge = document.getElementById("wireLockBadge");
    const box = document.getElementById("leakCheckStatus");
    const wire = (payload && payload.cloud_wire_payload) || {};
    const lc = wire.leak_check;

    box.classList.remove("hidden", "leak-ok", "leak-bad");
    badge.classList.remove("leak-ok", "leak-bad", "leak-unknown");
    box.textContent = "";

    const flagged = [];
    if (wire.contains_master_key === true) flagged.push("master key");
    if (wire.contains_raw_pii === true) flagged.push("raw PII");
    if (wire.contains_raw_secrets === true) flagged.push("raw secrets");

    const head = document.createElement("strong");
    const lines = [];

    if (lc && typeof lc === "object") {
        const spans = countOf(lc.detected_spans);
        const residual = countOf(lc.residual_matches);
        const spansTxt = spans === null ? "?" : spans;
        const residualTxt = residual === null ? "?" : residual;
        const bad = (residual !== null && residual > 0) || flagged.length > 0;
        head.textContent = bad
            ? `⚠ Leak check: ${spansTxt} spans blinded, ${residualTxt} residual matches`
            : `Leak check: ${spansTxt} spans blinded, ${residualTxt} residual matches`;
        if (bad) {
            lines.push("Detected values are still present in the outgoing payload.");
        }
        if (flagged.length) lines.push(`Flagged by backend: ${flagged.join(", ")}.`);
        if (lc.method) lines.push(`Method: ${lc.method}`);
        if (lc.note) lines.push(String(lc.note));
        else if (lc.heuristic !== false) {
            lines.push("Blinding is heuristic: only detected spans are checked. Wrap unlabeled secrets in <secret>…</secret>.");
        }
        box.classList.add(bad ? "leak-bad" : "leak-ok");
        badge.classList.add(bad ? "leak-bad" : "leak-ok");
        badge.textContent = bad ? `⚠ ${residualTxt} residual match(es)` : `✔ 0 residual matches (heuristic)`;
    } else {
        head.textContent = flagged.length
            ? `⚠ Backend flags: ${flagged.join(", ")}`
            : "Leak check not reported by backend";
        lines.push("Blinding is heuristic: only detected spans are replaced. Wrap unlabeled secrets in <secret>…</secret>.");
        if (flagged.length) {
            box.classList.add("leak-bad");
            badge.classList.add("leak-bad");
            badge.textContent = "⚠ Leak flagged";
        } else {
            badge.classList.add("leak-unknown");
            badge.textContent = "Leak check: not reported";
        }
    }

    box.appendChild(head);
    if (lines.length) {
        box.appendChild(document.createTextNode(lines.join("\n")));
    }
}

function resetLeakCheck(text) {
    const badge = document.getElementById("wireLockBadge");
    const box = document.getElementById("leakCheckStatus");
    badge.classList.remove("leak-ok", "leak-bad");
    badge.classList.add("leak-unknown");
    badge.textContent = text;
    box.classList.add("hidden");
    box.textContent = "";
}

function setPaillierBits(bits) {
    const n = Number(bits);
    if (!Number.isFinite(n) || n <= 0) return;
    document.getElementById("paillierBitsText").textContent =
        `Paillier ${n}-bit PHE + RLWE-BFV (leveled, depth 1)`;
}

// Turn any FastAPI error body into readable text.
function detailText(body, fallback) {
    if (!body) return fallback;
    const d = body.detail;
    if (typeof d === "string" && d) return d;
    if (Array.isArray(d)) {
        return d.map(e => (e && e.msg) ? e.msg : JSON.stringify(e)).join("; ");
    }
    if (d && typeof d === "object") return JSON.stringify(d);
    return fallback;
}

async function readJsonSafe(res) {
    try {
        return await res.json();
    } catch (_) {
        return null;
    }
}

function restoreRunButton(runBtn) {
    runBtn.disabled = false;
    runBtn.removeAttribute("aria-busy");
    runBtn.textContent = "Execute Zero-Trust Pipeline";
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

    const parseWarning = document.getElementById("parseWarning");

    runBtn.disabled = true;
    runBtn.setAttribute("aria-busy", "true");
    runBtn.textContent = "Running C Enclave, Paillier & RLWE-BFV...";
    decryptedOutput.className = "content-output placeholder";
    decryptedOutput.textContent = "Blinding sensitive spans, running Paillier PHE / C RLWE-BFV (leveled, depth 1), and verifying 2048-bit Feldman shards...";
    fheBanner.classList.add("hidden");
    parseWarning.classList.add("hidden");
    parseWarning.textContent = "";

    try {
        let res;
        try {
            res = await fetch("/api/process", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    prompt: text,
                    provider: provider,
                    api_key: apiKey || null
                })
            });
        } catch (netErr) {
            const e = new Error("Network error: could not reach the local VaultMind server (127.0.0.1). Is it running?");
            e.kind = "network";
            throw e;
        }

        const payload = await readJsonSafe(res);
        if (!res.ok) {
            let msg;
            if (res.status === 400) {
                msg = `Request rejected (400): ${detailText(payload, "missing or invalid API key / input.")}`;
            } else if (res.status === 502) {
                msg = `LLM provider error (502): ${detailText(payload, "the provider returned an error or no usable answer.")}`;
            } else {
                msg = `Server error (${res.status}): ${detailText(payload, res.statusText || "pipeline execution failed.")}`;
            }
            const e = new Error(msg);
            e.status = res.status;
            if (payload && typeof payload === "object" && payload.wire_request) {
                e.wireRequest = payload.wire_request;
            }
            throw e;
        }
        if (!payload || typeof payload !== "object") {
            throw new Error("Server returned an unreadable response.");
        }

        // Column 1: Local Decrypted Output (strict textContent)
        decryptedOutput.className = payload.status === "SUCCESS" ? "content-output" : "content-output error-state";
        decryptedOutput.textContent = payload.unblinded_result ?? "";
        providerUsedTag.textContent = payload.provider_used || provider;
        latencyBadge.textContent = `${payload.duration_ms ?? "--"} ms`;
        latencyBadge.classList.remove("hidden");

        const wirePayload = payload.cloud_wire_payload || {};
        setPaillierBits(
            (payload.paillier_public_key && payload.paillier_public_key.modulus_bits) ||
            wirePayload.paillier_phe_modulus_bits
        );

        // M3: surface parser warnings from the LLM phase, only when present.
        const phase3 = (payload.audit_trail || []).find(p => p && typeof p.phase === "string" && p.phase.startsWith("PHASE_3"));
        const pw = (phase3 && phase3.details && phase3.details.parse_warning) || payload.parse_warning;
        // Untrusted-LLM-output warnings (list of strings), from the response and/or audit phase 3.
        const warnList = [];
        [payload.llm_output_warnings, phase3 && phase3.details && phase3.details.llm_output_warnings].forEach(src => {
            (Array.isArray(src) ? src : []).forEach(w => {
                const s = typeof w === "string" ? w : JSON.stringify(w);
                if (s && !warnList.includes(s)) warnList.push(s);
            });
        });
        const warnLines = [];
        if (pw) {
            warnLines.push(`⚠ LLM output parse warning: ${typeof pw === "string" ? pw : JSON.stringify(pw)}`);
        }
        warnList.forEach(w => warnLines.push(`⚠ LLM output warning: ${w}`));
        if (warnLines.length > 0) {
            parseWarning.textContent = warnLines.join("\n");
            parseWarning.style.whiteSpace = "pre-wrap";
            parseWarning.classList.remove("hidden");
        }

        // Homomorphic Agent Computation Proof Banner
        if (payload.fhe_computation && !payload.fhe_computation.error) {
            const outs = Object.entries(payload.fhe_computation.decrypted_outputs || {})
                .map(([k, v]) => `${k} → ${v}`)
                .join("  |  ");
            const eng = payload.fhe_computation.engine || "Homomorphic engine";
            fheBanner.textContent =
                `[${eng}] ${payload.fhe_computation.formula}  ⟹  ${outs}`;
            fheBanner.classList.remove("hidden");
        }

        // Column 2: Escaped & Highlighted Wire View
        wireOutput.className = "wire-code-block";
        // Safe: formatSafeHighlightedWire escapes every dynamic value first.
        wireOutput.innerHTML = formatSafeHighlightedWire(payload);
        renderLeakCheck(payload);

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
                `QUORUM:      ${(r.quorum_nodes || []).join(", ")}`,
                r.rejected_tampered_nodes && r.rejected_tampered_nodes.length > 0
                    ? `REJECTED:    ${r.rejected_tampered_nodes.join(", ")} (Feldman VSS Failed!)`
                    : `VSS_CHECK:   All inspected shards valid`,
                `AES256_CT:   ${r.aes256_ciphertext_preview}`,
                `HMAC_SHA256: ${r.hmac_sha256_tag}`,
                `C_ZEROIZE:   ${r.c_enclave_zeroize}`
            ].join("\n");
        } else if (payload.enclave_error) {
            receiptOutput.className = "receipt-content receipt-blocked";
            receiptOutput.textContent = `❌ ENCLAVE BLOCKED:\n${payload.enclave_error}`;
        } else {
            receiptOutput.className = "receipt-content placeholder";
            receiptOutput.textContent = "Read-only query: no privileged Enclave write required.";
        }

        await verifyLedger(false);
    } catch (err) {
        decryptedOutput.className = "content-output error-state";
        decryptedOutput.textContent = `❌ ${err.message}`;
        providerUsedTag.textContent = "Error";
        latencyBadge.classList.add("hidden");
        if (err.wireRequest && typeof err.wireRequest === "object") {
            wireOutput.className = "wire-code-block";
            wireOutput.textContent =
                `// Provider returned HTTP ${err.status || 502}: no answer was used and nothing was sealed.\n` +
                `// Actual outbound request transmitted (API key redacted):\n\n` +
                JSON.stringify(err.wireRequest, null, 2);
        } else {
            wireOutput.className = "wire-code-block placeholder";
            wireOutput.textContent = err.status === 502
                ? "The provider returned an error, so no answer was used. Nothing was sealed."
                : "No request completed.";
        }
        resetLeakCheck("Leak check: no result");
    } finally {
        restoreRunButton(runBtn);
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
        const data = await readJsonSafe(res);
        if (!res.ok || !data) {
            throw new Error(detailText(data, `HTTP ${res.status}`));
        }
        setPaillierBits(data.modulus_bits);
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
        const data = await readJsonSafe(res);
        if (!res.ok || !data) {
            throw new Error(detailText(data, "BFV calculation error."));
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

// Per-row failure reason, if the backend sends one (field name tolerant).
function ledgerRowReason(row) {
    const r = row.verification_reason ?? row.verify_reason ?? row.failure_reason ?? row.reason ?? row.error ?? row.verification_error;
    if (r === null || r === undefined || r === "") return "";
    return typeof r === "string" ? r : JSON.stringify(r);
}

async function verifyLedger(showBanner = true) {
    const wrap = document.getElementById("ledgerTableWrap");
    const banner = document.getElementById("ledgerStatusBanner");

    try {
        const res = await fetch("/api/ledger");
        const data = await readJsonSafe(res);
        if (!res.ok || !data) {
            throw new Error(detailText(data, `HTTP ${res.status}`));
        }

        if (showBanner) {
            banner.classList.remove("hidden");
            banner.classList.toggle("banner-bad", !data.verified);
            const totalChecked = data.chain_length ?? (data.entries || []).length;
            if (data.verified) {
                banner.textContent =
                    `✔ C Enclave Constant-Time HMAC-SHA256 Verified across ${totalChecked} row(s) using quorum [${(data.quorum_used || []).join(", ")}].`;
            } else {
                let failDetail = data.error;
                if (!failDetail && Array.isArray(data.chain_errors) && data.chain_errors.length > 0) {
                    const firstErr = data.chain_errors[0];
                    const reasons = Array.isArray(firstErr.reasons) ? firstErr.reasons.join("; ") : String(firstErr.reasons || "");
                    failDetail = `Row #${firstErr.id} (${reasons || "chain/HMAC mismatch"})`;
                }
                banner.textContent = `❌ Ledger Verification Failed: ${failDetail || "HMAC mismatch detected!"}`;
            }
        }

        const entries = data.entries || [];
        wrap.textContent = "";
        if (entries.length === 0) {
            const p = document.createElement("p");
            p.className = "placeholder";
            p.textContent = "No sealed transactions in vault_ledger.db yet.";
            wrap.appendChild(p);
            return;
        }

        const table = document.createElement("table");
        table.className = "ledger-table";
        const caption = document.createElement("caption");
        caption.className = "visually-hidden";
        caption.textContent = "Sealed ledger rows and HMAC verification status";
        table.appendChild(caption);
        const thead = document.createElement("thead");
        const headRow = document.createElement("tr");
        ["ID", "Action", "Target", "AES-256 Ciphertext", "HMAC"].forEach(label => {
            const th = document.createElement("th");
            th.scope = "col";
            th.textContent = label;
            headRow.appendChild(th);
        });
        thead.appendChild(headRow);
        table.appendChild(thead);

        const tbody = document.createElement("tbody");
        entries.forEach(row => {
            const tr = document.createElement("tr");
            const ct = String(row.ciphertext_hex ?? "");
            const hm = String(row.hmac_hex ?? "");
            const cols = [
                `#${row.id}`,
                row.action ?? "",
                row.target_token ?? "",
                `${ct.slice(0, 16)}...`
            ];
            cols.forEach(val => {
                const td = document.createElement("td");
                td.textContent = val;
                tr.appendChild(td);
            });

            const hmacTd = document.createElement("td");
            if (row.hmac_verified === true) {
                hmacTd.textContent = "✔ VALID";
            } else if (row.hmac_verified === false) {
                hmacTd.textContent = "❌ BAD";
                const reason = ledgerRowReason(row);
                if (reason) {
                    const why = document.createElement("span");
                    why.className = "ledger-reason";
                    why.textContent = reason;
                    hmacTd.appendChild(why);
                }
            } else {
                hmacTd.textContent = `${hm.slice(0, 10)}...`;
            }
            tr.appendChild(hmacTd);
            tbody.appendChild(tr);
        });
        table.appendChild(tbody);
        wrap.appendChild(table);
    } catch (err) {
        wrap.textContent = `Failed to read ledger: ${err.message}`;
    }
}
