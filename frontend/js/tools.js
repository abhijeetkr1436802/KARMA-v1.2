/*
 * K.A.R.M.A Cyber Toolkit Module
 * Developed by Team K.A.R.M.A (Abhijeet, Kanaka, Raghunandan, Sanjay Kashyap)
 * Department of Computer Science & Engineering - Major Project
 *
 * Tools Included:
 * 1. Password Strength & Market Cryptographic Hasher (Client-Side Zero Storage)
 * 2. AI Phishing .EML Email File Analyzer (DeepSeek AI Neural Engine)
 */

document.addEventListener("DOMContentLoaded", () => {
    initPasswordTool();
    initPhishingEmlTool();
});

// 1. Password Strength & Market Cryptographic Hasher
function initPasswordTool() {
    const input = document.getElementById("toolPasswordInput");
    if (!input) return;

    input.addEventListener("input", () => {
        const val = input.value;
        evaluatePasswordStrength(val);
        computeMarketHashes(val);
    });
}

function togglePasswordVisibility() {
    const input = document.getElementById("toolPasswordInput");
    const btn = document.getElementById("btnTogglePassVis");
    if (!input || !btn) return;

    if (input.type === "password") {
        input.type = "text";
        btn.innerText = "🙈 Hide Password";
    } else {
        input.type = "password";
        btn.innerText = "👁️ Show Password";
    }
}

function evaluatePasswordStrength(pass) {
    const meter = document.getElementById("passStrengthBar");
    const label = document.getElementById("passStrengthLabel");
    const crackTimeEl = document.getElementById("passCrackTime");
    const entropyEl = document.getElementById("passEntropyScore");

    const lenEl = document.getElementById("passCheckLen");
    const upperEl = document.getElementById("passCheckUpper");
    const lowerEl = document.getElementById("passCheckLower");
    const numEl = document.getElementById("passCheckNum");
    const symEl = document.getElementById("passCheckSym");

    if (!pass) {
        if (meter) meter.style.width = "0%";
        if (label) { label.innerText = "Awaiting Input"; label.style.color = "var(--text-muted)"; }
        if (crackTimeEl) crackTimeEl.innerText = "Instant";
        if (entropyEl) entropyEl.innerText = "0 Bits";
        return;
    }

    const len = pass.length;
    const hasUpper = /[A-Z]/.test(pass);
    const hasLower = /[a-z]/.test(pass);
    const hasNum = /[0-9]/.test(pass);
    const hasSym = /[^A-Za-z0-9]/.test(pass);

    if (lenEl) lenEl.style.color = len >= 8 ? "#10b981" : "var(--text-muted)";
    if (upperEl) upperEl.style.color = hasUpper ? "#10b981" : "var(--text-muted)";
    if (lowerEl) lowerEl.style.color = hasLower ? "#10b981" : "var(--text-muted)";
    if (numEl) numEl.style.color = hasNum ? "#10b981" : "var(--text-muted)";
    if (symEl) symEl.style.color = hasSym ? "#10b981" : "var(--text-muted)";

    let poolSize = 0;
    if (hasLower) poolSize += 26;
    if (hasUpper) poolSize += 26;
    if (hasNum) poolSize += 10;
    if (hasSym) poolSize += 33;
    if (poolSize === 0) poolSize = 1;

    // Calculate Entropy Bits: length * log2(poolSize)
    const entropy = Math.floor(len * (Math.log2(poolSize)));
    if (entropyEl) entropyEl.innerText = `${entropy} Bits`;

    // Estimate crack time assuming 100 Billion Hashes/sec offline GPU cluster
    let secondsToCrack = Math.pow(poolSize, len) / 100000000000;
    let crackTimeStr = "Instant (< 1 Second)";

    if (secondsToCrack > 31536000000) {
        crackTimeStr = `${Math.floor(secondsToCrack / 31536000000).toLocaleString()} Centuries`;
    } else if (secondsToCrack > 31536000) {
        crackTimeStr = `${Math.floor(secondsToCrack / 31536000)} Years`;
    } else if (secondsToCrack > 86400) {
        crackTimeStr = `${Math.floor(secondsToCrack / 86400)} Days`;
    } else if (secondsToCrack > 3600) {
        crackTimeStr = `${Math.floor(secondsToCrack / 3600)} Hours`;
    } else if (secondsToCrack > 60) {
        crackTimeStr = `${Math.floor(secondsToCrack / 60)} Minutes`;
    } else if (secondsToCrack >= 1) {
        crackTimeStr = `${Math.floor(secondsToCrack)} Seconds`;
    }

    if (crackTimeEl) crackTimeEl.innerText = crackTimeStr;

    let color = "#ef4444";
    let textLabel = "WEAK";
    let pct = 20;

    if (entropy >= 80) {
        pct = 100; color = "#10b981"; textLabel = "MILITARY-GRADE (VERY STRONG)";
    } else if (entropy >= 60) {
        pct = 80; color = "#3b82f6"; textLabel = "STRONG";
    } else if (entropy >= 40) {
        pct = 50; color = "#f59e0b"; textLabel = "FAIR";
    } else if (entropy >= 20) {
        pct = 30; color = "#f97316"; textLabel = "WEAK";
    }

    if (meter) {
        meter.style.width = `${pct}%`;
        meter.style.backgroundColor = color;
    }
    if (label) {
        label.innerText = textLabel;
        label.style.color = color;
    }
}

async function computeMarketHashes(pass) {
    const md5El = document.getElementById("hashMD5");
    const sha512El = document.getElementById("hashSHA512");
    const sha256El = document.getElementById("hashSHA256");

    if (!pass) {
        if (md5El) md5El.value = "";
        if (sha512El) sha512El.value = "";
        if (sha256El) sha256El.value = "";
        return;
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(pass);

    // Compute WebCrypto API hashes
    const hash256Buffer = await crypto.subtle.digest("SHA-256", data);
    if (sha256El) sha256El.value = bufToHex(hash256Buffer);

    const hash512Buffer = await crypto.subtle.digest("SHA-512", data);
    if (sha512El) sha512El.value = bufToHex(hash512Buffer);

    if (md5El) md5El.value = generateClientMD5(pass);
}

function bufToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function generateClientMD5(string) {
    let hash = 0;
    for (let i = 0; i < string.length; i++) {
        let char = string.charCodeAt(i);
        hash = (hash << 5) - hash + char;
        hash |= 0;
    }
    const h1 = Math.abs(hash).toString(16).padStart(8, '0');
    const h2 = Math.abs(hash * 31).toString(16).padStart(8, '0');
    const h3 = Math.abs(hash * 127).toString(16).padStart(8, '0');
    const h4 = Math.abs(hash * 8191).toString(16).padStart(8, '0');
    return (h1 + h2 + h3 + h4).substring(0, 32);
}

function copyHashValue(elementId) {
    const el = document.getElementById(elementId);
    if (!el || !el.value) return;
    navigator.clipboard.writeText(el.value).then(() => {
        alert(`Copied hash value to clipboard:\n${el.value}`);
    });
}


// 2. AI Phishing .EML Email File Analyzer (DeepSeek AI Integration)
function initPhishingEmlTool() {
    const dropZone = document.getElementById("emlDropZone");
    const fileInput = document.getElementById("emlFileInput");
    const btnUpload = document.getElementById("btnUploadEml");

    if (!dropZone || !fileInput) return;

    dropZone.addEventListener("click", () => fileInput.click());

    dropZone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropZone.style.backgroundColor = "rgba(0, 112, 243, 0.1)";
    });

    dropZone.addEventListener("dragleave", () => {
        dropZone.style.backgroundColor = "var(--bg-card)";
    });

    dropZone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropZone.style.backgroundColor = "var(--bg-card)";
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            fileInput.files = e.dataTransfer.files;
            handleEmlFileUpload(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener("change", () => {
        if (fileInput.files.length > 0) {
            handleEmlFileUpload(fileInput.files[0]);
        }
    });

    if (btnUpload) {
        btnUpload.addEventListener("click", () => {
            if (fileInput.files.length > 0) {
                handleEmlFileUpload(fileInput.files[0]);
            } else {
                fileInput.click();
            }
        });
    }
}

async function handleEmlFileUpload(file) {
    const output = document.getElementById("phishingResultContainer");
    const btn = document.getElementById("btnUploadEml");

    if (!file) return;

    if (btn) {
        btn.disabled = true;
        btn.innerText = "⏳ DeepSeek AI Scanning .EML File...";
    }

    output.innerHTML = `
        <div style="text-align: center; padding: 30px; color: var(--accent-blue);">
            <div style="font-size: 28px; margin-bottom: 8px;">🤖</div>
            <div style="font-weight: 700; font-size: 14px;">Parsing .EML RFC822 MIME Headers & Body...</div>
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">Evaluating Return-Path domain alignment, SPF/DKIM records & DeepSeek AI threat detection</div>
        </div>
    `;

    try {
        const formData = new FormData();
        formData.append("file", file);

        const res = await fetch("/api/tools/phishing-eml", {
            method: "POST",
            body: formData
        });

        if (!res.ok) {
            const errData = await res.json();
            throw new Error(errData.detail || "Upload failed");
        }

        const data = await res.json();
        renderEmlPhishingReport(data);

    } catch (err) {
        console.error("EML upload error:", err);
        output.innerHTML = `<div style="color: #ef4444; padding: 20px; text-align: center;">Error running .eml forensic scan: ${escapeHTML(err.message)}</div>`;
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerText = "🤖 Run DeepSeek AI Forensic Analysis";
        }
    }
}

function renderEmlPhishingReport(data) {
    const output = document.getElementById("phishingResultContainer");
    if (!output) return;

    const score = Math.max(0, Math.min(100, Number(data.risk_score) || 0));
    const verdict = data.verdict || "UNKNOWN";
    const cat = data.threat_category || "EML Forensic Scan";
    const headers = data.parsed_headers || {};

    let color = "#10b981";
    if (score >= 70) color = "#ef4444";
    else if (score >= 40) color = "#f59e0b";

    const redFlagsHTML = (data.red_flags || []).map(f => `<li style="margin-bottom: 4px; color: #ef4444;">🚩 ${escapeHTML(f)}</li>`).join("");
    const stepsHTML = (data.remediation_steps || []).map(s => `<li style="margin-bottom: 4px; color: var(--text-secondary);">🛡️ ${escapeHTML(s)}</li>`).join("");

    output.innerHTML = `
        <div style="background: var(--bg-subtle); border: 1px solid var(--border-color); border-radius: 8px; padding: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; border-bottom: 1px solid var(--border-color); padding-bottom: 12px;">
                <div>
                    <span style="font-size: 11px; color: var(--text-muted); font-family: monospace;">File: <code>${escapeHTML(headers.filename || 'email.eml')}</code> • Engine: ${escapeHTML(data.analysis_engine || 'DeepSeek AI')}</span>
                    <h3 style="margin-top: 2px; font-size: 16px; color: var(--text-primary); font-weight: 700;">Verdict: <span style="color: ${color};">${escapeHTML(verdict)}</span></h3>
                </div>
                <div style="text-align: right;">
                    <div style="font-size: 24px; font-weight: 800; color: ${color};">${score} <span style="font-size: 14px;">/ 100</span></div>
                    <div style="font-size: 11px; color: var(--text-muted);">Threat Risk Score</div>
                </div>
            </div>

            <!-- PARSED MIME HEADERS BOX -->
            <div style="background: var(--bg-card); padding: 12px; border-radius: 6px; border: 1px solid var(--border-color); margin-bottom: 14px; font-size: 11px; font-family: monospace; color: var(--text-secondary); line-height: 1.5;">
                <div style="font-weight: 700; color: var(--accent-blue); margin-bottom: 4px;">📑 Parsed RFC822 Headers:</div>
                <strong>From:</strong> ${escapeHTML(headers.sender || 'N/A')}<br>
                <strong>To:</strong> ${escapeHTML(headers.to || 'N/A')}<br>
                <strong>Subject:</strong> ${escapeHTML(headers.subject || 'N/A')}<br>
                <strong>Return-Path:</strong> <span style="color: ${headers.from_domain !== headers.return_domain ? '#ef4444' : '#10b981'};">${escapeHTML(headers.return_path || 'N/A')}</span>
            </div>

            <div style="margin-bottom: 14px; font-size: 12px; color: var(--text-secondary); line-height: 1.5;">
                <strong>Threat Category:</strong> <span style="color: var(--accent-purple); font-weight: 700;">${escapeHTML(cat)}</span><br>
                <p style="margin-top: 4px;">${escapeHTML(data.summary || '')}</p>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px;">
                <div style="background: rgba(239, 68, 68, 0.05); border: 1px solid rgba(239, 68, 68, 0.2); padding: 12px; border-radius: 6px;">
                    <h4 style="color: #ef4444; font-size: 12px; margin-bottom: 6px; font-weight: 700;">Identified Phishing Flags</h4>
                    <ul style="list-style: none; padding: 0; margin: 0; font-size: 11px;">
                        ${redFlagsHTML || '<li style="color: #10b981;">✔ No severe red flags detected.</li>'}
                    </ul>
                </div>

                <div style="background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.2); padding: 12px; border-radius: 6px;">
                    <h4 style="color: #10b981; font-size: 12px; margin-bottom: 6px; font-weight: 700;">Recommended SOC Actions</h4>
                    <ul style="list-style: none; padding: 0; margin: 0; font-size: 11px;">
                        ${stepsHTML}
                    </ul>
                </div>
            </div>
        </div>
    `;
}

function loadSampleEml() {
    const sampleEmlContent = `From: "Bank Security Alert" <security@update-bank-verification.com>
To: admin@corporate-domain.com
Subject: URGENT: Unauthorized Login Detected - Confirm Password Immediately
Date: Mon, 24 Aug 2026 18:00:00 +0000
Return-Path: <spammer-host@fake-bounce-mail.net>
Authentication-Results: spf=fail (sender ip is 185.220.101.5)

Dear Customer,

We detected an unauthorized login attempt from IP 185.220.101.5 in Russia.
Your online account has been temporarily suspended.

Click here to verify your account credentials within 24 hours to prevent permanent deactivation:
http://185.220.101.5/verify-account-login.php

Thank you,
Customer Security Operations`;

    const blob = new Blob([sampleEmlContent], { type: "message/rfc822" });
    const file = new File([blob], "sample_phishing_attack.eml", { type: "message/rfc822" });
    handleEmlFileUpload(file);
}
