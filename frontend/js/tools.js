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

// Top real-world breach passwords (rockyou / HaveIBeenPwned "top" lists, abridged).
// A hit here is the proof that weak passwords fall instantly: attackers try these FIRST.
const COMMON_PASSWORDS = ["123456","password","12345678","qwerty","123456789","12345","1234","111111","1234567","dragon","123123","baseball","abc123","football","monkey","letmein","696969","shadow","master","666666","qwertyuiop","123321","mustang","1234567890","michael","654321","superman","1qaz2wsx","7777777","121212","000000","qazwsx","123qwe","killer","trustno1","jordan","jennifer","zxcvbnw","asdfgh","hunter","buster","soccer","harley","batman","andrew","tigger","sunshine","iloveyou","2000","charlie","robert","thomas","hockey","ranger","daniel","starwars","klaster","112233","george","computer","michelle","jessica","pepper","1111","zxcvbn","555555","11111111","131313","freedom","777777","pass","maggie","159753","aaaaaa","ginger","princess","joshua","cheese","amanda","summer","love","ashley","nicole","chelsea","biteme","matthew","access","yankees","987654321","dallas","austin","thunder","taylor","matrix","password1","qwerty123","admin","welcome","login","abc12345","passw0rd","p@ssw0rd","test","guest","root","changeme","secret"];

function fmtDuration(seconds) {
    if (seconds < 1e-3) return "instantly";
    const u = [["year",31557600],["day",86400],["hour",3600],["minute",60],["second",1]];
    for (const [name, s] of u) {
        if (seconds >= s) { const v = seconds / s; return (v >= 1e6 ? v.toExponential(1) : Math.round(v).toLocaleString()) + " " + name + (Math.round(v)===1?"":"s"); }
    }
    return seconds.toExponential(1) + " seconds";
}

function evaluatePasswordStrength(pass) {
    const meter = document.getElementById("passStrengthBar");
    const label = document.getElementById("passStrengthLabel");
    const crackTimeEl = document.getElementById("passCrackTime");
    const entropyEl = document.getElementById("passEntropyScore");
    const proofEl = document.getElementById("passProof");

    const lenEl = document.getElementById("passCheckLen");
    const upperEl = document.getElementById("passCheckUpper");
    const lowerEl = document.getElementById("passCheckLower");
    const numEl = document.getElementById("passCheckNum");
    const symEl = document.getElementById("passCheckSym");

    if (!pass) {
        if (meter) meter.style.width = "0%";
        if (label) { label.innerText = "Awaiting Input"; label.style.color = "var(--text-muted)"; }
        if (crackTimeEl) crackTimeEl.innerText = "—";
        if (entropyEl) entropyEl.innerText = "0 Bits";
        if (proofEl) proofEl.innerHTML = "";
        return;
    }

    const len = pass.length;
    const hasUpper = /[A-Z]/.test(pass);
    const hasLower = /[a-z]/.test(pass);
    const hasNum = /[0-9]/.test(pass);
    const hasSym = /[^A-Za-z0-9]/.test(pass);

    if (lenEl) lenEl.style.color = len >= 12 ? "#10b981" : "var(--text-muted)";
    if (upperEl) upperEl.style.color = hasUpper ? "#10b981" : "var(--text-muted)";
    if (lowerEl) lowerEl.style.color = hasLower ? "#10b981" : "var(--text-muted)";
    if (numEl) numEl.style.color = hasNum ? "#10b981" : "var(--text-muted)";
    if (symEl) symEl.style.color = hasSym ? "#10b981" : "var(--text-muted)";

    let pool = 0;
    if (hasLower) pool += 26;
    if (hasUpper) pool += 26;
    if (hasNum) pool += 10;
    if (hasSym) pool += 33;
    if (pool === 0) pool = 1;

    const entropy = Math.round(len * Math.log2(pool));
    if (entropyEl) entropyEl.innerText = `${entropy} Bits`;

    // Is it a known breached password? That is the real proof of "instant".
    const breachIndex = COMMON_PASSWORDS.indexOf(pass.toLowerCase());
    const breached = breachIndex !== -1;

    // Transparent math: combinations = pool^len, attacker tries half on average.
    // Attacker speeds are public hashcat-class benchmarks.
    const SCENARIOS = [
        ["Online guess (rate-limited login)", 100],
        ["Offline, slow hash (bcrypt/argon2)", 1e4],
        ["Offline, fast hash (MD5/SHA, 1 GPU)", 1e10],
        ["Offline, fast hash (GPU farm)", 1e12],
    ];
    const combos = Math.pow(pool, len);
    const avg = combos / 2;
    const fastHashSeconds = avg / 1e10;

    // Headline metric = fast-hash single GPU (stated assumption on the card)
    if (crackTimeEl) crackTimeEl.innerText = breached ? "Instant" : fmtDuration(fastHashSeconds);

    // Strength label
    let color = "#ef4444", textLabel = "VERY WEAK", pct = 15;
    if (breached) { color = "#ef4444"; textLabel = "BREACHED — DO NOT USE"; pct = 8; }
    else if (entropy >= 80) { pct = 100; color = "#10b981"; textLabel = "VERY STRONG"; }
    else if (entropy >= 60) { pct = 80; color = "#3b82f6"; textLabel = "STRONG"; }
    else if (entropy >= 40) { pct = 55; color = "#f59e0b"; textLabel = "FAIR"; }
    else if (entropy >= 28) { pct = 35; color = "#f97316"; textLabel = "WEAK"; }
    if (meter) { meter.style.width = `${pct}%`; meter.style.backgroundColor = color; }
    if (label) { label.innerText = textLabel; label.style.color = color; }

    // Build the proof panel
    if (!proofEl) return;
    const rows = SCENARIOS.map(([name, rate]) => {
        const t = breached ? "instantly (wordlist)" : fmtDuration(avg / rate);
        const danger = (breached || (avg / rate) < 60);
        return `<tr>
            <td style="padding:6px 10px;border-bottom:1px solid var(--border-color);">${name}</td>
            <td style="padding:6px 10px;border-bottom:1px solid var(--border-color);font-family:monospace;color:var(--text-muted);">${rate.toExponential(0)} /s</td>
            <td style="padding:6px 10px;border-bottom:1px solid var(--border-color);font-weight:800;color:${danger?'#ef4444':'#10b981'};">${t}</td>
        </tr>`;
    }).join("");

    const breachBanner = breached ? `
        <div style="background:rgba(239,68,68,0.1);border:2px solid #ef4444;border-radius:8px;padding:12px 14px;margin-bottom:14px;">
            <div style="font-weight:800;color:#ef4444;font-size:13px;">🚨 Found in public breach wordlists</div>
            <div style="font-size:12px;color:var(--text-secondary);margin-top:4px;line-height:1.6;">
                This password sits near the top of real leaked-password lists (e.g. <code>rockyou.txt</code>, ~#${breachIndex + 1} here).
                Attackers run these lists first, so it falls <strong>instantly</strong> — brute-force math never even applies. <em>This is the proof.</em>
            </div>
        </div>` : "";

    proofEl.innerHTML = `
        ${breachBanner}
        <div class="clay-card" style="padding:16px 18px;">
            <h4 style="font-size:13px;font-weight:800;color:var(--text-primary);margin-bottom:8px;">🧮 How the crack time is calculated (the proof)</h4>
            <div style="font-size:12px;color:var(--text-secondary);line-height:1.7;margin-bottom:10px;font-family:monospace;">
                character set N = <b>${pool}</b> &nbsp;·&nbsp; length L = <b>${len}</b><br>
                combinations = N<sup>L</sup> = ${pool}<sup>${len}</sup> ≈ <b>${combos.toExponential(2)}</b><br>
                time = (combinations ÷ 2) ÷ guesses-per-second
            </div>
            <table style="width:100%;border-collapse:collapse;font-size:12px;">
                <thead><tr style="text-align:left;color:var(--text-muted);">
                    <th style="padding:6px 10px;">Attacker scenario</th>
                    <th style="padding:6px 10px;">Guess rate</th>
                    <th style="padding:6px 10px;">Time to crack</th>
                </tr></thead>
                <tbody>${rows}</tbody>
            </table>
            <p style="font-size:11px;color:var(--text-muted);margin-top:10px;line-height:1.6;">
                Rates are public hashcat-class benchmarks: a single modern GPU does ~10<sup>10</sup> fast-hash (MD5/SHA-1) guesses/sec.
                Slow hashes like bcrypt/argon2 are deliberately ~10<sup>6</sup>× slower — which is why the hashes below matter.
            </p>
        </div>`;
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

// MD5 via blueimp-md5 (vendored, verified: md5("abc")==="900150983cd24fb0d6963f7d28e17f72").
function generateClientMD5(str) {
    return (typeof md5 === "function") ? md5(str) : "md5 library not loaded";
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
    const btnScanText = document.getElementById("btnScanEmlText");

    if (btnScanText) {
        btnScanText.addEventListener("click", () => {
            const text = (document.getElementById("emlPasteInput") || {}).value || "";
            if (!text.trim()) { document.getElementById("emlPasteInput")?.focus(); return; }
            handleEmlText(text);
        });
    }

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

}

function showEmlScanning() {
    const output = document.getElementById("phishingResultContainer");
    if (output) output.innerHTML = `
        <div style="text-align: center; padding: 30px; color: var(--accent-blue);">
            <div style="font-size: 28px; margin-bottom: 8px;">🔍</div>
            <div style="font-weight: 700; font-size: 14px;">Parsing headers &amp; body, scoring threat signals…</div>
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">Return-Path alignment, SPF/DKIM, urgency cues, embedded links</div>
        </div>`;
}

async function handleEmlText(source) {
    const btn = document.getElementById("btnScanEmlText");
    if (btn) { btn.disabled = true; btn.innerText = "⏳ Scanning…"; }
    showEmlScanning();
    try {
        const res = await fetch("/api/tools/phishing-text", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ source: source.slice(0, 200000) })
        });
        if (!res.ok) throw new Error((await res.json()).detail || "Scan failed");
        renderEmlPhishingReport(await res.json());
    } catch (err) {
        const output = document.getElementById("phishingResultContainer");
        if (output) output.innerHTML = `<div style="color:#ef4444;padding:20px;text-align:center;">Error: ${escapeHTML(err.message)}</div>`;
    } finally {
        if (btn) { btn.disabled = false; btn.innerText = "🔍 Scan Pasted Email"; }
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

    const box = document.getElementById("emlPasteInput");
    if (box) box.value = sampleEmlContent;
    handleEmlText(sampleEmlContent);
}
