/*
 * KARMA AI Cybersecurity Copilot Module
 * DeepSeek AI Neural Engine Integration
 * Dual-Mode UI: Full-Screen OpenAI/Gemini-Style View & Gmail-Composer Floating Widget
 */

let karmaChatHistory = [
    {
        role: "assistant",
        content: "👋 Greetings! I am **KARMA AI**, your autonomous Cybersecurity SOC Copilot powered by the DeepSeek AI Neural Engine.\n\nI can assist you with:\n- 🛡️ **Honeypot Telemetry Analysis** & active threat forensics\n- 🎯 **MITRE ATT&CK Matrix** adversary profiling (T1059, T1110, T1046, etc.)\n- 🚨 **Incident Response Playbooks** & IPTables / Firewall quarantine rules\n- 🔑 **Honeytoken breach audits** & credential exposure defense\n- 🔍 **Malware, Script & Exploit Analysis** (PowerShell, Bash, SQLi, YARA rules)\n\n*How can I assist your SOC defense operations today?*"
    }
];

let isAiThinking = false;
let includeSiemContext = true;  // always ground answers in live attack telemetry

document.addEventListener("DOMContentLoaded", () => {
    initKarmaAiChat();
});

function initKarmaAiChat() {
    initFloatingWidgetEvents();
    initFullScreenChatEvents();
    renderAllChatInstances();
    setupSuggestionChips();
}

// -------------------------------------------------------------
// EVENT HANDLERS & CONTROLS
// -------------------------------------------------------------

function initFloatingWidgetEvents() {
    const fab = document.getElementById("karmaAiFab");
    const widget = document.getElementById("karmaAiFloatingWidget");
    const btnClose = document.getElementById("aiWidgetClose");
    const btnMin = document.getElementById("aiWidgetMinimize");
    const btnExpand = document.getElementById("aiWidgetExpand");
    const inputMini = document.getElementById("aiWidgetInput");
    const btnSendMini = document.getElementById("aiWidgetSendBtn");

    if (!fab || !widget) return;

    fab.addEventListener("click", () => {
        widget.classList.remove("minimized");
        widget.classList.toggle("open");
        if (widget.classList.contains("open")) {
            setTimeout(() => { if (inputMini) inputMini.focus(); }, 150);
            scrollAllChatsToBottom();
        }
    });

    if (btnClose) {
        btnClose.addEventListener("click", () => {
            widget.classList.remove("open", "minimized");
        });
    }

    if (btnMin) {
        btnMin.addEventListener("click", () => {
            widget.classList.toggle("minimized");
        });
    }

    if (btnExpand) {
        btnExpand.addEventListener("click", () => {
            // Close mini widget and switch to full screen tab
            widget.classList.remove("open", "minimized");
            const aiTabBtn = document.querySelector(".siem-sidebar .nav-item[data-tab='ai-copilot']");
            if (aiTabBtn) {
                aiTabBtn.click();
                setTimeout(() => {
                    const fullInput = document.getElementById("aiFullChatInput");
                    if (fullInput) fullInput.focus();
                }, 200);
            }
        });
    }

    if (btnSendMini && inputMini) {
        btnSendMini.addEventListener("click", () => {
            const text = inputMini.value.trim();
            if (text) {
                inputMini.value = "";
                sendUserChatMessage(text);
            }
        });

        inputMini.addEventListener("keydown", (e) => {
            if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                btnSendMini.click();
            }
        });
    }
}

function initFullScreenChatEvents() {
    const fullInput = document.getElementById("aiFullChatInput");
    const fullSendBtn = document.getElementById("aiFullSendBtn");
    const btnClear = document.getElementById("aiClearChatBtn");
    const btnExport = document.getElementById("aiExportChatBtn");
    const toggleSiem = document.getElementById("aiSiemContextToggle");

    if (fullSendBtn && fullInput) {
        fullSendBtn.addEventListener("click", () => {
            const text = fullInput.value.trim();
            if (text) {
                fullInput.value = "";
                adjustTextareaHeight(fullInput);
                sendUserChatMessage(text);
            }
        });

        fullInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                fullSendBtn.click();
            }
        });

        fullInput.addEventListener("input", () => {
            adjustTextareaHeight(fullInput);
        });
    }

    if (btnClear) {
        btnClear.addEventListener("click", () => {
            if (confirm("Reset conversation and clear KARMA AI chat history?")) {
                karmaChatHistory = [
                    {
                        role: "assistant",
                        content: "🧹 Conversation history cleared. Ready for your next cybersecurity investigation!"
                    }
                ];
                renderAllChatInstances();
            }
        });
    }

    if (btnExport) {
        btnExport.addEventListener("click", exportChatTranscript);
    }

    if (toggleSiem) {
        toggleSiem.addEventListener("change", () => {
            includeSiemContext = toggleSiem.checked;
        });
    }
}

function adjustTextareaHeight(textarea) {
    if (!textarea) return;
    textarea.style.height = 'auto';
    textarea.style.height = Math.min(textarea.scrollHeight, 180) + 'px';
}

function setupSuggestionChips() {
    const chips = document.querySelectorAll(".ai-prompt-chip");
    chips.forEach(chip => {
        chip.addEventListener("click", () => {
            const prompt = chip.getAttribute("data-prompt") || chip.innerText.trim();
            if (prompt) {
                sendUserChatMessage(prompt);
            }
        });
    });
}

// -------------------------------------------------------------
// CORE CHAT COMMUNICATION
// -------------------------------------------------------------

async function sendUserChatMessage(text) {
    if (isAiThinking || !text.trim()) return;

    // 1. Add user message to history
    karmaChatHistory.push({
        role: "user",
        content: text.trim(),
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    });

    isAiThinking = true;
    renderAllChatInstances();
    scrollAllChatsToBottom();
    updateSendButtonsState();

    try {
        const response = await fetch("/api/ai/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                messages: karmaChatHistory.slice(-12).map(({role, content}) => ({role, content: content.slice(0, 8000)})),
                include_siem_context: includeSiemContext
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP Error ${response.status}`);
        }

        const data = await response.json();
        const replyText = data.reply || "No response received from KARMA AI.";

        karmaChatHistory.push({
            role: "assistant",
            content: replyText,
            timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            model: data.model || "deepseek-chat"
        });
    } catch (err) {
        console.error("[KARMA AI Request Error]", err);
        karmaChatHistory.push({
            role: "assistant",
            content: `⚠️ **AI Engine Notice**: Unable to contact neural endpoint (${escapeHtml(err.message)}).\n\nPlease verify your internet connection or backend server status.`,
            timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        });
    } finally {
        isAiThinking = false;
        renderAllChatInstances();
        scrollAllChatsToBottom();
        updateSendButtonsState();
    }
}

function updateSendButtonsState() {
    const btn1 = document.getElementById("aiFullSendBtn");
    const btn2 = document.getElementById("aiWidgetSendBtn");

    if (btn1) {
        btn1.disabled = isAiThinking;
        btn1.innerHTML = isAiThinking ? `<span class="ai-spinner"></span>` : `<span>Send 🚀</span>`;
    }
    if (btn2) {
        btn2.disabled = isAiThinking;
        btn2.innerHTML = isAiThinking ? `⏳` : `➤`;
    }
}

// -------------------------------------------------------------
// CHAT RENDERING ENGINE
// -------------------------------------------------------------

function renderAllChatInstances() {
    const fullContainer = document.getElementById("aiFullMessagesContainer");
    const widgetContainer = document.getElementById("aiWidgetMessagesContainer");

    if (fullContainer) renderMessagesInto(fullContainer, false);
    if (widgetContainer) renderMessagesInto(widgetContainer, true);
}

function renderMessagesInto(container, isMini) {
    container.innerHTML = "";

    karmaChatHistory.forEach(msg => {
        const isUser = msg.role === "user";
        const msgDiv = document.createElement("div");
        msgDiv.className = `ai-msg-row ${isUser ? "ai-msg-user" : "ai-msg-bot"}`;

        const avatarHTML = isUser
            ? `<div class="ai-msg-avatar user-avatar" title="Security Analyst">👤</div>`
            : `<div class="ai-msg-avatar bot-avatar" title="KARMA AI Copilot">🤖</div>`;

        const nameTag = isUser ? "You (Security Analyst)" : "KARMA AI (DeepSeek Copilot)";
        const timeTag = msg.timestamp || "";

        const bubbleHTML = `
            <div class="ai-msg-bubble">
                <div class="ai-msg-header">
                    <span class="ai-msg-author">${nameTag}</span>
                    <span class="ai-msg-time">${timeTag}</span>
                </div>
                <div class="ai-msg-body">${formatMarkdown(msg.content)}</div>
            </div>
        `;

        msgDiv.innerHTML = isUser ? (bubbleHTML + avatarHTML) : (avatarHTML + bubbleHTML);
        container.appendChild(msgDiv);
    });

    // If AI is thinking, show animated typing indicator
    if (isAiThinking) {
        const typingDiv = document.createElement("div");
        typingDiv.className = "ai-msg-row ai-msg-bot ai-typing-indicator-row";
        typingDiv.innerHTML = `
            <div class="ai-msg-avatar bot-avatar">🤖</div>
            <div class="ai-msg-bubble ai-typing-bubble">
                <span class="ai-typing-dot"></span>
                <span class="ai-typing-dot"></span>
                <span class="ai-typing-dot"></span>
                <span style="font-size: 11px; color: var(--text-muted); margin-left: 6px;">KARMA AI is analyzing...</span>
            </div>
        `;
        container.appendChild(typingDiv);
    }

    // Attach copy button listeners to rendered code blocks
    container.querySelectorAll(".ai-copy-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const codeEl = btn.parentElement.querySelector("code");
            if (codeEl) {
                navigator.clipboard.writeText(codeEl.innerText).then(() => {
                    const original = btn.innerText;
                    btn.innerText = "✓ Copied!";
                    btn.style.color = "#10b981";
                    setTimeout(() => {
                        btn.innerText = original;
                        btn.style.color = "";
                    }, 2000);
                });
            }
        });
    });
}

function scrollAllChatsToBottom() {
    setTimeout(() => {
        const fullContainer = document.getElementById("aiFullMessagesContainer");
        const widgetContainer = document.getElementById("aiWidgetMessagesContainer");

        if (fullContainer) fullContainer.scrollTop = fullContainer.scrollHeight;
        if (widgetContainer) widgetContainer.scrollTop = widgetContainer.scrollHeight;
    }, 50);
}

// -------------------------------------------------------------
// MARKDOWN PARSER & FORMATTER (Code Highlighting, Tables, Lists)
// -------------------------------------------------------------

function formatMarkdown(text) {
    if (!text) return "";

    // 1. Extract and protect fenced code blocks ```lang ... ```
    const codeBlocks = [];
    let formatted = text.replace(/```([a-zA-Z0-9_\-\+]*)\n([\s\S]*?)```/g, (match, lang, code) => {
        const id = `__CODE_BLOCK_${codeBlocks.length}__`;
        const language = lang.trim() || "code";
        const cleanCode = escapeHtml(code.trim());
        codeBlocks.push(`
            <div class="ai-code-wrapper">
                <div class="ai-code-header">
                    <span class="ai-code-lang">${language.toUpperCase()}</span>
                    <button class="ai-copy-btn" title="Copy code">📋 Copy</button>
                </div>
                <pre><code class="language-${language}">${cleanCode}</code></pre>
            </div>
        `);
        return id;
    });

    // 2. Escape HTML for non-code parts
    formatted = escapeHtml(formatted);

    // 3. Headers: ### H3, ## H2, # H1
    formatted = formatted.replace(/^### (.*$)/gim, '<h4 class="ai-md-h4">$1</h4>');
    formatted = formatted.replace(/^## (.*$)/gim, '<h3 class="ai-md-h3">$1</h3>');
    formatted = formatted.replace(/^# (.*$)/gim, '<h2 class="ai-md-h2">$1</h2>');

    // 4. Blockquotes: > quote
    formatted = formatted.replace(/^\> (.*$)/gim, '<blockquote class="ai-md-quote">$1</blockquote>');

    // 5. Bold & Italic
    formatted = formatted.replace(/\*\*\*(.*?)\*\*\*/g, '<strong><em>$1</em></strong>');
    formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    formatted = formatted.replace(/\*(.*?)\*/g, '<em>$1</em>');

    // 6. Inline Code `code`
    formatted = formatted.replace(/`([^`]+)`/g, '<code class="ai-inline-code">$1</code>');

    // 7. Bullet Lists (- or *)
    formatted = formatted.replace(/^[\-\*]\s+(.*$)/gim, '<li class="ai-md-li">$1</li>');
    formatted = formatted.replace(/(<li class="ai-md-li">.*<\/li>)/gms, '<ul class="ai-md-ul">$1</ul>');

    // 8. Line breaks
    formatted = formatted.replace(/\n\n/g, '<div class="ai-md-gap"></div>');
    formatted = formatted.replace(/\n/g, '<br>');

    // 9. Restore code blocks
    codeBlocks.forEach((block, idx) => {
        formatted = formatted.replace(`__CODE_BLOCK_${idx}__`, block);
    });

    return formatted;
}

function escapeHtml(str) {
    if (!str) return "";
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// -------------------------------------------------------------
// EXPORT TRANSCRIPT
// -------------------------------------------------------------

function exportChatTranscript() {
    let transcript = `# K.A.R.M.A AI Cybersecurity SOC Transcript\n`;
    transcript += `Generated: ${new Date().toLocaleString()}\n`;
    transcript += `Platform: K.A.R.M.A Cloud SIEM • DeepSeek AI Neural Engine\n`;
    transcript += `==================================================================\n\n`;

    karmaChatHistory.forEach(msg => {
        const sender = msg.role === "user" ? "USER (SOC Analyst)" : "KARMA AI (DeepSeek Copilot)";
        const time = msg.timestamp ? ` [${msg.timestamp}]` : "";
        transcript += `### ${sender}${time}:\n${msg.content}\n\n---\n\n`;
    });

    const blob = new Blob([transcript], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `KARMA_AI_SOC_Transcript_${Date.now()}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
