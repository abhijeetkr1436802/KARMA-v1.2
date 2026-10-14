"""
K.A.R.M.A Web Application Honeypot Sensor (Port 8080)
Simulates vulnerability web services, traps SQL Injection, XSS, and Path Traversal probes.
"""

from backend.database import mark_event_quarantine

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
import asyncio
import uvicorn
import threading
import time
from backend.config import PORT_WEB_HONEYPOT, SENSOR_HOST
from backend.security import RequestGuard
from backend.sensors.tcp_server import bind_listener, report_blocked
from backend.database import is_quarantined, get_attempt_count
import socket
from backend.engine.mitre_mapper import map_payload_to_mitre
from backend.engine.threat_score import calculate_event_risk
from backend.database import log_attack_event, record_honeytoken_hit
from backend.engine.active_defense import active_defense_engine

web_decoy_app = FastAPI(title="Corporate Admin Portal Decoy", docs_url=None, redoc_url=None, openapi_url=None)

@web_decoy_app.middleware("http")
async def enforce_sensor_access(request, call_next):
    from backend.decoy_state import is_decoy_enabled
    if not is_decoy_enabled("web_8080"):
        return JSONResponse({"detail": "Sensor disabled"}, status_code=503)
    if request.client and is_quarantined(request.client.host):
        report_blocked(request.client.host, PORT_WEB_HONEYPOT, "WEB_HONEYPOT")
        return JSONResponse({"detail": "Blocked on KARMA sensors"}, status_code=403)
    return await call_next(request)

web_decoy_app.add_middleware(RequestGuard, management=False)
broadcast_cb = None

def set_web_broadcast_callback(cb):
    global broadcast_cb
    broadcast_cb = cb

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Aegis Corporate Vault — Admin Authentication</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background: #0c101c;
            color: #f8fafc;
            font-family: 'Plus Jakarta Sans', sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
        }
        .login-box {
            background: #172033;
            padding: 40px 36px;
            border-radius: 26px;
            border: 1px solid rgba(255, 255, 255, 0.08);
            box-shadow: 12px 24px 44px rgba(0, 0, 0, 0.7),
                        inset 2px 2px 5px rgba(255, 255, 255, 0.12),
                        inset -4px -4px 10px rgba(0, 0, 0, 0.7);
            width: 380px;
            max-width: 100%;
        }
        .brand-icon {
            width: 52px;
            height: 52px;
            border-radius: 18px;
            background: linear-gradient(135deg, #3b82f6, #8b5cf6);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 26px;
            margin: 0 auto 16px auto;
            box-shadow: 6px 12px 20px rgba(59, 130, 246, 0.35),
                        inset 2px 2px 4px rgba(255, 255, 255, 0.5),
                        inset -2px -2px 4px rgba(0, 0, 0, 0.3);
        }
        h2 {
            margin-top: 0;
            color: #f8fafc;
            font-size: 20px;
            font-weight: 800;
            text-align: center;
            margin-bottom: 4px;
        }
        .sub-tag {
            text-align: center;
            font-size: 12px;
            color: #94a3b8;
            margin-bottom: 24px;
        }
        .form-group { margin-bottom: 18px; }
        label {
            display: block;
            margin-bottom: 8px;
            font-size: 12px;
            font-weight: 700;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 12px 14px;
            border-radius: 14px;
            border: 1px solid rgba(255, 255, 255, 0.08);
            background: #111726;
            color: #fff;
            font-family: inherit;
            font-size: 13.5px;
            outline: none;
            box-shadow: inset 3px 3px 7px rgba(0, 0, 0, 0.7),
                        inset -1px -1px 3px rgba(255, 255, 255, 0.05);
            transition: border-color 0.2s;
        }
        input[type="text"]:focus, input[type="password"]:focus {
            border-color: #3b82f6;
        }
        button {
            width: 100%;
            padding: 13px;
            border-radius: 14px;
            border: 1px solid rgba(255, 255, 255, 0.3);
            background: linear-gradient(135deg, #3b82f6, #2563eb);
            color: white;
            font-weight: 800;
            cursor: pointer;
            font-size: 14px;
            font-family: inherit;
            box-shadow: 6px 14px 24px rgba(0, 0, 0, 0.6),
                        inset 2px 2px 4px rgba(255, 255, 255, 0.4),
                        inset -3px -3px 6px rgba(0, 0, 0, 0.6);
            transition: transform 0.15s cubic-bezier(0.2, 0.8, 0.4, 1.2), box-shadow 0.15s ease;
            margin-top: 6px;
        }
        button:hover {
            transform: translateY(-2px);
        }
        button:active {
            transform: translateY(2px) scale(0.98);
        }
        .notice {
            font-size: 11px;
            color: #64748b;
            margin-top: 20px;
            text-align: center;
            line-height: 1.5;
        }
        a {
            color: #38bdf8;
            text-decoration: none;
            font-size: 11.5px;
            display: block;
            margin-top: 16px;
            text-align: center;
            font-weight: 600;
            transition: color 0.15s;
        }
        a:hover {
            color: #60a5fa;
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <div class="brand-icon">🛡️</div>
        <h2>Aegis Vault Portal</h2>
        <div class="sub-tag">Decoy Honeytoken Entrypoint (Port 8080)</div>
        <form method="POST" action="/login">
            <div class="form-group">
                <label>Username / Email</label>
                <input type="text" name="username" placeholder="admin@aegis-corp.internal" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="••••••••" required>
            </div>
            <button type="submit">Authenticate to Vault</button>
        </form>
        <a href="/secret-vault-admin-login-php">Backdoor Recovery Console (Legacy)</a>
        <!-- TODO(dev): remove before go-live. Integration API: GET /api/v1/auth/keys and /api/v1/admin/db_export,
             send the deploy key in the X-API-Key header (see operations/deploy.env on the file server). -->
        <div class="notice">Restricted Corporate System. All access attempts are profiled and logged into SIEM.</div>
    </div>
</body>
</html>
"""

def process_web_attack(client_ip, path, method, payload, agent=""):
    from backend.decoy_state import is_decoy_enabled
    if not is_decoy_enabled("web_8080"):
        return

    # Check for Honeytoken URL hit, or a planted (decoy) API key presented in any request
    from backend.honeytokens import tokens_used_in
    used_keys = tokens_used_in(payload, "API Key")
    is_honeytoken = used_keys or "secret-vault-admin" in path or path.startswith("/api/v1/") or "Honeytoken" in payload
    if is_honeytoken:
        if "secret-vault-admin" in path:
            record_honeytoken_hit("ht-admin-url", client_ip)
        for token in used_keys:
            record_honeytoken_hit(token["token_id"], client_ip)
        if path.endswith("/keys") and not used_keys:
            record_honeytoken_hit("ht-aws-01", client_ip)
        attack_type = "Honeytoken Compromise"
        service = "HONEYTOKEN"
    else:
        attack_type = "Web Vulnerability Probe"
        service = "WEB_HONEYPOT"

    mitre = map_payload_to_mitre(service, attack_type, payload or path)
    score, severity = calculate_event_risk(mitre['risk_score'], get_attempt_count(client_ip) + 1)

    log_id = log_attack_event(
        attacker_ip=client_ip,
        port=PORT_WEB_HONEYPOT,
        decoy_service="WEB_HONEYPOT",
        attack_type=attack_type,
        payload=f"[{method}] Path: {path} | Data: {payload}" + (f" | UA: {agent[:200]}" if agent else ""),
        mitre_id=mitre['mitre_id'],
        mitre_name=mitre['mitre_name'],
        mitre_tactic=mitre['mitre_tactic'],
        risk_score=score,
        severity=severity
    )

    from backend.database import get_geo_info
    geo = get_geo_info(client_ip)

    quarantined, _ = active_defense_engine.process_event(client_ip, score, mitre['mitre_name'])
    mark_event_quarantine(log_id, quarantined)

    if broadcast_cb:
        broadcast_cb({
            "id": log_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "attacker_ip": client_ip,
            "port": PORT_WEB_HONEYPOT,
            "decoy_service": "WEB_HONEYPOT",
            "attack_type": attack_type,
            "payload": f"[{method}] {path} | Payload: {payload}",
            "mitre_id": mitre['mitre_id'],
            "mitre_name": mitre['mitre_name'],
            "mitre_tactic": mitre['mitre_tactic'],
            "risk_score": score,
            "severity": severity,
            "quarantined": quarantined,
            "country": geo['country'],
            "city": geo['city'],
            "lat": geo['lat'],
            "lng": geo['lng'],
            "flag": geo['flag']
        })

@web_decoy_app.get("/", response_class=HTMLResponse)
def get_login(request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    process_web_attack(client_ip, request.url.path, "GET", str(request.query_params), request.headers.get("user-agent", ""))
    return HTML_TEMPLATE

@web_decoy_app.get("/secret-vault-admin-login-php", response_class=HTMLResponse)
def get_honeytoken(request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    process_web_attack(client_ip, request.url.path, "GET", "Honeytoken URL Triggered", request.headers.get("user-agent", ""))
    return "<h1 style='color:red; font-family:sans-serif; text-align:center;'>403 Access Denied - Security Alert Triggered</h1>"

@web_decoy_app.post("/login")
def post_login(request: Request, username: str = Form(...), password: str = Form(...)):
    client_ip = request.client.host if request.client else "127.0.0.1"
    payload = f"user={username[:2048]} & pass=[redacted]"
    process_web_attack(client_ip, "/login", "POST", payload, request.headers.get("user-agent", ""))
    return HTMLResponse(content="<script>alert('Invalid Authentication Credentials'); window.location.href='/';</script>")

def presented_key(request):
    """API key the client sent, so a stolen decoy key is recognised when it is used."""
    key = request.headers.get("x-api-key") or request.headers.get("authorization", "") or request.query_params.get("api_key", "")
    return f" | API key: {key[:200]}" if key else ""


@web_decoy_app.get("/robots.txt", response_class=PlainTextResponse)
def robots(request: Request):
    # Classic recon breadcrumb: "hidden" paths an attacker will try next.
    process_web_attack(request.client.host, "/robots.txt", "GET", "", request.headers.get("user-agent", ""))
    return "User-agent: *\nDisallow: /secret-vault-admin-login-php\nDisallow: /api/v1/\n"


@web_decoy_app.get("/api/v1/auth/keys")
@web_decoy_app.get("/api/v1/admin/db_export")
def api_trap(request: Request):
    from backend.decoy_state import is_decoy_enabled
    key = "api_auth_keys" if request.url.path.endswith("keys") else "api_db_export"
    if not is_decoy_enabled(key):
        return JSONResponse({"detail": "Not found"}, status_code=404)
    process_web_attack(request.client.host, request.url.path, "GET", "Honeytoken URL Triggered" + presented_key(request), request.headers.get("user-agent", ""))
    return JSONResponse({"detail": "Access denied"}, status_code=403)

@web_decoy_app.get('/documents/{token}', response_class=HTMLResponse)
def document_landing(token: str):
    from backend.documents import lookup_document
    from html import escape
    document = lookup_document(token)
    if not document:
        raise HTTPException(404, 'Document link missing or expired')
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Document acknowledgement</title>
<style>body{{font:17px system-ui;max-width:650px;margin:12vh auto;padding:24px;background:#101726;color:#eaf0f6;line-height:1.6}}button{{padding:14px 24px;background:#2563eb;color:white;border:0;border-radius:8px;font:inherit}}</style>
<h1>Aegis document register</h1><p>{escape(document['filename'])}</p>
<p>This is a KARMA security lab demonstration. Confirming sends this document's session identifier and your connection IP to the lab dashboard.</p>
<p>No software is installed and no access to your computer is granted.</p>
<form method="post"><button name="acknowledgement" value="confirm">Confirm document interaction</button></form></html>'''


@web_decoy_app.post('/documents/{token}', response_class=HTMLResponse)
def document_confirmation(request: Request, token: str, acknowledgement: str = Form(..., max_length=16)):
    from backend.documents import lookup_document, record_document_event
    document = lookup_document(token)
    if not document:
        raise HTTPException(404, 'Document link missing or expired')
    if acknowledgement != 'confirm':
        raise HTTPException(400, 'Explicit acknowledgement required')
    record_document_event(document['filename'], document['source_ip'], document['session_id'],
                          request.client.host, confirmed=True, broadcast=broadcast_cb)
    return '<!doctype html><title>Interaction recorded</title><h1>Lab interaction recorded</h1><p>The KARMA dashboard received an acknowledgement. No backdoor was opened.</p>'


@web_decoy_app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE"])
def catch_all(request: Request, full_path: str):
    client_ip = request.client.host if request.client else "127.0.0.1"
    from backend.database import get_honeytokens
    for token in get_honeytokens():
        if token["type"] == "Decoy URL" and token["token_value"] == "/" + full_path:
            record_honeytoken_hit(token["token_id"], client_ip)
            process_web_attack(client_ip, "/" + full_path, request.method, "Honeytoken URL Triggered", request.headers.get("user-agent", ""))
            return HTMLResponse("Access denied", status_code=403)
    process_web_attack(client_ip, f"/{full_path}", request.method, str(request.query_params) + presented_key(request), request.headers.get("user-agent", ""))
    return HTMLResponse(content="<h1>404 Not Found</h1>", status_code=404)

class WebHoneypotServer:
    def __init__(self, host=SENSOR_HOST, port=PORT_WEB_HONEYPOT):
        self.host, self.port = host, port
        self.server = None
        self.thread = None
        self.socket = None

    @property
    def running(self):
        return bool(self.server and self.server.started and self.thread and self.thread.is_alive())

    def start(self):
        self.socket = bind_listener(self.host, self.port)
        try:
            config = uvicorn.Config(web_decoy_app, host=self.host, port=self.port,
                                    log_level="warning", proxy_headers=False,
                                    limit_concurrency=64, timeout_keep_alive=5, timeout_graceful_shutdown=5)
            self.server = uvicorn.Server(config)
            self.thread = threading.Thread(target=asyncio.run, args=(self._serve(),), daemon=True)
            self.thread.start()
            deadline = time.monotonic() + 5
            while not self.server.started and self.thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.02)
            if not self.running:
                raise RuntimeError("Web listener failed to start")
        except BaseException:
            self.stop()
            raise

    async def _serve(self):
        from backend.runtime import ignore_connection_reset
        asyncio.get_running_loop().set_exception_handler(ignore_connection_reset)
        await self.server.serve(sockets=[self.socket])

    def stop(self):
        if self.server:
            self.server.should_exit = True
        if self.thread:
            self.thread.join(timeout=7)
        if self.socket:
            self.socket.close()
