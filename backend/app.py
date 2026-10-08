"""Authenticated management API. Public traps run on the web sensor port."""
import asyncio
import csv
import logging
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Form, Request, UploadFile, File, Query
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, IPvAnyAddress
from starlette.concurrency import run_in_threadpool
from backend import config, database as db
from backend.security import RequestGuard, load_admin_token, session_value, COOKIE_NAME, SESSION_SECONDS
from backend.engine.csv_logger import audit_csv_logger
from backend.engine.active_defense import active_defense_engine
from backend.engine.ai_analyst import generate_ai_threat_summary, generate_single_event_ai_report
from backend.honeytokens import create_honeytoken
from backend.decoy_state import initialize_decoys, toggle_decoy, add_custom_decoy
from backend.sensors.manager import SensorManager

log = logging.getLogger(__name__)
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


class ConnectionManager:
    def __init__(self):
        self.connections = {}
        self.loop = None
        self.dropped = 0

    async def connect(self, websocket):
        if len(self.connections) >= 64:
            await websocket.close(code=1013)
            return None
        await websocket.accept()
        queue = asyncio.Queue(maxsize=100)
        self.connections[websocket] = queue
        return queue

    def enqueue(self, data):
        for queue in list(self.connections.values()):
            if queue.full():
                queue.get_nowait()
                self.dropped += 1
            queue.put_nowait(data)

    def sync_broadcast(self, data):
        # Always publish the persisted canonical event, including ID and timestamp.
        event = db.get_event(data.get("id")) if data.get("id") else None
        if event:
            event["quarantined"] = data.get("quarantined", False)
            audit_csv_logger.log_event(event)
            if self.loop and self.loop.is_running():
                self.loop.call_soon_threadsafe(self.enqueue, event)

    async def close(self):
        for ws in list(self.connections):
            try:
                await ws.close(code=1001)
            except RuntimeError:
                pass
        self.connections.clear()
        self.loop = None


manager = ConnectionManager()
sensors = SensorManager(manager.sync_broadcast)
ai_slots = asyncio.Semaphore(4)


@asynccontextmanager
async def lifespan(app):
    from backend.runtime import InstanceLock
    with InstanceLock():
        app.state.admin_token = load_admin_token()
        await run_in_threadpool(db.init_db)
        await run_in_threadpool(initialize_decoys)
        await run_in_threadpool(active_defense_engine.load_mode)
        manager.loop = asyncio.get_running_loop()
        audit_csv_logger.start()
        try:
            if config.ENABLE_SENSORS:
                await run_in_threadpool(sensors.start)
            yield
        finally:
            await run_in_threadpool(sensors.stop)
            await manager.close()
            audit_csv_logger.stop()


app = FastAPI(title="KARMA SIEM", version="2.0.0", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(RequestGuard)
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/healthz")
def health():
    return {"status": "ok"}


@app.get("/login", response_class=HTMLResponse)
def login_page():
    return """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>KARMA sign in</title><style>body{background:#101726;color:#eee;font:18px system-ui;max-width:440px;margin:12vh auto;padding:24px}input,button{box-sizing:border-box;width:100%;padding:14px;margin-top:16px}p{line-height:1.6}</style>
<h1>KARMA operator sign in</h1><p>Enter the admin token configured for this installation. Local installations store the generated token in the KARMA data directory.</p>
<form method="post" action="/login"><label for="token">Admin token</label><input id="token" name="token" type="password" required autocomplete="current-password"><button>Sign in</button></form></html>"""


@app.post("/login")
def login(request: Request, token: str = Form(..., max_length=512)):
    if not secrets.compare_digest(token, request.app.state.admin_token):
        raise HTTPException(401, "Invalid credentials")
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(COOKIE_NAME, session_value(request.app.state.admin_token),
                        httponly=True, secure=config.COOKIE_SECURE, samesite="strict", max_age=SESSION_SECONDS)
    return response


@app.post("/api/logout")
def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(COOKIE_NAME)
    return response


@app.get("/")
def root():
    return FileResponse(FRONTEND_DIR / "index.html")


class QuarantineRequest(BaseModel):
    ip: IPvAnyAddress
    action: Literal["BLOCK", "UNBLOCK"]
    reason: str = Field(default="Admin intervention", max_length=500)


class HoneytokenRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    type: Literal["API Key", "Credentials", "Decoy URL"]


class DecoyToggleRequest(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    enabled: bool | None = None


class DecoyAddRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    port: int = Field(ge=1, le=65535)
    service_type: str = Field(default="Custom Decoy", max_length=80)
    description: str = Field(default="", max_length=500)


@app.get("/api/status")
def status():
    decoys = sensors.status()
    conn = db.get_db()
    try:
        web_count = conn.execute("SELECT COUNT(*) FROM attack_logs WHERE decoy_service='WEB_HONEYPOT'").fetchone()[0]
        total = db.get_total_attack_count()
        return {"platform": "KARMA SIEM", "status": "DEGRADED" if audit_csv_logger.last_error or any(d["status"] == "ERROR" for d in decoys) else "ONLINE",
                "active_honeypots": decoys, "containment_scope": "KARMA sensors only; no host firewall changes",
                "telemetry_dropped": manager.dropped, "audit_error": audit_csv_logger.last_error,
                "engagement_mode": "contain" if active_defense_engine.auto_quarantine_enabled else "observe",
                "metrics": {"total_attacks_logged": total, "web_events": web_count, "network_events": total-web_count,
                            "unique_attackers": conn.execute("SELECT COUNT(*) FROM attackers").fetchone()[0],
                            "quarantined_ips": len(db.get_quarantine_list()), "active_honeytokens": len(db.get_honeytokens()),
                            "active_decoys": sum(d["status"] == "ACTIVE" for d in decoys), "total_decoys": len(decoys)}}
    finally:
        conn.close()


@app.get("/api/logs")
def logs(limit: int = Query(50, ge=1, le=1000)):
    return db.get_recent_logs(limit)


class EngagementRequest(BaseModel):
    mode: Literal['observe', 'contain']


@app.post('/api/engagement')
def engagement(req: EngagementRequest):
    active_defense_engine.set_mode(req.mode)
    return {'mode':req.mode}


@app.get("/api/attackers")
def attackers(limit: int = Query(1000, ge=1, le=1000), offset: int = Query(0, ge=0)):
    return db.get_attackers_list(limit, offset)


@app.get('/api/document-events')
def document_events():
    conn = db.get_db()
    try:
        return [db.with_location(row) for row in conn.execute("SELECT * FROM attack_logs WHERE decoy_service='DOCUMENT_DECOY' ORDER BY id DESC LIMIT 20")]
    finally:
        conn.close()


@app.get("/api/mitre")
def mitre():
    return db.get_mitre_stats()


@app.get("/api/honeytokens")
def tokens():
    return db.get_honeytokens()


@app.post("/api/honeytokens/create")
def add_token(req: HoneytokenRequest):
    if len(db.get_honeytokens()) >= 1000:
        raise HTTPException(409, "Maximum honeytoken count reached")
    return create_honeytoken(req.name, req.type)


@app.get("/api/quarantine")
def quarantine():
    return db.get_quarantine_list()


@app.post("/api/quarantine/toggle")
def toggle_quarantine(req: QuarantineRequest):
    if req.action == "BLOCK":
        active_defense_engine.manual_quarantine(str(req.ip), req.reason)
    else:
        active_defense_engine.manual_unblock(str(req.ip))
    return {"status": "SUCCESS", "scope": "KARMA sensors only"}


@app.get("/api/ai-report/event/{log_id}")
def event_report(log_id: int):
    event = db.get_event(log_id)
    if not event:
        raise HTTPException(404, "Event not found")
    return generate_single_event_ai_report(event)


@app.get("/api/ai-report/{ip}")
def attacker_report(ip: IPvAnyAddress):
    conn = db.get_db()
    try:
        events = [dict(r) for r in conn.execute("SELECT * FROM attack_logs WHERE attacker_ip=? ORDER BY id DESC LIMIT 1000", (str(ip),))]
        profile = conn.execute("SELECT * FROM attackers WHERE ip=?", (str(ip),)).fetchone()
        if not events:
            raise HTTPException(404, "No events for this IP")
        return generate_ai_threat_summary(str(ip), events, dict(profile) if profile else {})
    finally:
        conn.close()


@app.post("/api/reset")
def reset():
    db.clear_all_data()
    return {"status": "SUCCESS"}


@app.get("/api/decoys")
def decoys():
    return sensors.status()


@app.post("/api/decoys/toggle")
def toggle(req: DecoyToggleRequest):
    try:
        result = toggle_decoy(req.id, req.enabled)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    sensors.reconcile()
    return {**result, "listeners": sensors.status()}


@app.post("/api/decoys/add")
def add_decoy(req: DecoyAddRequest):
    try:
        result = add_custom_decoy(req.name, req.port, req.service_type, req.description)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    sensors.reconcile()
    return {**result, "listeners": sensors.status()}


def csv_path(filename):
    if Path(filename).name != filename or not filename.startswith("karma_audit_") or not filename.endswith(".csv"):
        raise HTTPException(400, "Invalid audit filename")
    path = config.LOG_DIR / filename
    if path.is_symlink() or not path.is_file() or path.resolve().parent != config.LOG_DIR.resolve():
        raise HTTPException(404, "Audit file not found")
    return path


@app.get("/api/logs/csv/list")
def csv_list():
    result = []
    for path in sorted(config.LOG_DIR.glob("karma_audit_*.csv"), reverse=True)[:200]:
        if path.is_symlink():
            continue
        from datetime import datetime, timezone
        result.append({"filename": path.name, "size_bytes": path.stat().st_size,
                       "created_time": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(), "row_count": None})
    return result


@app.get("/api/logs/csv/view/{filename}")
def csv_view(filename: str):
    with csv_path(filename).open(encoding="utf-8", newline="") as file:
        import itertools
        rows = list(itertools.islice(csv.DictReader(file), 1001))
    return {"filename": filename, "total_rows": min(len(rows), 1000), "rows": rows[:1000], "truncated": len(rows) > 1000}


@app.get("/api/logs/csv/download/{filename}")
def csv_download(filename: str):
    return FileResponse(csv_path(filename), media_type="text/csv", filename=filename)


@app.delete("/api/logs/csv/delete/{filename}")
def csv_delete(filename: str):
    path = csv_path(filename)
    if audit_csv_logger.is_active and path.resolve() == Path(audit_csv_logger.file_path).resolve():
        raise HTTPException(409, "Cannot delete the active audit file")
    path.unlink()
    return {"status": "SUCCESS"}


async def run_ai(function, *args):
    if ai_slots.locked():
        raise HTTPException(429, "AI workers busy; retry later")
    async with ai_slots:
        return await run_in_threadpool(function, *args)


@app.post("/api/tools/phishing-eml")
async def phishing(file: UploadFile = File(...)):
    try:
        if not file.filename or not file.filename.lower().endswith(".eml"):
            raise HTTPException(400, "Only RFC822 .eml files are supported")
        content = await file.read(config.MAX_BODY_BYTES + 1)
        if not content or len(content) > config.MAX_BODY_BYTES:
            raise HTTPException(400, "Email is empty or too large")
        from backend.engine.phishing_analyzer import parse_and_analyze_eml
        return await run_ai(parse_and_analyze_eml, content, file.filename)
    finally:
        await file.close()


class AIChatMessage(BaseModel):
    role: Literal["user", "assistant"] = "user"
    content: str = Field(min_length=1, max_length=8000)


class AIChatRequest(BaseModel):
    messages: list[AIChatMessage] = Field(min_length=1, max_length=12)
    include_siem_context: bool = False


@app.post("/api/ai/chat")
async def chat(req: AIChatRequest):
    from backend.engine.ai_chat import generate_cybersecurity_chat_response
    return await run_ai(generate_cybersecurity_chat_response, [m.model_dump() for m in req.messages], req.include_siem_context)


@app.get("/api/ai/status")
def ai_status():
    return {"status": "configured" if config.DEEPSEEK_API_KEY else "local_fallback", "model": config.DEEPSEEK_MODEL,
            "siem_context_support": True, "external_provider": "DeepSeek"}


@app.post("/api/tester/launch")
@app.post("/api/simulator/launch")
def demo_disabled():
    raise HTTPException(403, "Run demonstration tools locally from the desktop launcher")


@app.websocket("/ws/telemetry")
async def telemetry(ws: WebSocket):
    queue = await manager.connect(ws)
    if queue is None:
        return
    import anyio
    try:
        async with anyio.create_task_group() as group:
            async def sender():
                try:
                    while True:
                        event = await queue.get()
                        await asyncio.wait_for(ws.send_json(event), timeout=5)
                except (WebSocketDisconnect, RuntimeError, asyncio.TimeoutError):
                    pass
                finally:
                    group.cancel_scope.cancel()
            group.start_soon(sender)
            try:
                while True:
                    await ws.receive_text()
            except (WebSocketDisconnect, RuntimeError):
                pass
            finally:
                group.cancel_scope.cancel()
    finally:
        manager.connections.pop(ws, None)
