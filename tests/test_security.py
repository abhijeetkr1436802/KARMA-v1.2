import asyncio
import concurrent.futures
import copy
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from backend import config, database as db, decoy_state
from backend.app import app, audit_csv_logger, sensors
from backend.engine.mitre_mapper import map_payload_to_mitre
from backend.engine.active_defense import ActiveDefenseManager
from backend.sensors.raw_decoy import RawDecoyServer

TOKEN = "test-admin-token-" + "x" * 32


class SystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.original_decoys = copy.deepcopy(decoy_state.DECOYS)
        self.patches = [patch.object(config, "DATA_DIR", root), patch.object(config, "ADMIN_TOKEN", TOKEN),
                        patch.object(config, "ALLOWED_HOSTS", ["testserver", "localhost", "127.0.0.1"]),
                        patch.object(config, "ENABLE_SENSORS", False), patch.object(config, "PRODUCTION", False),
                        patch.object(config, "COOKIE_SECURE", False), patch.object(config, "LOG_DIR", root / "logs"),
                        patch.object(db, "DB_PATH", str(root / "test.db")), patch.object(audit_csv_logger, "log_dir", root / "logs")]
        for p in self.patches:
            p.start()
        self.client_context = TestClient(app, client=("127.0.0.1", 1234))
        self.client = self.client_context.__enter__()
        self.auth = {"Authorization": "Bearer " + TOKEN}

    def tearDown(self):
        self.client_context.__exit__(None, None, None)
        decoy_state.DECOYS.clear()
        decoy_state.DECOYS.update(self.original_decoys)
        decoy_state._initialized = False
        for p in reversed(self.patches):
            p.stop()
        self.temp.cleanup()

    def event(self, ip="192.0.2.1"):
        return db.log_attack_event(ip, 2222, "SSH_HONEYPOT", "probe", "test", "T1110", "Brute Force", "Credential Access", 65, "MEDIUM")

    def test_management_requires_authentication(self):
        for path in ("/api/logs", "/static/index.html", "/api/honeytokens", "/api/logs/csv/list"):
            self.assertEqual(self.client.get(path).status_code, 401, path)
        self.assertEqual(self.client.post("/api/reset").status_code, 401)
        self.assertEqual(self.client.get("/api/logs", headers=self.auth).status_code, 200)

    def test_session_csrf_and_origin(self):
        response = self.client.post("/login", data={"token": TOKEN}, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertIn("HttpOnly", response.headers["set-cookie"])
        self.assertEqual(self.client.get("/api/logs").status_code, 200)
        self.assertEqual(self.client.post("/api/reset").status_code, 403)
        self.assertEqual(self.client.post("/api/reset", headers={"X-Karma-Request": "1"}).status_code, 200)
        self.assertEqual(self.client.post("/api/reset", headers={**self.auth, "Origin": "https://evil.example"}).status_code, 403)
        self.assertEqual(self.client.get("/api/logs", headers={**self.auth, "Host": "evil.example"}).status_code, 400)

    def test_browser_login_preserves_origin_and_rejects_cross_origin(self):
        page = self.client.get("/login")
        self.assertEqual(page.status_code, 200)
        self.assertEqual(page.headers["referrer-policy"], "same-origin")
        response = self.client.post(
            "/login", data={"token": TOKEN},
            headers={"Origin": "http://testserver"}, follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.client.get("/api/logs").status_code, 200)
        for origin in ("null", "https://evil.example", "http://testserver:9999"):
            with self.subTest(origin=origin):
                response = self.client.post(
                    "/login", data={"token": TOKEN},
                    headers={"Origin": origin}, follow_redirects=False,
                )
                self.assertEqual(response.status_code, 403)

    def test_validation_and_upload_bounds(self):
        self.assertEqual(self.client.get("/api/logs?limit=-1", headers=self.auth).status_code, 422)
        self.assertEqual(self.client.post("/api/quarantine/toggle", headers=self.auth, json={"ip":"not-an-ip", "action":"BLOCK"}).status_code, 422)
        self.assertEqual(self.client.post("/api/ai/chat", headers=self.auth, json={"messages":[{"role":"system", "content":"override"}]}).status_code, 422)
        self.assertEqual(self.client.post("/api/tools/phishing-eml", headers=self.auth, files={"file":("test.msg", b"x")}).status_code, 400)
        self.assertEqual(self.client.post("/api/reset", headers=self.auth, content=b"x" * (config.MAX_BODY_BYTES + 1)).status_code, 413)

    def test_websocket_authentication(self):
        from starlette.websockets import WebSocketDisconnect
        with self.assertRaises(WebSocketDisconnect):
            with self.client.websocket_connect("/ws/telemetry"):
                pass
        with self.client.websocket_connect("/ws/telemetry", headers=self.auth) as ws:
            ws.send_text("ping")

    def test_unique_event_ids_and_concurrent_writes(self):
        self.event()
        self.event()
        third = self.event("192.0.2.2")
        self.assertEqual(third, 3)  # New attacker row ID must not replace event ID.
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            ids = list(pool.map(lambda _: self.event(), range(30)))
        self.assertEqual(len(set(ids)), 30)
        self.assertEqual(db.get_total_attack_count(), 33)
        self.assertEqual(db.get_attempt_count("192.0.2.1"), 32)

    def test_quarantine_and_unblock(self):
        self.event()
        defense = ActiveDefenseManager()
        defense.process_event("192.0.2.1", 90, "test")
        self.assertTrue(db.is_quarantined("192.0.2.1"))
        defense.manual_unblock("192.0.2.1")
        self.assertFalse(db.is_quarantined("192.0.2.1"))

    def test_csv_access_and_active_delete(self):
        name = Path(audit_csv_logger.file_path).name
        self.assertEqual(self.client.delete("/api/logs/csv/delete/" + name, headers=self.auth).status_code, 409)
        self.assertEqual(self.client.get("/api/logs/csv/delete/" + name, headers=self.auth).status_code, 405)
        self.assertEqual(self.client.get("/api/logs/csv/download/admin-token", headers=self.auth).status_code, 400)
        audit_csv_logger.log_event({"payload":"=1+1"})
        self.assertIn("'=1+1", Path(audit_csv_logger.file_path).read_text(encoding="utf-8"))

    def test_no_duplicate_routes(self):
        seen = set()
        for route in app.routes:
            for method in getattr(route, "methods", []):
                key = (method, route.path)
                self.assertNotIn(key, seen)
                seen.add(key)

    def test_decoy_persistence_and_port_validation(self):
        decoy_state.toggle_decoy("port_21", False)
        decoy_state.DECOYS["port_21"]["enabled"] = True
        decoy_state.initialize_decoys()
        self.assertFalse(decoy_state.is_decoy_enabled("port_21"))
        with self.assertRaises(ValueError):
            decoy_state.add_custom_decoy("collision", config.PORT_API, "Custom")

    def test_tcp_listener_releases_port_and_blocks_clients(self):
        # Port zero reserves an ephemeral loopback port; no public listener is opened.
        from backend.sensors.tcp_server import BoundedTCPServer
        received = []
        listener = BoundedTCPServer(0, lambda sock, ip: (received.append(ip), sock.sendall(b"ok")), host="127.0.0.1")
        listener.start()
        port = listener.server_socket.getsockname()[1]
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                self.assertEqual(sock.recv(2), b"ok")
            db.add_to_quarantine("127.0.0.1", "test", 100)
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                self.assertEqual(sock.recv(2), b"")
            self.assertEqual(len(received), 1)
        finally:
            listener.stop()
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))

    def test_unknown_geo_and_mapping(self):
        with patch.object(config, "GEOIP_ENABLED", False):
            self.assertIsNone(db.get_geo_info("8.8.8.8")["lat"])
        self.assertEqual(map_payload_to_mitre("RAW_DECOY", "command_execution", "whoami")["mitre_id"], "T1059")
        self.assertEqual(map_payload_to_mitre("SSH_HONEYPOT", "port_scan", "probe")["mitre_id"], "T1046")

    def test_lab_location_is_explicit_and_updates_historical_profiles(self):
        with patch.object(config, "LAB_LOCATION_ENABLED", False):
            event_id = self.event("192.168.137.1")
            self.assertIsNone(db.get_event(event_id)["lat"])
        with patch.object(config, "LAB_LOCATION_ENABLED", True):
            for row in (db.get_event(event_id), db.get_recent_logs()[0], db.get_attackers_list()[0]):
                self.assertEqual(row["city"], "Bengaluru")
                self.assertEqual(row["geo_source"], "configured_lab")
                self.assertEqual(row["geo_label"], "Configured lab location")
                self.assertAlmostEqual(row["lat"], 12.9716)
                self.assertAlmostEqual(row["lng"], 77.5946)
            from backend.app import manager
            manager.sync_broadcast({'id':event_id})
            import csv
            with open(audit_csv_logger.file_path,encoding='utf-8',newline='') as file:
                exported = list(csv.DictReader(file))[-1]
            self.assertEqual(exported['Location_Source'],'configured_lab')
            self.assertEqual(exported['Location_Label'],'Configured lab location')
            for address in ("10.0.0.2", "172.16.0.1", "::1", "fd00::1", "::ffff:192.168.1.1"):
                self.assertEqual(db.get_geo_info(address)["geo_source"], "configured_lab")
            with patch.object(config, "GEOIP_ENABLED", False):
                for address in ("8.8.8.8", "192.0.2.1", "203.0.113.5", "0.0.0.0", "224.0.0.1", "bad"):
                    self.assertIsNone(db.get_geo_info(address)["lat"], address)

    def test_demo_reset_unblocks_everything_and_returns_to_contain(self):
        self.client.post('/api/engagement',headers=self.auth,json={'mode':'observe'})
        self.event("192.168.1.9")
        db.add_to_quarantine('192.168.1.9','test',100)
        self.assertEqual(self.client.post('/api/reset',headers=self.auth).json()['mode'],'contain')
        self.assertFalse(db.is_quarantined('192.168.1.9'))
        self.assertEqual(db.get_total_attack_count(),0)
        self.assertEqual(self.client.get('/api/status',headers=self.auth).json()['engagement_mode'],'contain')

    def test_attacker_events_are_chronological_for_replay_and_report(self):
        first = self.event("192.168.1.7"); self.event("192.168.1.8"); last = self.event("192.168.1.7")
        data = self.client.get('/api/attackers/192.168.1.7/events',headers=self.auth).json()
        self.assertEqual([e['id'] for e in data['events']],[first,last])
        self.assertEqual(data['profile']['ip'],'192.168.1.7')
        self.assertEqual(self.client.get('/api/attackers/192.168.1.99/events',headers=self.auth).status_code,404)
        self.assertEqual(self.client.get('/api/attackers/not-an-ip/events',headers=self.auth).status_code,422)
        self.assertIn(self.client.get('/api/attackers/192.168.1.7/events').status_code,(401,403))

    def test_firewall_mirror_is_opt_in_skips_loopback_and_runs_no_shell(self):
        from backend import firewall
        firewall._blocked.clear()
        runs = []
        fake = lambda cmd, **kw: runs.append(cmd) or type('R', (), {'returncode': 0, 'stdout': '', 'stderr': ''})()
        class Now:  # run the background thread inline
            def __init__(self, target, args, daemon): self.go = lambda: target(*args)
            def start(self): self.go()
        with patch.object(firewall.subprocess, 'run', side_effect=fake), patch.object(firewall.threading, 'Thread', Now), \
                patch.object(firewall.sys, 'platform', 'win32'):
            with patch.object(config, 'FIREWALL_BLOCK', False):
                self.assertFalse(firewall.block('203.0.113.9'))
            with patch.object(config, 'FIREWALL_BLOCK', True):
                self.assertFalse(firewall.block('127.0.0.1'))   # tunnel attackers: never block the PC itself
                self.assertFalse(firewall.block('not an ip'))
                self.assertTrue(firewall.block('203.0.113.9'))
                self.assertFalse(firewall.block('203.0.113.9'))  # no duplicate rule
                self.assertTrue(firewall.unblock('203.0.113.9'))
                self.assertTrue(firewall.clear())
        self.assertEqual(runs, [
            ['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=KARMA Quarantine', 'dir=in', 'action=block', 'remoteip=203.0.113.9'],
            ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=KARMA Quarantine', 'remoteip=203.0.113.9'],
            ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=KARMA Quarantine']])

    def test_public_ip_geolocation_is_cached_stored_and_offline_safe(self):
        import requests
        from unittest.mock import MagicMock
        db._geo_cache.clear(); db._geo_calls.clear()
        reply = MagicMock()
        reply.json.return_value = {"status": "success", "country": "United States", "countryCode": "US",
                                   "city": "Ashburn", "lat": 39.03, "lon": -77.5}
        with patch.object(config, "GEOIP_ENABLED", True), patch.object(db.requests, "get", return_value=reply) as get:
            event_id = self.event("8.8.8.8")
            self.assertEqual(db.get_geo_info("8.8.8.8")["city"], "Ashburn")
            for address in ("192.168.1.5", "203.0.113.5", "224.0.0.1"):
                db.get_geo_info(address)
            self.assertEqual(get.call_count, 1)  # cached; LAN/documentation/multicast never looked up
        with patch.object(db.requests, "get", side_effect=AssertionError("reads must not call the network")):
            for row in (db.get_event(event_id), db.get_attackers_list()[0]):
                self.assertEqual((row["city"], row["geo_source"], row["flag"]), ("Ashburn", "geoip", "🇺🇸"))
        db._geo_cache.clear()
        with patch.object(config, "GEOIP_ENABLED", True), \
                patch.object(db.requests, "get", side_effect=requests.ConnectionError("offline")):
            self.assertEqual(db.get_geo_info("1.1.1.1")["geo_source"], "unknown")
        db._geo_cache.clear()

    def test_sensor_manager_toggle_and_failed_bind(self):
        from backend.sensors.manager import SensorManager
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
            decoy_state.DECOYS.clear()
            decoy_state.add_custom_decoy("test", port, "Custom Decoy")
            controller = SensorManager(lambda event: None)
            with patch.object(config, "SENSOR_HOST", "127.0.0.1"):
                controller.start()
                self.assertEqual(controller.status()[0]["status"], "ERROR")
        try:
            with patch.object(config, "SENSOR_HOST", "127.0.0.1"):
                controller.reconcile()
            self.assertEqual(controller.status()[0]["status"], "ACTIVE")
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                pass
            decoy_state.toggle_decoy(f"custom_port_{port}", False)
            controller.reconcile()
            self.assertEqual(controller.status()[0]["status"], "DISABLED")
            with socket.socket() as released:
                released.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                released.bind(("127.0.0.1", port))
        finally:
            controller.stop()

    def test_web_trap_toggle_and_custom_honeytoken(self):
        from backend.sensors.web_honeypot import web_decoy_app
        from backend.honeytokens import create_honeytoken
        token = create_honeytoken("custom", "Decoy URL")
        with TestClient(web_decoy_app, client=("192.0.2.40", 1234)) as web:
            decoy_state.toggle_decoy("api_auth_keys", False)
            self.assertEqual(web.get("/api/v1/auth/keys").status_code, 404)
            self.assertEqual(db.get_total_attack_count(), 0)
            self.assertEqual(web.get(token["token_value"]).status_code, 403)
            self.assertEqual(db.get_total_attack_count(), 1)
            saved = next(t for t in db.get_honeytokens() if t["token_id"] == token["token_id"])
            self.assertEqual(saved["hit_count"], 1)
            self.assertTrue(db.is_quarantined("192.0.2.40"))
            self.assertEqual(web.get("/").status_code, 403)
            # A blocked attempt is logged once as BLOCKED, then rate-limited per IP/port.
            self.assertEqual(db.get_total_attack_count(), 2)
            self.assertEqual(db.get_recent_logs(1)[0]["attack_type"], "Blocked Connection (Quarantined)")
            self.assertEqual(web.get("/").status_code, 403)
            self.assertEqual(db.get_total_attack_count(), 2)

    def test_leaked_key_and_credentials_are_detected_when_used(self):
        from backend.sensors.web_honeypot import web_decoy_app
        from backend.sensors.virtual_shell import VirtualShell
        from backend.sensors.ssh_honeypot import ParamikoHoneypotInterface
        leak = VirtualShell("192.0.2.50", "10.0.0.1").files["/srv/company/operations/deploy.env"].decode()
        key = leak.split("API_KEY=")[1].split()[0]
        user, password = leak.split("STAGING_SSH=")[1].split()[0].split(":", 1)
        with TestClient(web_decoy_app, client=("192.0.2.50", 1234)) as web:
            self.assertEqual(web.get("/api/v1/admin/db_export", headers={"X-API-Key": key}).status_code, 403)
        hits = {t["token_id"]: t["hit_count"] for t in db.get_honeytokens()}
        self.assertEqual(hits["ht-aws-01"], 1)
        ssh = ParamikoHoneypotInterface("192.0.2.51")
        ssh.check_auth_password(user, password)
        hits = {t["token_id"]: t["hit_count"] for t in db.get_honeytokens()}
        self.assertEqual(hits["ht-ssh-key"], 1)
        self.assertTrue(db.is_quarantined("192.0.2.51"))

    def test_production_cookie_and_https_requirement(self):
        with patch.object(config, "PRODUCTION", True), patch.object(config, "COOKIE_SECURE", True):
            self.assertEqual(self.client.get("/healthz").status_code, 400)
            tls = TestClient(app, base_url="https://testserver", client=("127.0.0.1", 1234))
            response = tls.post("/login", data={"token": TOKEN}, follow_redirects=False)
            self.assertEqual(response.status_code, 303)
            self.assertIn("Secure", response.headers["set-cookie"])
            tls.close()

    def test_phishing_runs_off_event_loop(self):
        import time
        import httpx
        from backend.engine import phishing_analyzer
        async def check():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver", headers=self.auth) as client:
                task = asyncio.create_task(client.post("/api/tools/phishing-eml", files={"file":("test.eml", b"Subject: hello\n\nbody")}))
                await asyncio.sleep(0.05)
                start = time.monotonic()
                response = await client.get("/api/status")
                self.assertEqual(response.status_code, 200)
                self.assertLess(time.monotonic() - start, 0.3)
                self.assertFalse(task.done())
                await task
        with patch.object(phishing_analyzer, "parse_and_analyze_eml", side_effect=lambda *a: (time.sleep(0.5) or {"verdict":"UNKNOWN"})):
            asyncio.run(check())

    def test_ssh_login_and_shell_are_simulated(self):
        import paramiko
        from backend.sensors import ssh_honeypot
        keypath = Path(self.temp.name) / "host-key"
        with patch.object(ssh_honeypot, "KEY_FILE", str(keypath)), patch.object(ssh_honeypot, "DATA_DIR", Path(self.temp.name)):
            server = ssh_honeypot.SSHHoneypotServer(host="127.0.0.1", port=0)
            server.start()
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect("127.0.0.1", port=server.server_socket.getsockname()[1], username="probe", password="secret", look_for_keys=False, allow_agent=False, timeout=5)
                channel = client.invoke_shell()
                channel.settimeout(5)
                self.assertIn(b"Welcome", channel.recv(4096))
                client.close()
                events = db.get_recent_logs()
                self.assertEqual(len(events), 1)
                self.assertNotIn("secret", events[0]["payload"])
                self.assertEqual(events[0]["mitre_id"], "T1110")
            finally:
                server.stop()

    def test_partial_database_migration(self):
        conn = db.get_db()
        conn.execute("ALTER TABLE attack_logs DROP COLUMN flag")
        conn.commit()
        conn.close()
        db.init_db()
        self.assertIsNotNone(db.get_event(self.event())["flag"])

    def test_engagement_mode_persists_and_respects_manual_blocks(self):
        from backend.engine.active_defense import active_defense_engine
        self.assertEqual(self.client.post('/api/engagement', json={'mode':'observe'}).status_code,401)
        self.assertEqual(self.client.post('/api/engagement', headers=self.auth, json={'mode':'invalid'}).status_code,422)
        self.assertEqual(self.client.post('/api/engagement', headers=self.auth, json={'mode':'observe'}).status_code,200)
        active_defense_engine.load_mode()
        decoy_state.initialize_decoys()
        self.assertFalse(active_defense_engine.process_event('192.168.1.2',100,'test')[0])
        self.assertEqual(self.client.get('/api/status',headers=self.auth).json()['engagement_mode'],'observe')
        active_defense_engine.manual_quarantine('192.168.1.2')
        self.assertTrue(db.is_quarantined('192.168.1.2'))
        self.client.post('/api/engagement',headers=self.auth,json={'mode':'contain'})
        self.assertTrue(active_defense_engine.process_event('192.168.1.3',100,'test')[0])

    def test_virtual_shell_has_no_host_files_or_execution(self):
        from backend.sensors.virtual_shell import VirtualShell
        first = VirtualShell('192.168.1.2','192.168.137.1')
        second = VirtualShell('192.168.1.2','192.168.137.1')
        self.assertIn('AEGIS_Financials.xlsm',first.execute('ls -la')[0])
        self.assertEqual(first.execute('cd /srv/company')[1],0)
        self.assertEqual(first.execute('pwd')[0],'/srv/company\n')
        self.assertEqual(first.execute('touch test.txt')[1],0)
        self.assertNotEqual(second.execute('cat /srv/company/test.txt')[1],0)
        self.assertNotEqual(first.execute('cat ../../../../Windows/win.ini')[1],0)
        self.assertNotEqual(first.execute('python -c "import os"')[1],0)
        self.assertNotEqual(first.execute('echo x > /tmp/test')[1],0)
        self.assertNotEqual(first.execute('ls; whoami')[1],0)
        self.assertNotEqual(first.execute('A'*8193)[1],0)
        for i in range(140): first.execute(f'touch /tmp/f{i}')
        self.assertIn('quota',first.execute('touch /tmp/overflow')[0])

    @unittest.skipUnless(all((Path(__file__).parents[1]/'backend'/'assets'/n).exists() for n in ('company_data_2026.pdf','company_financials_25-26.xlsx')),
                         'link templates not shipped; only the AEGIS macro decoys are in backend/assets')
    def test_document_confirmation_is_explicit_expiring_and_correlated(self):
        import io
        import zipfile
        from pypdf import PdfReader
        from backend import documents
        from backend.sensors.web_honeypot import web_decoy_app
        content = documents.issue_document(documents.TEMPLATES[0],'192.168.1.2','session-a','http://192.168.137.1:8080')
        reader = PdfReader(io.BytesIO(content))
        action = reader.pages[0]['/Annots'][0].get_object()['/A']
        self.assertEqual(action['/S'],'/URI')
        self.assertNotIn('/OpenAction',reader.trailer['/Root'])
        token = str(action['/URI']).rsplit('/',1)[-1]
        self.assertEqual(documents.lookup_document(token)['session_id'],'session-a')
        workbook = documents.personalize(documents.TEMPLATES[1],str(action['/URI']))
        with zipfile.ZipFile(io.BytesIO(workbook)) as z:
            self.assertIn(token.encode(),z.read('xl/worksheets/_rels/sheet1.xml.rels'))
            self.assertFalse(any('vbaProject' in n or 'externalLinks/' in n or 'connections.xml' in n for n in z.namelist()))
            self.assertNotIn(b'HYPERLINK is not implemented',z.read('xl/worksheets/sheet1.xml'))
        for invalid in ('file:///etc/passwd','http://user:password@example.com','http://example.com:99999','http://example.com/path'):
            with patch.object(config,'CALLBACK_BASE_URL',invalid), self.assertRaises(ValueError):
                documents.callback_base('127.0.0.1')
        with TestClient(web_decoy_app,client=('192.168.1.3',1234)) as web:
            self.assertEqual(web.get('/documents/'+token).status_code,200)
            self.assertEqual(db.get_total_attack_count(),0)
            self.assertEqual(web.post('/documents/'+token,data={'acknowledgement':'no'}).status_code,400)
            self.assertEqual(db.get_total_attack_count(),0)
            self.assertEqual(web.post('/documents/'+token,data={'acknowledgement':'confirm'}).status_code,200)
            event = self.client.get('/api/document-events',headers=self.auth).json()[0]
            self.assertEqual(event['attack_type'],'Document interaction confirmed')
            self.assertEqual(event['attacker_ip'],'192.168.1.3')
            self.assertIn('192.168.1.2',event['payload'])
            self.assertIn('session-a',event['payload'])
            self.assertEqual(web.get('/documents/'+'x'*43).status_code,404)
            with patch.object(documents.time,'time',return_value=10**12):
                self.assertEqual(web.get('/documents/'+token).status_code,404)

    def test_sftp_downloads_and_ssh_exec_are_isolated(self):
        import paramiko
        from backend.sensors import ssh_honeypot
        self.client.post('/api/engagement',headers=self.auth,json={'mode':'observe'})
        keypath = Path(self.temp.name) / 'sftp-host-key'
        with patch.object(ssh_honeypot,'KEY_FILE',str(keypath)),patch.object(ssh_honeypot,'DATA_DIR',Path(self.temp.name)):
            server = ssh_honeypot.SSHHoneypotServer(host='127.0.0.1',port=0)
            server.start()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                port = server.server_socket.getsockname()[1]
                client.connect('127.0.0.1',port=port,username='root',password='fake',look_for_keys=False,allow_agent=False,timeout=5)
                with client.open_sftp() as sftp:
                    sftp.get_channel().settimeout(5)
                    self.assertIn('AEGIS_Financials.xlsm',sftp.listdir('/root'))
                    with sftp.open('/root/AEGIS_Financials.xlsm','rb') as f:
                        self.assertTrue(f.read().startswith(b'PK'))
                    self.assertEqual(len([e for e in db.get_recent_logs() if e['decoy_service']=='DOCUMENT_DECOY']),1)
                    with self.assertRaises(OSError): sftp.open('/tmp/upload','wb')
                    with self.assertRaises(OSError): sftp.open('/root/../../Windows/win.ini','rb')
                    db.add_to_quarantine('127.0.0.1','manual test',100)
                    with self.assertRaises(OSError): sftp.open('/root/AEGIS_Financials.xlsm','rb')
                client.close()
                db.remove_from_quarantine('127.0.0.1')
                client.connect('127.0.0.1',port=port,username='root',password='fake',look_for_keys=False,allow_agent=False,timeout=5)
                _,out,_ = client.exec_command('ls /srv/company',timeout=5)
                self.assertIn(b'AEGIS_Financials.xlsm',out.read())
                self.assertEqual(out.channel.recv_exit_status(),0)
                client.close()
                client.connect('127.0.0.1',port=port,username='root',password='fake',look_for_keys=False,allow_agent=False,timeout=5)
                channel = client.invoke_shell()
                channel.settimeout(5)
                def read_prompt():
                    response = b''
                    while not response.endswith(b'# '):
                        chunk = channel.recv(4096)
                        if not chunk:
                            self.fail('SSH session closed before the prompt')
                        response += chunk
                    return response
                self.assertIn(b'Welcome',read_prompt())
                channel.sendall(b'cd /srv/company\r\n')
                self.assertIn(b'/srv/company# ',read_prompt())
                channel.sendall(b'pwd\r')
                self.assertIn(b'\r\n/srv/company\r\n',read_prompt())
                channel.sendall(b'\x1b[A\r')
                self.assertIn(b'\r\n/srv/company\r\n',read_prompt())
                channel.sendall(b'\x04')
                self.assertEqual(channel.recv_exit_status(),0)
            finally:
                client.close()
                server.stop()

    def test_ai_fallback_never_contacts_provider_without_key(self):
        from backend.engine import ai_chat, phishing_analyzer
        with patch.object(config, "DEEPSEEK_API_KEY", ""), patch.object(ai_chat.requests, "post") as request:
            result = ai_chat.generate_cybersecurity_chat_response([{"role":"user", "content":"hello"}], False)
            self.assertIn("reply", result)
            request.assert_not_called()
        with patch.object(config, "DEEPSEEK_API_KEY", ""), patch.object(phishing_analyzer.requests, "post") as request:
            result = phishing_analyzer.parse_and_analyze_eml(b"From: user@example.com\nSubject: hello\n\nhello")
            self.assertEqual(result["verdict"], "UNKNOWN")
            request.assert_not_called()

    def test_remote_development_management_is_denied(self):
        remote = TestClient(app, client=("192.0.2.50", 1234))
        try:
            self.assertEqual(remote.get("/api/logs", headers=self.auth).status_code, 403)
        finally:
            remote.close()

    def test_websocket_receives_persisted_event(self):
        from backend.app import manager
        with self.client.websocket_connect("/ws/telemetry", headers=self.auth) as ws:
            event_id = self.event()
            manager.sync_broadcast({"id":event_id, "quarantined":False})
            event = ws.receive_json()
            self.assertEqual(event["id"], event_id)
            self.assertIn("timestamp", event)

    def test_second_instance_is_rejected(self):
        from backend.runtime import InstanceLock
        with self.assertRaises(RuntimeError):
            with InstanceLock():
                pass

    def test_production_rejects_missing_admin_secret(self):
        from backend.security import load_admin_token
        with patch.object(config, "PRODUCTION", True), patch.object(config, "ADMIN_TOKEN", ""):
            with self.assertRaises(RuntimeError):
                load_admin_token()


if __name__ == "__main__":
    unittest.main()
