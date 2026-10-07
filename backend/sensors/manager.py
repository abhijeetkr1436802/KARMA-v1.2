"""Owns all listeners; configuration and observed health are separate."""
import threading
from backend import config
from backend.decoy_state import get_all_decoys


class SensorManager:
    def __init__(self, broadcast):
        self.broadcast = broadcast
        self.servers = {}
        self.errors = {}
        self.lock = threading.RLock()
        self.active = False

    def start(self):
        self.active = True
        self.reconcile()

    def reconcile(self):
        if not self.active:
            return
        from backend.sensors.ssh_honeypot import SSHHoneypotServer
        from backend.sensors.raw_decoy import RawDecoyServer
        from backend.sensors.web_honeypot import WebHoneypotServer, set_web_broadcast_callback
        set_web_broadcast_callback(self.broadcast)
        with self.lock:
            for decoy in get_all_decoys():
                id = decoy["id"]
                if id in {"api_auth_keys", "api_db_export"}:
                    continue
                if not decoy["enabled"] and id in self.servers:
                    self.servers.pop(id).stop()
                if not decoy["enabled"]:
                    self.errors.pop(id, None)
                if decoy["enabled"] and id not in self.servers:
                    try:
                        if id == "ssh_2222":
                            server = SSHHoneypotServer(broadcast_callback=self.broadcast)
                        elif id == "web_8080":
                            server = WebHoneypotServer()
                        else:
                            server = RawDecoyServer([decoy["port"]], self.broadcast)
                        server.start()
                        self.servers[id] = server
                        self.errors.pop(id, None)
                    except Exception as exc:
                        self.errors[id] = str(exc)

    def status(self):
        with self.lock:
            result = []
            for d in get_all_decoys():
                parent = "web_8080" if d["id"] in {"api_auth_keys", "api_db_export"} else d["id"]
                server = self.servers.get(parent)
                live = bool(server and getattr(server, "running", False))
                d["status"] = "DISABLED" if not d["enabled"] else ("ACTIVE" if live else "ERROR" if parent in self.errors else "STOPPED")
                d["error"] = self.errors.get(parent)
                result.append(d)
            return result

    def stop(self):
        self.active = False
        with self.lock:
            for server in self.servers.values():
                server.stop()
            self.servers.clear()
