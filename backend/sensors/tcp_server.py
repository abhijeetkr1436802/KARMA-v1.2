"""Bounded TCP listener with deterministic bind failures and shutdown."""
import logging
import socket
import threading
import time
from backend.config import MAX_CLIENTS, SENSOR_HOST
from backend.database import is_quarantined

log = logging.getLogger(__name__)
broadcast_cb = None  # set by SensorManager so blocked attempts reach the dashboard
_last_blocked = {}


def report_blocked(ip, port, service):
    """Log a refused attempt from a quarantined IP, at most once per IP/port every 10 s."""
    # ponytail: unbounded dict keyed by (ip, port); fine for a lab, prune if exposed to the internet
    now = time.monotonic()
    if now - _last_blocked.get((ip, port), -10) < 10:
        return
    _last_blocked[(ip, port)] = now
    from backend.database import log_attack_event, mark_event_quarantine
    try:
        log_id = log_attack_event(ip, port, service, "Blocked Connection (Quarantined)",
                                  f"Connection to {service}:{port} refused, attacker is quarantined",
                                  "", "Blocked by Active Defense", "Containment", 0, "LOW")
        mark_event_quarantine(log_id, True)
    except Exception:
        log.exception("Could not log blocked connection from %s", ip)
        return
    if broadcast_cb:
        broadcast_cb({"id": log_id, "quarantined": True})

def bind_listener(host, port):
    """Bound, listening socket. Windows: exclusive bind, so no other process can hijack the port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            try:
                sock.bind((host, port))
            except OSError:
                # Connections from the previous run still in TIME_WAIT (~2 min) block an exclusive
                # re-bind after a quick restart. A plain bind still refuses ports held by a live listener.
                sock.close()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind((host, port))
                log.warning("Port %s re-bound without exclusive mode (recent restart)", port)
        else:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
        sock.listen(32)
        return sock
    except BaseException:
        sock.close()
        raise


class BoundedTCPServer:
    service = "TCP_DECOY"

    def __init__(self, port, handler, host=SENSOR_HOST):
        self.host, self.port, self.handler = host, port, handler
        self.running = False
        self.server_socket = None
        self.thread = None
        self.clients = set()
        self.workers = set()
        self.lock = threading.RLock()
        self.slots = threading.BoundedSemaphore(MAX_CLIENTS)

    def start(self):
        if self.running:
            return
        sock = bind_listener(self.host, self.port)
        sock.settimeout(0.5)
        self.server_socket = sock
        self.running = True
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def _accept(self):
        while self.running:
            try:
                client, addr = self.server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self.slots.acquire(blocking=False):
                client.close()
                continue
            client.settimeout(15)
            with self.lock:
                self.clients.add(client)
                worker = threading.Thread(target=self._client, args=(client, addr[0]), daemon=True)
                self.workers.add(worker)
                worker.start()

    def _client(self, client, ip):
        try:
            if not is_quarantined(ip):
                self.handler(client, ip)
            else:
                log.warning('Sensor connection denied: %s is quarantined (port %s). Unblock the test IP in Attacker Profiles; use Observe mode for interactive labs.', ip, self.port)
                report_blocked(ip, self.port, self.service)
        except (OSError, EOFError):
            pass
        except Exception:
            log.exception("Sensor client failed on port %s", self.port)
        finally:
            client.close()
            with self.lock:
                self.clients.discard(client)
                self.workers.discard(threading.current_thread())
            self.slots.release()

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        with self.lock:
            clients = list(self.clients)
            workers = list(self.workers)
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            client.close()
        if self.thread:
            self.thread.join(timeout=2)
        for worker in workers:
            worker.join(timeout=0.1)
