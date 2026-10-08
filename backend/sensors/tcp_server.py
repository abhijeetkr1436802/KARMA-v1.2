"""Bounded TCP listener with deterministic bind failures and shutdown."""
import logging
import socket
import threading
from backend.config import MAX_CLIENTS, SENSOR_HOST
from backend.database import is_quarantined

log = logging.getLogger(__name__)


class BoundedTCPServer:
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
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.host, self.port))
            sock.listen(32)
            sock.settimeout(0.5)
        except BaseException:
            sock.close()
            raise
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
