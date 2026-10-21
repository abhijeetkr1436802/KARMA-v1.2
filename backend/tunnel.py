"""Public TCP tunnels through a bore server (https://github.com/ekzhang/bore), so an attacker on another
network (e.g. a different phone hotspot) can reach the decoys with nothing installed on either PC.

Pure-Python bore client: JSON frames ending in a NUL byte on control port 7835.
  -> {"Hello": 0}            <- {"Hello": <public port>}
  <- "Heartbeat" | {"Connection": "<uuid>"} | {"Error": "..."}
  per connection: new socket, -> {"Accept": "<uuid>"}, then raw bytes both ways.
Every tunnelled connection reaches the decoy from 127.0.0.1, so remote attackers appear as 127.0.0.1.
"""
import json
import logging
import os
import socket
import threading

from backend import config

log = logging.getLogger(__name__)
SERVER = os.environ.get("KARMA_BORE_SERVER", "bore.pub")
CONTROL_PORT = int(os.environ.get("KARMA_BORE_PORT", "7835"))
MAX_FRAME = 256
TIMEOUT = 5


def send(sock, message):
    sock.sendall(json.dumps(message).encode() + b"\0")


def recv(sock):
    buf = bytearray()
    while True:
        byte = sock.recv(1)
        if not byte:
            raise ConnectionError("server closed the tunnel")
        if byte == b"\0":
            return json.loads(buf)
        buf += byte
        if len(buf) > MAX_FRAME:
            raise ConnectionError("oversized frame from server")


def pipe(src, dst):
    try:
        while data := src.recv(65536):
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()


class Tunnels:
    def __init__(self, server=None, control_port=None):
        self.server = server or SERVER
        self.control_port = control_port or CONTROL_PORT
        self.lock = threading.Lock()
        self.controls = {}
        self.ports = {}
        self.error = None

    def status(self):
        with self.lock:
            return {"enabled": bool(self.controls), "server": self.server,
                    "ports": dict(self.ports), "error": self.error}

    def _open(self, local_port):
        control = socket.create_connection((self.server, self.control_port), timeout=TIMEOUT)
        try:
            send(control, {"Hello": 0})
            reply = recv(control)
            if not (isinstance(reply, dict) and "Hello" in reply):
                raise ConnectionError(reply.get("Error", reply) if isinstance(reply, dict) else
                                      "server requires a secret" if reply == "Challenge" else reply)
        except BaseException:
            control.close()
            raise
        control.settimeout(None)
        threading.Thread(target=self._serve, args=(control, local_port), daemon=True).start()
        return control, f"{self.server}:{reply['Hello']}"

    def _serve(self, control, local_port):
        try:
            while True:
                msg = recv(control)
                if isinstance(msg, dict) and "Connection" in msg:
                    threading.Thread(target=self._accept, args=(msg["Connection"], local_port), daemon=True).start()
                elif isinstance(msg, dict) and "Error" in msg:
                    raise ConnectionError(msg["Error"])
        except (OSError, ValueError) as exc:
            with self.lock:
                if self.controls.get(local_port) is control:  # dropped, not stopped by us
                    del self.controls[local_port]
                    self.ports[local_port] = None
                    self.error = f"Port {local_port}: tunnel lost ({exc}). Press Stop, then Start again."

    def _accept(self, conn_id, local_port):
        try:
            remote = socket.create_connection((self.server, self.control_port), timeout=TIMEOUT)
            send(remote, {"Accept": conn_id})
            local = socket.create_connection(("127.0.0.1", local_port), timeout=TIMEOUT)
        except OSError as exc:
            log.warning("Tunnel connection for port %s failed: %s", local_port, exc)
            return
        remote.settimeout(None)
        local.settimeout(None)
        threading.Thread(target=pipe, args=(remote, local), daemon=True).start()
        pipe(local, remote)

    def start(self, ports):
        self.stop()
        with self.lock:
            # Never expose the dashboard.
            for port in sorted({int(p) for p in ports} - {config.PORT_API, 8000, 443}):
                try:
                    self.controls[port], self.ports[port] = self._open(port)
                except (OSError, ValueError) as exc:
                    self.ports[port] = None
                    self.error = f"Port {port}: could not reach {self.server} ({exc}). Check this PC's internet."
            log.info("Tunnels: %s", self.ports)

    def stop(self):
        # ponytail: already-open attacker sessions run until they close; track sockets if that matters.
        with self.lock:
            controls = list(self.controls.values())
            self.controls.clear()
            self.ports.clear()
            self.error = None
        for control in controls:
            try:
                control.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            control.close()


tunnels = Tunnels()
