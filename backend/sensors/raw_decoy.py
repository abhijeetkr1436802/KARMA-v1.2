"""
K.A.R.M.A Network Decoy Sensors (Ports 21 FTP, 23 Telnet, 3389 RDP)
Captures network port scans, banner enumeration, and unencrypted Telnet/FTP probes.
"""

from backend.database import mark_event_quarantine

import socket
import threading
import time
from backend.config import DECOY_PORTS
from backend import config
from backend.engine.mitre_mapper import map_payload_to_mitre
from backend.engine.threat_score import calculate_event_risk
from backend.database import log_attack_event
from backend.engine.active_defense import active_defense_engine

# Global reference for stopping sockets

from backend.sensors.tcp_server import BoundedTCPServer
from backend.database import is_quarantined, get_attempt_count


class RawDecoyServer:
    def __init__(self, ports=DECOY_PORTS, broadcast_callback=None):
        self.ports = ports
        self.broadcast_callback = broadcast_callback
        self.listeners = []
        self.running = False

    def start(self):
        self.running = True
        try:
            for port in self.ports:
                listener = BoundedTCPServer(port, lambda sock, ip, p=port: self._handle_client_connection(sock, ip, p), host=config.SENSOR_HOST)
                listener.start()
                self.listeners.append(listener)
        except Exception:
            self.stop()
            raise

    def _handle_client_connection(self, client_sock, client_ip, port):
        try:
            client_sock.settimeout(5.0)

            # INTERACTIVE FTP DECOY (PORT 21)
            if port == 21:
                client_sock.sendall(b"220 ProFTPD 1.3.5 Server Ready.\r\n")
                while self.running and not is_quarantined(client_ip):
                    data = client_sock.recv(1024)
                    if not data:
                        break
                    cmd_str = data.decode('utf-8', errors='ignore').strip()
                    if not cmd_str:
                        continue

                    payload_info = f"FTP Command Executed: '{cmd_str}'"
                    self._log_and_broadcast(client_ip, port, "FTP_HONEYPOT", "FTP Command Probe", payload_info, "T1059")

                    cmd_upper = cmd_str.upper()
                    if cmd_upper.startswith("USER"):
                        client_sock.sendall(b"331 Please specify the password.\r\n")
                    elif cmd_upper.startswith("PASS"):
                        client_sock.sendall(b"230 User logged in, proceed.\r\n")
                    elif cmd_upper.startswith("PWD"):
                        client_sock.sendall(b"257 \"/\" is current directory.\r\n")
                    elif cmd_upper.startswith("LIST"):
                        client_sock.sendall(b"150 Opening ASCII mode data connection for file list.\r\n226 Transfer complete.\r\n")
                    elif cmd_upper in ["QUIT", "BYE"]:
                        client_sock.sendall(b"221 Goodbye.\r\n")
                        break
                    else:
                        client_sock.sendall(b"502 Command not implemented.\r\n")

            # INTERACTIVE TELNET DECOY (PORT 23)
            elif port == 23:
                self._handle_telnet(client_sock, client_ip, port)

            # RDP DECOY (PORT 3389)
            elif port == 3389:
                self._handle_rdp(client_sock, client_ip, port)

            # OTHER / CUSTOM TCP DECOY PORTS
            else:
                payload_info = f"Port Scan Probe on Decoy Port {port}"
                self._log_and_broadcast(client_ip, port, f"DECOY_PORT_{port}", "Network Service Discovery / Scan", payload_info, "T1046")

            client_sock.close()
        except Exception:
            try:
                client_sock.close()
            except Exception:
                pass

    @staticmethod
    def _strip_telnet(data):
        # Drop Telnet IAC negotiation (0xFF ...) so it is not logged as "input".
        out = bytearray()
        i = 0
        while i < len(data):
            if data[i] == 255:  # IAC
                if i + 1 < len(data) and data[i + 1] == 250:  # SB ... SE
                    end = data.find(240, i)  # SE
                    i = end + 1 if end != -1 else len(data)
                else:
                    i += 3  # IAC + command + option
                continue
            out.append(data[i])
            i += 1
        return out

    def _handle_telnet(self, client_sock, client_ip, port):
        self._log_and_broadcast(client_ip, port, "TELNET_HONEYPOT",
                                "Telnet connection / service discovery",
                                "TCP connection to Telnet service", "T1046")
        # Suppress Go-Ahead only; let the client keep local echo so the typed
        # username is visible (we never claim ECHO, which would blank their input).
        client_sock.sendall(b"\xff\xfb\x03")  # IAC WILL SGA
        client_sock.sendall(b"\r\nUbuntu 22.04 LTS aegis-gateway\r\naegis-gateway login: ")
        buf = bytearray()
        username = None
        attempts = 0
        deadline = time.monotonic() + 300
        while self.running and not is_quarantined(client_ip) and attempts < 30 and time.monotonic() < deadline:
            try:
                data = client_sock.recv(1024)
            except socket.timeout:
                continue
            if not data:
                break
            buf += self._strip_telnet(data)
            # Process each completed line (terminated by CR or LF).
            while True:
                nl = -1
                for mark in (b"\n", b"\r"):
                    pos = buf.find(mark)
                    if pos != -1 and (nl == -1 or pos < nl):
                        nl = pos
                if nl == -1:
                    break
                line = bytes(buf[:nl]).decode("utf-8", "ignore").strip("\x00 \t")
                del buf[:nl + 1]
                if not line:
                    continue
                if username is None:
                    username = line[:64]
                    client_sock.sendall(b"Password: ")
                else:
                    attempts += 1
                    payload = f"Telnet login attempt: USER '{username}' / PASS '[redacted]'"
                    self._log_and_broadcast(client_ip, port, "TELNET_HONEYPOT",
                                            "Telnet Credential Brute-Force", payload, "T1110")
                    username = None
                    client_sock.sendall(b"\r\nLogin incorrect\r\naegis-gateway login: ")

    def _handle_rdp(self, client_sock, client_ip, port):
        # Real RDP clients send an X.224 Connection Request first; it often carries
        # the Windows username as  Cookie: mstshash=<user>. Capture that, then reply.
        cookie_user = None
        try:
            data = client_sock.recv(2048)
        except socket.timeout:
            data = b""
        if data:
            text = data.decode("latin-1", "ignore")
            marker = "mstshash="
            if marker in text:
                cookie_user = text.split(marker, 1)[1].split("\r")[0].split("\n")[0][:64]
        detail = f"RDP connection attempt (cookie user '{cookie_user}')" if cookie_user else "RDP connection attempt / scan"
        self._log_and_broadcast(client_ip, port, "RDP_HONEYPOT", "Remote Desktop Access Attempt", detail, "T1021")
        try:
            # X.224 Connection Confirm, then refuse (no real RDP stack behind it).
            client_sock.sendall(b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00")
        except OSError:
            pass

    def _log_and_broadcast(self, client_ip, port, service_name, attack_type, payload_info, default_mitre):
        mitre = map_payload_to_mitre("RAW_DECOY", "command_execution" if default_mitre == "T1059" else "port_scan", payload_info)
        score, severity = calculate_event_risk(mitre['risk_score'], get_attempt_count(client_ip) + 1)

        log_id = log_attack_event(
            attacker_ip=client_ip,
            port=port,
            decoy_service=service_name,
            attack_type=attack_type,
            payload=payload_info,
            mitre_id=mitre['mitre_id'] or default_mitre,
            mitre_name=mitre['mitre_name'],
            mitre_tactic=mitre['mitre_tactic'],
            risk_score=score,
            severity=severity
        )

        from backend.database import get_geo_info
        geo = get_geo_info(client_ip)

        quarantined, _ = active_defense_engine.process_event(client_ip, score, mitre['mitre_name'])
        mark_event_quarantine(log_id, quarantined)

        if self.broadcast_callback:
            self.broadcast_callback({
                "id": log_id,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "attacker_ip": client_ip,
                "port": port,
                "decoy_service": service_name,
                "attack_type": attack_type,
                "payload": payload_info,
                "mitre_id": mitre['mitre_id'] or default_mitre,
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

    def stop(self):
        self.running = False
        for listener in self.listeners:
            listener.stop()
        self.listeners.clear()
