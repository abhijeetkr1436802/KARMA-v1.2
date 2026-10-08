"""
K.A.R.M.A OpenSSH Honeypot Decoy Sensor (Port 2222)
Handles OpenSSH key exchange via Paramiko, traps authentication brute-force attempts,
and records post-exploitation bash command execution telemetry.
"""

from backend.database import mark_event_quarantine

import os
import socket
import threading
import time
import logging
import codecs
import paramiko
from backend.config import PORT_SSH_HONEYPOT, DATA_DIR, SENSOR_HOST
from backend.sensors.tcp_server import BoundedTCPServer
from backend.database import is_quarantined, get_attempt_count
from backend.engine.mitre_mapper import map_payload_to_mitre
from backend.engine.threat_score import calculate_event_risk
from backend.database import log_attack_event, get_geo_info
from backend.engine.active_defense import active_defense_engine
from backend.sensors.virtual_shell import VirtualShell, VirtualSFTP
from backend.sensors.terminal import TerminalInput

# Silence Paramiko background transport exception logging to keep console output clean
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

# Global instance reference for stopping

# Persistent RSA Host Key for Paramiko SSH protocol handshake
KEY_FILE = str(DATA_DIR / "ssh_host_rsa_key")

def get_persistent_host_key():
    if os.path.exists(KEY_FILE):
        return paramiko.RSAKey(filename=KEY_FILE)
    DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = paramiko.RSAKey.generate(3072)
    with open(KEY_FILE, "x", encoding="utf-8", opener=lambda p, flags: os.open(p, flags, 0o600)) as file:
        key.write_private_key(file)
    return key


FAKE_SHELL_RESPONSES = {
    "whoami": "root\r\n",
    "id": "uid=0(root) gid=0(root) groups=0(root)\r\n",
    "uname -a": "Linux aegis-soc-gateway 5.15.0-76-generic #83-Ubuntu SMP x86_64 GNU/Linux\r\n",
    "ls": "bin  boot  etc  home  lib  opt  root  sys  tmp  var\r\n",
    "ls -l": "total 32\r\ndrwxr-xr-x 2 root root 4096 Aug 23 12:00 bin\r\ndrwxr-xr-x 12 root root 4096 Aug 23 12:00 etc\r\n-rw------- 1 root root 1024 Aug 23 12:00 id_rsa\r\n-rw-r--r-- 1 root root  512 Aug 23 12:00 config.json\r\n",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nadmin:x:1000:1000:AegisAdmin:/home/admin:/bin/bash\r\n",
    "cat /etc/shadow": "root:$6$vUaZ4mN...:19200:0:99999:7:::\r\nadmin:$6$xKw9L1...:19200:0:99999:7:::\r\n",
    "cat /etc/issue": "Ubuntu 22.04.3 LTS \\n \\l\r\n",
    "pwd": "/root\r\n",
    "hostname": "aegis-soc-gateway\r\n",
}

class ParamikoHoneypotInterface(paramiko.ServerInterface):
    def __init__(self, client_ip, broadcast_cb=None, port=2222, shell=None):
        self.client_ip = client_ip
        self.broadcast_cb = broadcast_cb
        self.port = port
        self.event_event = threading.Event()
        self.shell = shell
        self.channel_open = False
        self.mode = None
        self.command = None

    def check_channel_request(self, kind, chanid):
        if kind == 'session' and not self.channel_open:
            self.channel_open = True
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        payload_info = f"SSH Login Attempt: USER '{username}' / PASS '[redacted]'"
        mitre = map_payload_to_mitre("SSH_HONEYPOT", "ssh_command_execution", payload_info)
        score, severity = calculate_event_risk(mitre['risk_score'], get_attempt_count(self.client_ip) + 1)

        log_id = log_attack_event(
            attacker_ip=self.client_ip,
            port=self.port,
            decoy_service="SSH_HONEYPOT",
            attack_type="SSH Credential Brute-Force",
            payload=payload_info,
            mitre_id="T1110",
            mitre_name="Brute Force Authentication",
            mitre_tactic="Credential Access",
            risk_score=score,
            severity=severity
        )

        geo = get_geo_info(self.client_ip)
        quarantined, _ = active_defense_engine.process_event(self.client_ip, score, "SSH Brute Force")
        mark_event_quarantine(log_id, quarantined)

        if self.broadcast_cb:
            self.broadcast_cb({
                "id": log_id,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "attacker_ip": self.client_ip,
                "port": self.port,
                "decoy_service": "SSH_HONEYPOT",
                "attack_type": "SSH Credential Brute-Force",
                "payload": payload_info,
                "mitre_id": "T1110",
                "mitre_name": "Brute Force Authentication",
                "mitre_tactic": "Credential Access",
                "risk_score": score,
                "severity": severity,
                "quarantined": quarantined,
                "country": geo['country'],
                "city": geo['city'],
                "lat": geo['lat'],
                "lng": geo['lng'],
                "flag": geo['flag']
            })

        return paramiko.AUTH_FAILED if quarantined else paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        return self.check_auth_password(username, "[public-key]")

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        if self.mode is not None:
            return False
        self.mode = 'shell'
        self.event_event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        if self.mode is not None or len(command) > 8192:
            return False
        self.mode = 'exec'
        self.command = command.decode('utf-8', errors='replace')
        self.event_event.set()
        return True

    def check_channel_subsystem_request(self, channel, name):
        if name != 'sftp' or self.mode is not None:
            return False
        self.mode = 'sftp'
        accepted = super().check_channel_subsystem_request(channel, name)
        self.event_event.set()
        return accepted

class SSHHoneypotServer(BoundedTCPServer):
    def __init__(self, host=SENSOR_HOST, port=PORT_SSH_HONEYPOT, broadcast_callback=None):
        super().__init__(port, self._handle_client, host)
        self.broadcast_callback = broadcast_callback
        self.host_key = None

    def start(self):
        from backend.documents import callback_base, ASSETS, FILES
        callback_base('127.0.0.1')
        for name in FILES:
            if not (ASSETS / name).is_file():
                raise RuntimeError(f'Missing decoy document template: {name}')
        self.host_key = get_persistent_host_key()
        super().start()

    def _handle_client(self, client_sock, client_ip):
        transport = None
        try:
            # First peek to see if client sends SSH handshake or raw data
            transport = paramiko.Transport(client_sock)
            transport.local_version = 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1'
            transport.add_server_key(self.host_key)
            transport.banner_timeout = 10
            transport.auth_timeout = 120
            shell = VirtualShell(client_ip, client_sock.getsockname()[0], self.broadcast_callback)
            server = ParamikoHoneypotInterface(client_ip, self.broadcast_callback, self.port, shell)
            transport.set_subsystem_handler('sftp', paramiko.SFTPServer, VirtualSFTP)

            try:
                transport.start_server(server=server)
            except Exception:
                # Log Port Scan Event & Fallback to raw socket handling
                self._log_scan_probe(client_ip)
                self._handle_raw_client(client_sock, client_ip)
                return

            channel = transport.accept(120)
            if channel is None:
                self._log_scan_probe(client_ip)
                transport.close()
                return

            if not server.event_event.wait(10):
                return
            deadline = time.monotonic() + 900
            if server.mode == 'sftp':
                while self.running and transport.is_active() and not channel.closed and not is_quarantined(client_ip):
                    if time.monotonic() >= deadline or time.monotonic() - shell.last_activity > 120:
                        break
                    time.sleep(0.25)
                return
            if server.mode == 'exec':
                self._process_command(server.command, client_ip)
                if not is_quarantined(client_ip):
                    response, status = shell.execute(server.command)
                    channel.sendall(response.encode('utf-8'))
                    channel.send_exit_status(status)
                return

            # Send welcome prompt
            channel.send(b"\r\nWelcome to Aegis Linux Security Gateway 22.04 LTS\r\n\r\n")
            channel.sendall(shell.prompt.encode())

            channel.settimeout(120)
            terminal = TerminalInput()
            decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
            while self.running and not channel.closed and not is_quarantined(client_ip) and time.monotonic() < deadline:
                channel.settimeout(min(120, max(0.1, deadline-time.monotonic())))
                data = channel.recv(1024)
                if not data:
                    break

                text = decoder.decode(data)
                for char in text:
                    echo, cmd, eof = terminal.feed(char, shell.prompt)
                    if echo:
                        channel.sendall(echo.encode('utf-8'))
                    if eof:
                        channel.send_exit_status(0)
                        return
                    if cmd is None:
                        continue
                    cmd = cmd.strip()
                    if cmd in ('exit', 'quit'):
                        channel.sendall(b'logout\r\n')
                        channel.send_exit_status(0)
                        return
                    if cmd:
                        self._process_command(cmd, client_ip)
                        if is_quarantined(client_ip):
                            channel.sendall(b'\r\nSession ended by KARMA containment policy.\r\n')
                            return
                        response, _ = shell.execute(cmd)
                        channel.sendall(response.replace('\n', '\r\n').encode('utf-8'))
                    channel.sendall(shell.prompt.encode())

            transport.close()
        except (socket.timeout, EOFError, OSError):
            pass
        except Exception:
            logging.getLogger(__name__).exception('SSH session failed for %s on port %s', client_ip, self.port)
            try:
                client_sock.close()
            except Exception:
                pass
        finally:
            if transport is not None:
                transport.close()

    def _handle_raw_client(self, client_sock, client_ip):
        try:
            client_sock.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
            client_sock.sendall(b"root@aegis-gateway:~# ")
            client_sock.settimeout(6.0)

            while self.running and not is_quarantined(client_ip):
                data = client_sock.recv(1024)
                if not data:
                    break
                raw_cmd = data.decode('utf-8', errors='ignore').strip()
                if not raw_cmd:
                    continue
                if raw_cmd.lower() in ["exit", "quit"]:
                    client_sock.sendall(b"logout\r\n")
                    break

                self._process_command(raw_cmd, client_ip)

                cmd_lower = raw_cmd.lower()
                resp = FAKE_SHELL_RESPONSES.get(cmd_lower)
                if not resp:
                    resp = f"bash: {raw_cmd.split()[0]}: command not found\r\n"

                client_sock.sendall(resp.encode('utf-8') + b"root@aegis-gateway:~# ")
            client_sock.close()
        except Exception:
            try:
                client_sock.close()
            except Exception:
                pass

    def _process_command(self, raw_cmd, client_ip):
        payload_info = f"SSH Executed Command: '{raw_cmd}'"
        mitre_key = "ssh_command_execution"
        if "cat /etc" in raw_cmd or "shadow" in raw_cmd or "passwd" in raw_cmd:
            mitre_key = "credential_access"
        elif "whoami" in raw_cmd or "id" in raw_cmd or "uname" in raw_cmd:
            mitre_key = "system_discovery"

        mitre = map_payload_to_mitre("SSH_HONEYPOT", mitre_key, payload_info)
        score, severity = calculate_event_risk(mitre['risk_score'], get_attempt_count(client_ip) + 1)

        log_id = log_attack_event(
            attacker_ip=client_ip,
            port=self.port,
            decoy_service="SSH_HONEYPOT",
            attack_type="SSH Command Execution / Probe",
            payload=payload_info,
            mitre_id=mitre['mitre_id'],
            mitre_name=mitre['mitre_name'],
            mitre_tactic=mitre['mitre_tactic'],
            risk_score=score,
            severity=severity
        )

        geo = get_geo_info(client_ip)
        quarantined, _ = active_defense_engine.process_event(client_ip, score, mitre['mitre_name'])
        mark_event_quarantine(log_id, quarantined)

        if self.broadcast_callback:
            self.broadcast_callback({
                "id": log_id,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "attacker_ip": client_ip,
                "port": self.port,
                "decoy_service": "SSH_HONEYPOT",
                "attack_type": "SSH Command Execution / Probe",
                "payload": payload_info,
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

    def _log_scan_probe(self, client_ip):
        payload_info = f"SSH Port Reconnaissance / TCP Banner Probe on Port {self.port}"
        mitre = map_payload_to_mitre("SSH_HONEYPOT", "port_scan", payload_info)
        score, severity = calculate_event_risk(mitre['risk_score'], get_attempt_count(client_ip) + 1)

        log_id = log_attack_event(
            attacker_ip=client_ip,
            port=self.port,
            decoy_service="SSH_HONEYPOT",
            attack_type="SSH Network Reconnaissance / Probe",
            payload=payload_info,
            mitre_id=mitre['mitre_id'],
            mitre_name=mitre['mitre_name'],
            mitre_tactic=mitre['mitre_tactic'],
            risk_score=score,
            severity=severity
        )

        geo = get_geo_info(client_ip)
        quarantined, _ = active_defense_engine.process_event(client_ip, score, mitre['mitre_name'])
        mark_event_quarantine(log_id, quarantined)

        if self.broadcast_callback:
            self.broadcast_callback({
                "id": log_id,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "attacker_ip": client_ip,
                "port": self.port,
                "decoy_service": "SSH_HONEYPOT",
                "attack_type": "SSH Network Reconnaissance / Probe",
                "payload": payload_info,
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
