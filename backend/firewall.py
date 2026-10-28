"""Optional OS firewall enforcement of quarantine (off by default: KARMA_FIREWALL_BLOCK=1 to enable).

Windows: one inbound Block rule per IP named "KARMA Quarantine" (netsh). Linux: an iptables DROP rule
commented "karma". Needs Administrator/root; failures are logged and KARMA's own sensor blocking still
applies. Loopback, unspecified and invalid addresses are never sent to the firewall, so a tunnel
attacker (127.0.0.1) can never cut off the KARMA PC from itself.
"""
import ipaddress
import logging
import subprocess
import sys
import threading

from backend import config

log = logging.getLogger(__name__)
RULE = "KARMA Quarantine"
_blocked = set()   # ponytail: in-memory only; after a restart a re-quarantined IP may get one duplicate rule
_lock = threading.Lock()


def _commands(action, ip):
    if sys.platform == "win32":
        base = ["netsh", "advfirewall", "firewall"]
        if action == "block":
            return [base + ["add", "rule", f"name={RULE}", "dir=in", "action=block", f"remoteip={ip}"]]
        if action == "unblock":
            return [base + ["delete", "rule", f"name={RULE}", f"remoteip={ip}"]]
        return [base + ["delete", "rule", f"name={RULE}"]]
    if sys.platform.startswith("linux"):
        tool = "ip6tables" if ip and ":" in ip else "iptables"
        rule = ["INPUT", "-s", ip or "", "-j", "DROP", "-m", "comment", "--comment", "karma"]
        if action == "block":
            return [[tool, "-I", *rule]]
        if action == "unblock":
            return [[tool, "-D", *rule]]
        return []  # ponytail: Linux clear removes nothing; unblock IPs one by one or flush the karma rules by hand
    return []


def _safe(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified:
        return None
    return str(address)


def _run(action, ip=None):
    for cmd in _commands(action, ip):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode:
                log.warning("Firewall %s %s failed (run KARMA as Administrator?): %s", action, ip or "",
                            (result.stdout + result.stderr).strip()[:200])
        except (OSError, subprocess.SubprocessError) as exc:
            log.warning("Firewall %s %s failed: %s", action, ip or "", exc)


def _submit(action, ip=None):
    if not config.FIREWALL_BLOCK:
        return False
    if action != "clear":
        ip = _safe(ip)
        if not ip:
            return False
    with _lock:
        if action == "block":
            if ip in _blocked:
                return False
            _blocked.add(ip)
        elif action == "unblock":
            _blocked.discard(ip)
        else:
            _blocked.clear()
    threading.Thread(target=_run, args=(action, ip), daemon=True).start()  # never slow down a sensor
    return True


def block(ip):
    return _submit("block", ip)


def unblock(ip):
    return _submit("unblock", ip)


def clear():
    return _submit("clear")
