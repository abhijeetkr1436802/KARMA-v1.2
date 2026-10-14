"""Phone/e-mail alert when an attack *starts*.

One alert per attack episode: the first event after QUIET_SECONDS without any event
starts a new episode and sends one notification; everything inside the episode is silent.
Channels (both free): ntfy.sh push to the ntfy phone app, and e-mail over SMTP (e.g. Gmail
with an app password). Settings live in the private data dir, never in the repository.
"""
import json
import logging
import os
import re
import smtplib
import threading
import time
from email.message import EmailMessage

import requests

from backend import config

log = logging.getLogger(__name__)
QUIET_SECONDS = 3600
FIELDS = ("ntfy_topic", "email_to", "smtp_user", "smtp_password", "smtp_host")
EMAIL = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,}$")
TOPIC = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")

_lock = threading.Lock()
_last_event = 0.0          # monotonic time of the last attack event seen
last_result = "No alert sent yet"


def settings_file():
    return config.DATA_DIR / "notify.json"  # looked up each time so a changed data dir is honoured


def load():
    try:
        data = json.loads(settings_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    return {k: str(data.get(k, "")) for k in FIELDS} | {"smtp_host": data.get("smtp_host") or "smtp.gmail.com"}


def public_settings():
    """Settings for the dashboard: the password is never sent back, only whether one is set."""
    s = load()
    return {"ntfy_topic": s["ntfy_topic"], "email_to": s["email_to"], "smtp_user": s["smtp_user"],
            "smtp_host": s["smtp_host"], "has_password": bool(s["smtp_password"]),
            "quiet_minutes": QUIET_SECONDS // 60, "last_result": last_result}


def save(values):
    """Validate and store. An empty password keeps the saved one."""
    s = load()
    for key in FIELDS:
        value = str(values.get(key) or "").strip()
        if key == "smtp_password":
            if value:
                s[key] = value.replace(" ", "")  # Gmail shows app passwords in groups of four
            continue
        s[key] = value
    s["smtp_host"] = s["smtp_host"] or "smtp.gmail.com"
    if s["ntfy_topic"] and not TOPIC.match(s["ntfy_topic"]):
        raise ValueError("ntfy topic: use letters, digits, - or _ (max 64)")
    for key in ("email_to", "smtp_user"):
        if s[key] and not EMAIL.match(s[key]):
            raise ValueError(f"{key.replace('_', ' ')} is not a valid e-mail address")
    if not HOST.match(s["smtp_host"]):
        raise ValueError("SMTP server is not a valid host name")
    if s["email_to"] and not (s["smtp_user"] and s["smtp_password"]):
        raise ValueError("E-mail alerts need the sender address and its app password")
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    settings_file().write_text(json.dumps(s), encoding="utf-8")
    try:
        os.chmod(settings_file(), 0o600)
    except OSError:
        pass
    return public_settings()


def send(title, body):
    """Send on every configured channel; returns a short human-readable result."""
    global last_result
    s = load()
    results = []
    if s["ntfy_topic"]:
        try:
            r = requests.post(f"https://ntfy.sh/{s['ntfy_topic']}", data=body.encode("utf-8"), timeout=10,
                              headers={"Title": title, "Priority": "high", "Tags": "rotating_light"})
            results.append("phone push sent" if r.ok else f"phone push failed ({r.status_code})")
        except requests.RequestException as exc:
            results.append(f"phone push failed ({type(exc).__name__})")
    if s["email_to"]:
        try:
            msg = EmailMessage()
            msg["Subject"], msg["From"], msg["To"] = title, s["smtp_user"], s["email_to"]
            msg.set_content(body)
            with smtplib.SMTP_SSL(s["smtp_host"], 465, timeout=15) as smtp:
                smtp.login(s["smtp_user"], s["smtp_password"])
                smtp.send_message(msg)
            results.append("e-mail sent")
        except (OSError, smtplib.SMTPException) as exc:
            results.append(f"e-mail failed ({type(exc).__name__})")
    last_result = time.strftime("%Y-%m-%d %H:%M:%S ") + ("; ".join(results) or "no channel configured")
    log.info("Alert: %s", last_result)
    return last_result


def is_new_episode(now):
    """True when no attack event was seen for QUIET_SECONDS; also records this event."""
    global _last_event
    with _lock:
        new = _last_event == 0.0 or now - _last_event >= QUIET_SECONDS
        _last_event = now
        return new


def on_event(event):
    """Called for every logged attack event. Sends at most one alert per attack episode."""
    if not is_new_episode(time.monotonic()):
        return
    body = (f"Attack started at {event.get('timestamp', '')[:19].replace('T', ' ')} UTC\n"
            f"Attacker: {event.get('attacker_ip')}\n"
            f"Target: {event.get('decoy_service')} port {event.get('port')}\n"
            f"Activity: {event.get('mitre_name') or event.get('attack_type')} ({event.get('severity')})\n"
            f"Further alerts are muted until the attacks stop for {QUIET_SECONDS // 60} minutes.\n"
            f"Dashboard: {config.DASHBOARD_URL}")
    threading.Thread(target=send, args=("KARMA: attack started", body), daemon=True).start()


if __name__ == "__main__":
    # Self-check of the episode rule: first event alerts, events inside the hour don't, a gap re-arms.
    assert is_new_episode(1000.0)
    assert not is_new_episode(1000.0 + 60)
    assert not is_new_episode(1000.0 + 60 + QUIET_SECONDS - 1)
    assert is_new_episode(1000.0 + 60 + QUIET_SECONDS - 1 + QUIET_SECONDS)
    print("notifier episode rule ok")
