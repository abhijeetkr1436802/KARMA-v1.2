"""
CSV SIEM Audit Logger for K.A.R.M.A Cloud SIEM
Automatically creates timestamped CSV log files on server startup (logs/karma_audit_YYYY-MM-DD_HH-MM-SS.csv),
logs all incoming attack telemetry in real-time with immediate flushing,
and safely saves and closes on server shutdown.
"""

import os
import csv
import threading
from backend.config import LOG_DIR
from pathlib import Path
import logging
import time
from datetime import datetime

class AuditCsvLogger:
    def __init__(self, log_dir=LOG_DIR):
        self.lock = threading.RLock()
        self.log_dir = log_dir
        self.file_path = None
        self.file_handle = None
        self.csv_writer = None
        self.is_active = False
        self.last_error = None

    def start(self):
        try:
            if not os.path.exists(self.log_dir):
                os.makedirs(self.log_dir)

            # Retain at most 50 completed 20 MiB segments per installation.
            for old in sorted(Path(self.log_dir).glob("karma_audit_*.csv"))[:-49]:
                if old.is_file() and not old.is_symlink():
                    old.unlink()
            timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f")
            filename = f"karma_audit_{timestamp_str}.csv"
            self.file_path = os.path.join(self.log_dir, filename)

            self.file_handle = open(self.file_path, mode="w", newline="", encoding="utf-8")
            self.csv_writer = csv.writer(self.file_handle, quoting=csv.QUOTE_MINIMAL, escapechar="\\")

            # Write Standard CSV Header
            headers = [
                "Log_ID",
                "Timestamp",
                "Attacker_IP",
                "Country",
                "City",
                "Target_Service",
                "Port",
                "Attack_Type",
                "Executed_Payload",
                "MITRE_ID",
                "MITRE_Name",
                "Severity",
                "Risk_Score",
                "Action_Taken",
                "Location_Source",
                "Location_Label"
            ]
            self.csv_writer.writerow(headers)
            self.file_handle.flush()
            self.is_active = True
            self.last_error = None
            print(f"[CSV Audit Logger] Session log initialized: {self.file_path}")
        except Exception as e:
            raise RuntimeError("Cannot initialize audit log") from e

    def log_event(self, event):
        with self.lock:
            return self._log_event(event)

    def _log_event(self, event):
        if not self.is_active or not self.csv_writer:
            return

        try:
            payload_str = str(event.get("payload", "")).replace("\n", " ").replace("\r", " ")
            row = [
                event.get("id", ""),
                event.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%S")),
                event.get("attacker_ip", ""),
                event.get("country", ""),
                event.get("city", ""),
                event.get("decoy_service", ""),
                event.get("port", ""),
                event.get("attack_type", ""),
                payload_str,
                event.get("mitre_id", ""),
                event.get("mitre_name", ""),
                event.get("severity", ""),
                event.get("risk_score", 0),
                "Blocked on KARMA sensors" if event.get("quarantined") else "Monitored",
                event.get('geo_source', 'unknown'),
                event.get('geo_label', 'Location unavailable')
            ]
            row = ["'" + str(v) if str(v).lstrip().startswith(("=", "+", "-", "@")) else v for v in row]
            self.csv_writer.writerow(row)
            if self.file_handle.tell() > 20 * 1024 * 1024:
                self._stop()
                self.start()
            self.file_handle.flush() # Immediate flush so no data is lost on crash/exit
        except Exception as e:
            self.last_error = "Audit CSV write failed; inspect service logs"
            logging.getLogger(__name__).exception("Audit CSV write failed")

    def stop(self):
        with self.lock:
            self._stop()

    def _stop(self):
        if self.file_handle:
            try:
                self.file_handle.flush()
                self.file_handle.close()
                print(f"[CSV Audit Logger] Session log saved and closed cleanly: {self.file_path}")
            except Exception as e:
                print(f"[CSV Audit Logger Error] Error closing CSV log file: {e}")
            finally:
                self.is_active = False

# Global instance for app import
audit_csv_logger = AuditCsvLogger()
