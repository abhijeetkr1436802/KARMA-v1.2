import unittest
from backend.config import QUARANTINE_SCORE_THRESHOLD as T
from backend.engine.threat_score import calculate_event_risk


class ThreatScoreTests(unittest.TestCase):
    def test_repetition_alone_never_reaches_quarantine(self):
        for base in (40, 45, 50, 65, 70):  # scans, page views, SSH logins
            self.assertLess(calculate_event_risk(base, attempt_count=500)[0], T)

    def test_high_risk_events_still_quarantine(self):
        for base in (85, 90, 95):  # exploit, command execution, honeytoken
            self.assertGreaterEqual(calculate_event_risk(base, 1)[0], T)


if __name__ == "__main__":
    unittest.main()
