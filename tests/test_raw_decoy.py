import unittest
from unittest.mock import patch
from backend.sensors import raw_decoy as rd


class FakeSock:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = bytearray()
    def recv(self, n):
        return self.chunks.pop(0) if self.chunks else b""
    def sendall(self, b):
        self.sent += b
    def settimeout(self, t):
        pass
    def close(self):
        pass


def _server():
    srv = rd.RawDecoyServer.__new__(rd.RawDecoyServer)
    srv.running = True
    srv.broadcast_callback = None
    events = []
    srv._log_and_broadcast = lambda ip, p, svc, atk, payload, m: events.append((svc, atk, payload))
    return srv, events


class RawDecoyTests(unittest.TestCase):
    def test_telnet_buffers_chars_into_one_login(self):
        srv, events = _server()
        chunks = [b"\xff\xfd\x01"] + [c.encode() for c in "admin\r"] + [c.encode() for c in "pass\r"]
        fs = FakeSock(chunks)
        with patch.object(rd, "is_quarantined", lambda ip: False):
            srv._handle_telnet(fs, "10.0.0.9", 23)
        logins = [e for e in events if e[1] == "Telnet Credential Brute-Force"]
        self.assertEqual(len(logins), 1)
        self.assertIn("USER 'admin'", logins[0][2])
        self.assertEqual(bytes(fs.sent).decode("latin-1").count("Login incorrect"), 1)

    def test_rdp_captures_mstshash_user(self):
        srv, events = _server()
        data = b"\x03\x00\x00\x2a\x25\xe0Cookie: mstshash=Administrator\r\n\x01\x00\x08\x00"
        fs = FakeSock([data])
        with patch.object(rd, "is_quarantined", lambda ip: False):
            srv._handle_rdp(fs, "10.0.0.9", 3389)
        self.assertTrue(any("Administrator" in e[2] for e in events))
        self.assertTrue(len(fs.sent) > 0)


if __name__ == "__main__":
    unittest.main()
