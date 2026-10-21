import json
import socket
import threading
import unittest

from backend import tunnel


def frame(msg):
    return json.dumps(msg).encode() + b"\0"


def read_frame(sock):
    buf = b""
    while not buf.endswith(b"\0"):
        buf += sock.recv(1)
    return json.loads(buf[:-1])


class FakeBoreServer:
    """Minimal bore server: grants port 40001, then forwards one connection carrying b'ping'."""
    def __init__(self, reply=None):
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.reply = reply or {"Hello": 40001}
        self.echoed = None
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        control, _ = self.sock.accept()
        assert read_frame(control) == {"Hello": 0}
        control.sendall(frame(self.reply))
        if "Hello" not in self.reply:
            return
        control.sendall(frame("Heartbeat") + frame({"Connection": "1234"}))
        data, _ = self.sock.accept()
        assert read_frame(data) == {"Accept": "1234"}
        data.sendall(b"ping")
        self.echoed = data.recv(4)
        self.control = control


def echo_server():
    srv = socket.create_server(("127.0.0.1", 0))
    def run():
        conn, _ = srv.accept()
        conn.sendall(conn.recv(4))
    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1]


class TunnelTests(unittest.TestCase):
    def test_forwards_connection_to_local_decoy_and_never_dashboard(self):
        bore = FakeBoreServer()
        decoy = echo_server()
        t = tunnel.Tunnels("127.0.0.1", bore.port)
        t.start([decoy, tunnel.config.PORT_API])
        self.assertEqual(t.status()["ports"], {decoy: "127.0.0.1:40001"})
        for _ in range(50):
            if bore.echoed:
                break
            threading.Event().wait(0.05)
        self.assertEqual(bore.echoed, b"ping")
        t.stop()
        self.assertFalse(t.status()["enabled"])

    def test_server_error_and_unreachable_server_reported(self):
        bore = FakeBoreServer({"Error": "port already in use"})
        t = tunnel.Tunnels("127.0.0.1", bore.port)
        t.start([2222])
        self.assertIn("port already in use", t.status()["error"])
        dead = socket.create_server(("127.0.0.1", 0)); port = dead.getsockname()[1]; dead.close()
        t = tunnel.Tunnels("127.0.0.1", port)
        t.start([2222])
        self.assertEqual(t.status()["ports"], {2222: None})
        self.assertIn("could not reach", t.status()["error"])


if __name__ == "__main__":
    unittest.main()
