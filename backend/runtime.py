"""Prevent multiple processes from owning the same sensors and data directory."""
import os
from backend import config


def ignore_connection_reset(loop, context):
    """asyncio handler: Windows' Proactor loop logs a traceback whenever a client
    (browser, scanner, attacker) drops a TCP connection. Harmless on a honeypot."""
    if isinstance(context.get("exception"), ConnectionResetError):
        return
    loop.default_exception_handler(context)


class InstanceLock:
    def __enter__(self):
        config.DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.file = open(config.DATA_DIR / "instance.lock", "a+b")
        try:
            if os.name == "nt":
                import msvcrt
                self.file.seek(0)
                if not self.file.read(1):
                    self.file.write(b"0")
                    self.file.flush()
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.file.close()
            raise RuntimeError("Another KARMA process already owns this data directory. Use one worker.") from exc
        return self

    def __exit__(self, *args):
        if os.name == "nt":
            import msvcrt
            self.file.seek(0)
            msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
        self.file.close()
