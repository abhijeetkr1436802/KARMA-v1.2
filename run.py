"""Desktop or single-process headless entry point."""
import argparse
import logging
import importlib.util
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent


def check_dependencies():
    modules = ('fastapi', 'uvicorn', 'websockets', 'paramiko', 'pydantic',
               'requests', 'python_multipart', 'pypdf')
    missing = [name for name in modules if importlib.util.find_spec(name) is None]
    if missing:
        command = [sys.executable, '-m', 'pip', 'install', '-r', str(ROOT / 'requirements.txt')]
        if sys.platform == 'win32':
            install_command = '& ' + ' '.join("'" + part.replace("'", "''") + "'" for part in command)
        else:
            import shlex
            install_command = shlex.join(command)
        raise SystemExit('KARMA cannot start: missing dependencies: ' + ', '.join(missing)
                         + '\nPython: ' + sys.executable + '\nInstall with:\n' + install_command)


def main():
    parser = argparse.ArgumentParser(description="KARMA SIEM")
    parser.add_argument("--headless", action="store_true", help="Run without Tkinter")
    parser.add_argument("--certfile", help="TLS certificate PEM")
    parser.add_argument("--keyfile", help="TLS private key PEM")
    args = parser.parse_args()
    check_dependencies()
    from backend import config
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if config.PRODUCTION and not (args.certfile and args.keyfile):
        parser.error("Production requires --headless, --certfile and --keyfile")
    if config.PRODUCTION and not args.headless:
        parser.error("Use --headless in production")
    if args.headless:
        import uvicorn
        logging.info("Management login at %s://%s:%s; local token file: %s",
                     "https" if args.certfile else "http", config.HOST, config.PORT_API, config.ADMIN_TOKEN_FILE)
        uvicorn.run("backend.app:app", host=config.HOST, port=config.PORT_API,
                    proxy_headers=False, workers=1, limit_concurrency=128,
                    timeout_keep_alive=5, timeout_graceful_shutdown=15,
                    ws_max_size=4096, ws_max_queue=16,
                    ssl_certfile=args.certfile, ssl_keyfile=args.keyfile)
    else:
        from backend.launcher_gui import launch_gui
        launch_gui()


if __name__ == "__main__":
    main()
