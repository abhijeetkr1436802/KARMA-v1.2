"""Desktop or single-process headless entry point."""
import argparse
import logging
from backend import config


def main():
    parser = argparse.ArgumentParser(description="KARMA SIEM")
    parser.add_argument("--headless", action="store_true", help="Run without Tkinter")
    parser.add_argument("--certfile", help="TLS certificate PEM")
    parser.add_argument("--keyfile", help="TLS private key PEM")
    args = parser.parse_args()
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
