# Operating KARMA

## Supported topology

Use one process and one worker per private local data directory. An exclusive instance lock rejects duplicate processes. SQLite WAL and bounded sensor client pools support a single host; this is not a distributed SIEM or HA deployment. Do not put the database on a network share. Run under a dedicated low-privilege account on an isolated honeypot host. Low ports may require port forwarding or narrowly scoped bind capabilities on Linux; do not run the entire service as root for convenience.

Management and sensor listeners are separate. Restrict management port 8000 to an operator network/VPN using the host/network firewall. Public sensors default to all IPv4 interfaces; use `KARMA_SENSOR_HOST` to select a specific sensor interface.

## TLS and credentials

Production fails startup without an explicit random admin token of at least 32 characters. `run.py` also requires a certificate and private key. Configure secrets in the service manager, not in a committed file. Example (replace placeholders with real values):

```powershell
$env:KARMA_ENV = "production"
$env:KARMA_ADMIN_TOKEN = "<32-or-more-random-characters-from-your-secret-store>"
$env:KARMA_HOST = "0.0.0.0"
$env:KARMA_ALLOWED_HOSTS = "soc.example.internal"
$env:KARMA_DATA_DIR = "C:/ProgramData/KARMA/private"
.\.venv\Scripts\python run.py --headless --certfile C:/certs/fullchain.pem --keyfile C:/certs/key.pem
```

Use a trusted TLS certificate whose name matches the configured host. Production rejects plain HTTP, uses Secure/HttpOnly/SameSite=Strict cookies, and checks Host and Origin. Forwarded client/protocol headers are disabled. The documented path terminates TLS in Uvicorn; a reverse-proxy topology requires separate configuration and validation. Never trust arbitrary forwarded headers from sensor clients.

Rotate the previously committed DeepSeek credential with the provider if it was valid. Removing it from the current tree does not revoke it or erase Git history. The published SSH private host key has been removed; each installation generates a new key. Expected SSH host fingerprints therefore change during upgrade.

The generated development token file and runtime directory need service-account-only ACLs on Windows. On Unix, token/key files are created with mode 0600 and the data directory with mode 0700. Secure existing directories and backups as well. Admin sessions are bearer-equivalent, expire after eight hours, and are invalidated by token rotation/restart. This installation has one operator credential, not RBAC or per-user identity auditing.

## Data, retention, and upgrades

Default data location: `~/.karma`. `KARMA_DATA_DIR` overrides it. Files include `karma.db`, SQLite WAL/SHM files, `admin-token` (development), `ssh_host_rsa_key`, `instance.lock`, and `logs/`.

Before upgrading, stop the old service and back up its database/logs. For a live backup use SQLite's backup API; do not copy only the main DB while WAL writes are active. To migrate the old root-level `aegis_soc.db`, stop both versions, back it up, and copy it to the new directory as `karma.db` before first launch. Do not overwrite an existing destination database. Existing schema columns are migrated individually. Old mock geolocation records are historical demo data and should be cleared or explicitly treated as simulated.

Attack events retain approximately `KARMA_MAX_EVENTS` rows (default 100,000; pruning every 100 inserts). CSV segments rotate near 20 MiB, retaining at most 50 segments. Archive audit files elsewhere before retention removes them if longer history is required. Dashboard totals describe retained events, not an immutable lifetime counter. Attacker profiles are pruned after their events age out unless blocked. Quarantine and honeytoken records persist until operators change them. The active CSV cannot be deleted via the API. CSV previews are capped at 1,000 records; downloads provide the full segment.

There is no built-in off-host backup, tamper-proof audit ledger, or automatic disk-free monitoring. Configure service monitoring and backup jobs on the deployment host. Test restore and storage-exhaustion recovery before exposure.

## Health and limits

Private LAN/loopback events display the operator-configured Bengaluru lab marker on
both Esri maps. Tooltips, reports and new CSV exports label its source as configured.
This is not IP geolocation. Public (globally routable) addresses are located at
city level with ip-api.com when the event is logged (only the IP is sent, over HTTP;
cached one day; at most 40 lookups a minute) and the result is stored with the event.
Set `KARMA_GEOIP_ENABLED=0` to never contact ip-api.com. Documentation, multicast and
unspecified addresses, and public addresses that could not be looked up, have no
coordinates. API reads apply the current lab setting to historical records;
stored event coordinates describe the configuration at event creation. Existing CSV
files are not rewritten. Set `KARMA_LAB_LOCATION_ENABLED=0` to disable the override.

The dashboard's observation mode suppresses automatic quarantine for demonstrations;
manual and pre-existing blocks still apply. The saved mode takes precedence over the
initial `KARMA_ENGAGEMENT_MODE` environment default (`contain`). Inspect this setting
before exposing sensors. Document acknowledgement routes run on the web sensor, not
the management listener. For NAT or remote labs, configure a reachable HTTP(S) origin
with `KARMA_CALLBACK_BASE_URL`. An acknowledgement identifies a link interaction,
not computer compromise. Tokens expire after seven days, are stored as hashes, and
are bounded to 10,000 records. The shell cannot execute host programs or access host
files, and SFTP uploads are rejected.

- `/healthz` reports process liveness; production requires HTTPS and an allowed Host even for health probes.
- Authenticated `/api/status` reports listener state and telemetry queue drops. Alert on ERROR/STOPPED enabled sensors or a growing drop count.
- HTTP bodies: 2 MiB including multipart overhead; body reads time out after 10 seconds without data.
- Login attempts: 10 per minute per source IP. Other HTTP/WebSocket connection requests: 600 per minute per source IP, with bounded tracking.
- TCP clients: at most 64 per listener, with socket timeouts. Web sensor concurrency: 64. Management concurrency: 128 via the provided entry point.
- AI requests: four workers; excess requests receive 429. External requests have timeouts. No retries that silently multiply provider charges.
- WebSockets: 64 clients, 100 queued events per client, slow clients time out. Overflow drops oldest queued events; the dashboard refreshes from persisted state.
- Request logs and application errors go to service stdout/stderr; capture and rotate those logs through the service manager.

Chart.js, Leaflet, the fonts and a 1:110m world outline (Natural Earth via world-atlas) are bundled in `frontend/vendor`. Only map tiles (Esri/OpenStreetMap) and public-IP geolocation (ip-api.com) use the internet; offline, maps fall back to the bundled outlines. For environments that prohibit third-party requests, set `KARMA_GEOIP_ENABLED=0` and use approved map tiles.

## Release acceptance

Run regression tests, frontend checks, `pip check`, and `pip-audit` from the locked environment. Validate the target OS, certificate chain, startup/restart, listener conflicts, backup/restore, resource limits under expected load, and firewall exposure. The automated suite exercises isolated requests, concurrency, a real loopback SSH handshake, listener shutdown, and security boundaries; it is not a penetration test or a capacity certification.
