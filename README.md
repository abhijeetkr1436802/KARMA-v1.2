# K.A.R.M.A SIEM

A single-host honeypot monitoring application with an authenticated management dashboard, SQLite storage, CSV audit segments, SSH/Web/TCP decoys, rule-based MITRE classification, and optional DeepSeek chat/email analysis.

Developed by Abhijeet Kumar, Kanaka C, Raghunandan T V, and Sanjay Kashyap at The Oxford Evening Polytechnic, guided by Subhash J R.

## Run locally

Tested with Python 3.14 on Windows. Install the locked runtime dependencies in an isolated environment:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python run.py
```

For a terminal server without Tkinter:

```powershell
.\.venv\Scripts\python run.py --headless
```

Visit `http://localhost:8000`. On first startup a random admin token is saved to `%USERPROFILE%/.karma/admin-token`. Read that file locally and enter the token on the login page. Do not paste the token into chat or source control. Set `KARMA_ADMIN_TOKEN` to supply your own 32+ character random secret.

The management console is loopback-only in development, including API and WebSocket access. Browser sessions expire after eight hours. API clients use `Authorization: Bearer <token>`. Cookie-authenticated mutations require `X-Karma-Request: 1`; the dashboard supplies it automatically. Changing the token and restarting invalidates existing sessions.

## Network surfaces

| Port | Purpose |
| --- | --- |
| 8000 | Authenticated dashboard/API; localhost by default |
| 8080 | Public web decoy and honeytoken URL/API traps |
| 2222 | SSH simulation; commands are never executed by the OS |
| 21, 23, 3389 | FTP/Telnet/RDP decoys |

The previous public traps on port 8000 have moved to 8080. The misleading demo “production vault” login has been removed. Try `/secret-vault-admin-login-php` or `/api/v1/auth/keys` on the web sensor. Only enable sensors in networks you administer. Port conflicts are reported as ERROR in the dashboard rather than ACTIVE. Custom decoys create TCP listeners; toggles change actual listener state. API trap toggles depend on the web sensor being enabled.

Quarantine blocks new connections and subsequent interactions on KARMA sensors. It does **not** install OS firewall rules or isolate machines from other services. A triggering SSH login may now be rejected and later connections blocked; unblock the testing IP in the dashboard before repeating a demonstration. Desktop testing remains available from the launcher; the web API cannot launch desktop windows or attack simulations.

## Production deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for TLS, service operation, backups, retention, upgrades, and operational limits. This repository includes hardening and regression tests; production readiness still requires validation on your actual host and traffic profile.

## Truthful analysis and privacy

- Event/attacker reports and MITRE mappings are deterministic heuristics, not external AI verdicts.
- IP locations remain unknown without a geolocation provider; private IPs are not assigned invented cities.
- Without `DEEPSEEK_API_KEY`, chat/email analysis falls back locally. The email heuristic does not certify a message as legitimate.
- Configured email analysis sends headers and up to 2,500 characters of body text to DeepSeek. Chat sends the selected conversation history. Sending live SIEM context is opt-in in the dashboard.
- Email `Authentication-Results` headers are untrusted input. SPF/DKIM is not independently verified. Outlook binary `.msg` is unsupported; export RFC822 `.eml` instead.
- Captured SSH/web login passwords are redacted; arbitrary attack payloads can still contain sensitive data. Restrict access to the data directory and backups.
- Generated API keys/credential honeytokens are decoy strings, not provider-managed keys. They do not detect use outside KARMA. Custom URL tokens are routed by the web sensor.

## Checks

```powershell
.\.venv\Scripts\python -m pip install -r requirements-dev.txt
.\.venv\Scripts\python -B -m unittest discover -s tests -v
node tests/frontend.test.cjs
.\.venv\Scripts\python -m pip check
.\.venv\Scripts\python -m pip_audit --local
```

Tests use temporary databases and loopback ephemeral ports. They do not contact DeepSeek, change firewall rules, or alter existing telemetry. The Python lockfile records the tested dependency closure; `requirements.in` lists upgrade inputs. Refresh dependencies in a clean environment, rerun checks and audit, then update the lockfile. CI runs regression checks on Windows and Linux.

## Packaging

Install PyInstaller separately in your build environment, then run `python setup.py`. The backend is collected as Python modules; runtime data and per-installation SSH keys are stored outside the executable bundle. The executable build is an optional distribution path and must be smoke-tested on the target Windows version.

## License

All rights reserved, Team K.A.R.M.A, 2025–2026.
