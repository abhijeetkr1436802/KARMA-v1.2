# K.A.R.M.A SIEM

A single-host honeypot monitoring application with an authenticated management dashboard, SQLite storage, CSV audit segments, SSH/Web/TCP decoys, rule-based MITRE classification, and optional DeepSeek chat/email analysis.

Developed by Abhijeet Kumar, Kanaka C, Raghunandan T V, and Sanjay Kashyap at The Oxford Evening Polytechnic, guided by Subhash J R.

## Run locally

Tested with Python 3.14 on Windows. Install the locked runtime dependencies into your Python installation:

```powershell
python -m pip install -r requirements.txt
python run.py
```

For a terminal server without Tkinter:

```powershell
python run.py --headless
```

Visit `http://localhost:8000`. On first startup a random admin token is saved to `%USERPROFILE%/.karma/admin-token`. Read that file locally and enter the token on the login page. Do not paste the token into chat or source control. Set `KARMA_ADMIN_TOKEN` to supply your own 32+ character random secret.

The management console is loopback-only in development, including API and WebSocket access. Browser sessions expire after eight hours. API clients use `Authorization: Bearer <token>`. Cookie-authenticated mutations require `X-Karma-Request: 1`; the dashboard supplies it automatically. Changing the token and restarting invalidates existing sessions.

## Live demo: https://karma-honeypot.com with Windows and Linux attackers

Three PCs on the same network (Wi-Fi, switch or the KARMA PC's mobile hotspot):

| PC | Role |
| --- | --- |
| KARMA PC (Windows) | Runs KARMA, shows the dashboard and the live visualizer |
| Attacker 1 (Windows) | Scans and attacks the KARMA PC's LAN IP |
| Attacker 2 (Linux) | Scans and attacks the KARMA PC's LAN IP |

**One-time setup on the KARMA PC** (Administrator PowerShell, in the repo folder):

```powershell
python -m pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File tools\setup-demo.ps1
```

The script maps `karma-honeypot.com` to this PC, creates and trusts a local HTTPS certificate,
allows Python through Windows Firewall on every network profile, warns about busy ports
(turn off Remote Desktop if 3389 is taken) and prints the LAN IP the attackers should target.
Then start KARMA with `python run.py`, launch the server and open:

- `https://karma-honeypot.com` for the dashboard
- `https://karma-honeypot.com/visualizer` for the live shield diagram. Press **Fullscreen** on the projector.

The dashboard stays private to the KARMA PC; attackers only reach the decoys.
Without the certificate, KARMA falls back to `http://localhost:8000`.

**Attack script.** Replace `<KARMA-IP>` with the printed LAN IP:

| Stage | Linux attacker | Windows attacker |
| --- | --- | --- |
| Recon | `nmap -sT -sV -p 21,23,2222,3389,8080 <KARMA-IP>` | `nmap -sT -p 21,23,2222,3389,8080 <KARMA-IP>` (if Nmap is installed) or `Test-NetConnection <KARMA-IP> -Port 2222` |
| Web probe | `curl "http://<KARMA-IP>:8080/?id=1+UNION+SELECT+password+FROM+users"` | Open `http://<KARMA-IP>:8080` in Edge |
| Honeytoken | `curl http://<KARMA-IP>:8080/api/v1/auth/keys` | Edge: `http://<KARMA-IP>:8080/secret-vault-admin-login-php` |
| Break-in | `ssh root@<KARMA-IP> -p 2222` (any password), then `ls`, `cd /srv/company`, `cat contacts.csv` | Same in PowerShell `ssh` (built into Windows 10/11) |
| Escalation | `whoami` or `cat /etc/passwd` inside the SSH session | Same |
| FTP loot | `ftp <KARMA-IP>`, user `Admin` | `ftp <KARMA-IP>`, user `Admin` |

Use `nmap -sT` (connect scan): the default root SYN scan (`-sS`) never completes a TCP connection,
so no honeypot can see it. The visualizer labels each attacker's OS from its SSH client banner or
browser user agent (Nmap and curl don't reveal an OS).

**Contain vs Observe.** In *Contain* mode scans, page views and logins are logged but never
blocked. Only high-risk actions (SQL injection, honeytokens, `whoami`/`cat /etc/...`) quarantine
the attacker, which ends the demo on a "contained" moment. Use *Observe* to explore the fake shell
freely, and unblock attacker IPs in the dashboard between rehearsals.

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
- Private LAN/loopback addresses use Bengaluru, India as an explicitly **configured lab location**, not a measured attacker origin. Public addresses remain unknown without a geolocation provider. See `.env.example` to disable or change the lab marker.
- Without `DEEPSEEK_API_KEY`, chat/email analysis falls back locally. The email heuristic does not certify a message as legitimate.
- Configured email analysis sends headers and up to 2,500 characters of body text to DeepSeek. Chat sends the selected conversation history. Sending live SIEM context is opt-in in the dashboard.
- Email `Authentication-Results` headers are untrusted input. SPF/DKIM is not independently verified. Outlook binary `.msg` is unsupported; export RFC822 `.eml` instead.
- Captured SSH/web login passwords are redacted; arbitrary attack payloads can still contain sensitive data. Restrict access to the data directory and backups.
- Generated API keys/credential honeytokens are decoy strings, not provider-managed keys. They do not detect use outside KARMA. Custom URL tokens are routed by the web sensor.

## SSH and document demonstration

Restart KARMA after updating dependencies with `python -m pip install -r requirements.txt`.
KARMA uses the Python interpreter you launch it with; it does not switch environments. Missing dependencies are reported before opening the launcher, with an install command for that interpreter.
In the dashboard's **Document decoy lab** panel choose **Observe** to prevent automatic
quarantine from ending the demo. Existing blocks still apply: unblock your test IP
in Attacker Profiles. The choice persists across restarts; switch back to **Contain**
when the demonstration ends.

```powershell
ssh root@192.168.137.1 -p 2222
```

The SSH sensor accepts synthetic credentials in observation mode. Type `help` to see
the emulated commands, then try `ls -la`, `cd /srv/company`, `pwd`, and `cat contacts.csv`.
Each connection has an isolated in-memory filesystem. It supports common file and
discovery commands, not a full Linux shell: pipelines, redirection, program execution,
outbound connections and installation commands are unsupported. Nothing executes on
the host. Sessions have a 15-minute lifetime and 120-second idle timeout, with at most
128 virtual file/directory entries, 2 MiB of copied content, and 32 open SFTP handles.
The terminal supports Up/Down command history, Backspace, Ctrl+C to cancel input,
and Ctrl+D to log out. CRLF input is treated as one Enter key. Password entry allows
up to 120 seconds. Unknown commands remain simulated errors; no host shell is invoked.

If SSH reports `kex_exchange_identification: read: Connection reset`, check Attacker
Profiles for a block on the connecting address. A quarantined connection is rejected
before SSH negotiation. The server log now names the blocked address and listener.
For an approved interactive lab, choose Observe and unblock that specific test address.
Changing mode alone does not remove existing blocks.

Download actual synthetic reports from another terminal:

```powershell
sftp -P 2222 root@192.168.137.1
# At the sftp prompt:
get /root/company_data_2026.pdf
get /root/company_financials_25-26.xlsx
bye
```

The dashboard records **Decoy file read started** when the first bytes are requested.
Open the PDF or workbook, follow **Open document acknowledgement page**, then click
**Confirm document interaction**. A dashboard popup and retained event show the
document, callback connection IP, original SSH connection IP, and session identifier.
Opening the file alone sends no signal. The reports contain no macros, executable
payloads or backdoors; a confirmation does not prove device compromise or identify a
person. Link preview GET requests do not count as confirmations. Each explicit POST
is a separate observation; scanners could submit forms too.

Links use the SSH connection's local IP and port 8080 by default. For this LAN you can
set `$env:KARMA_CALLBACK_BASE_URL="http://192.168.137.1:8080"` before launch. The web
sensor must be enabled and reachable from the reader's machine. Links expire after
seven days; the newest 10,000 document tokens are retained. Clearing telemetry revokes
all document links. The committed PDF/XLSX are templates with inactive placeholder
links; obtain personalized copies through SFTP for the demonstration.

For a changed SSH host-key warning, compare the reported fingerprint with the saved
server key before removing the specific cached entry:

```powershell
ssh-keygen -lf "$env:USERPROFILE/.karma/ssh_host_rsa_key"
# Only after the fingerprints match:
ssh-keygen -R "[192.168.137.1]:2222"
```

Keep the per-installation `ssh_host_rsa_key` across restarts and upgrades. Never turn
off strict host-key checking to hide a mismatch.

## Checks

### FTP archive (port 21)

Restart the server after updating to replace the old banner-only FTP listener.
Windows `ftp` uses active data connections; allow the FTP client through its local
firewall for listings/downloads. Passive clients use an ephemeral data port on the
server; those ports must be reachable on the lab network. SFTP on 2222 needs no
separate data connection and is preferable across restrictive firewalls/NAT.

```text
ftp 192.168.137.1
Admin
<any dummy password>
pwd
dir
ls
cd reports
binary
get company_data_2026.pdf
cd ../finance
get company_financials_25-26.xlsx
cd ..
get README.txt
bye
```

FTP starts in `/srv/company`, with `finance`, `reports`, `operations`, and `archive`
directories and synthetic text/CSV records. `PWD`/`XPWD`, `CWD`/`CDUP`, `LIST`/`NLST`,
`RETR`, `SIZE`, `MDTM`, `TYPE`, `PORT`/`EPRT`, `PASV`/`EPSV`, `SYST`, `FEAT`, `NOOP`,
and `HELP` are supported. Uploads and mutations are rejected: this is a read-only
virtual archive. Active data endpoints must match the control connection's source
IP and use an unprivileged port. FTP passwords are redacted from telemetry.

## Regression checks

```powershell
python -m pip install -r requirements-dev.txt
python -B -m unittest discover -s tests -v
node tests/frontend.test.cjs
python -m pip check
python -m pip_audit --local
```

Tests use temporary databases and loopback ephemeral ports. They do not contact DeepSeek, change firewall rules, or alter existing telemetry. The Python lockfile records the tested dependency closure; `requirements.in` lists upgrade inputs. Refresh dependencies in a clean environment, rerun checks and audit, then update the lockfile. CI runs regression checks on Windows and Linux.

## Packaging

Install PyInstaller separately in your build environment, then run `python setup.py`. The backend is collected as Python modules; runtime data and per-installation SSH keys are stored outside the executable bundle. The executable build is an optional distribution path and must be smoke-tested on the target Windows version.

## License

All rights reserved, Team K.A.R.M.A, 2025–2026.
