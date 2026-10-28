# K.A.R.M.A SIEM

A single-host honeypot monitoring application with an authenticated management dashboard, SQLite storage, CSV audit segments, SSH/Web/TCP decoys, rule-based MITRE classification, and optional DeepSeek chat/email analysis.

Developed by Abhijeet Kumar, Kanaka C, Raghunandan T V, and Sanjay Kashyap at The Oxford Evening Polytechnic, guided by Subhash J R.

## Documentation

- [Getting started](#getting-started-step-by-step) and [Live demo setup](#live-demo-setup-httpskarma-honeypotcom-with-windows-and-linux-attackers) (below)
- [Decoys and attacks guide](docs/DECOYS_AND_ATTACKS.md): every decoy, trap and honeytoken and how to attack it
- [Presentation speaker guide](docs/SPEAKER_GUIDE.md): what to say on each of the 25 slides
- [Viva Q&A](docs/VIVA_QA.md): short answers to likely examiner questions

## Getting started (step by step)

Follow these steps in order on the Windows PC that will run KARMA.

### Step 1 – Install the prerequisites

| Software | Version | Download |
| --- | --- | --- |
| Python | 3.14 (the version KARMA is tested and locked with) | https://www.python.org/downloads/ |
| Git | any recent version | https://git-scm.com/download/win |

While installing Python, tick **"Add python.exe to PATH"** and keep **tcl/tk and IDLE** selected
(Tkinter is needed for the desktop control panel).

Open a new **PowerShell** window and check that both are installed:

```powershell
python --version
git --version
```

### Step 2 – Download the project (git clone)

```powershell
cd $HOME\Desktop
git clone https://github.com/abhijeetkr1436802/KARMA-v1.2.git
cd KARMA-v1.2
```

All later commands are run from inside this `KARMA-v1.2` folder.

### Step 3 – Install the Python requirements

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

`requirements.txt` holds the exact package versions KARMA was tested with (FastAPI, Uvicorn,
Paramiko, WebSockets, Pydantic, Requests, python-multipart, pypdf). If a package is missing
later, `run.py` stops and prints the exact install command for you.

### Step 4 – (Optional) Create the `.env` settings file

KARMA works without this step. Create it only if you want AI Copilot chat or your own settings:

```powershell
copy .env.example .env
notepad .env
```

```env
# Enables free-form AI Copilot chat. Without it, the offline analyst still
# answers from live telemetry — no internet required.
DEEPSEEK_API_KEY=sk-your-deepseek-key-here

# Optional overrides (defaults shown):
# KARMA_DOMAIN=karma-honeypot.com
# KARMA_ADMIN_TOKEN=<your own 32+ character random secret>
# KARMA_ENGAGEMENT_MODE=contain
```

KARMA reads `.env` from the project folder and from the data folder `%USERPROFILE%\.karma`.
Real environment variables always win over `.env`. `.env` is git-ignored, so your key is never
committed. Restart KARMA after editing it. You can also paste the key into the launcher's
**AI Copilot — DeepSeek API Key** field and press **Save Key** (it is saved to
`%USERPROFILE%\.karma\.env` and works at once, also in the `.exe`).

### Step 5 – Run KARMA

```powershell
python run.py
```

The **K.A.R.M.A control panel** window opens:

1. Tick the decoy ports and traps you want.
2. Press **🚀 LAUNCH K.A.R.M.A SIEM SERVER**.
3. Open a browser on the same PC at **http://localhost:8000**.

If you ran the live demo setup (`tools\setup-demo.ps1`, see **Live demo setup** below), the dashboard is at **https://karma-honeypot.com** instead.

No desktop / no Tkinter (for example a server terminal)? Run it without the window:

```powershell
python run.py --headless
```

To stop KARMA press **🛑 STOP K.A.R.M.A SIEM SERVER**, or `Ctrl+C` in headless mode.

### Step 6 – Log in with the admin token

The login page asks for an **admin token**.

**Why it exists:** the dashboard can see every captured attack and can block or unblock IPs,
change the engagement mode and clear logs. KARMA has no user accounts, so a single long random
secret (the admin token) protects it. A random token cannot be guessed like a password, and it
is different on every PC, so nobody can log in with a value copied from GitHub.

**How it is created:** the first time the server starts, if you did not set `KARMA_ADMIN_TOKEN`,
KARMA generates a random 43-character token with Python's `secrets.token_urlsafe(32)` and saves
it to a file. Later starts reuse the same file, so the token stays the same.

**Where it is stored:**

```
C:\Users\<your-user>\.karma\admin-token
```

Show it in PowerShell, then copy and paste it into the login page:

```powershell
Get-Content $env:USERPROFILE\.karma\admin-token
```

- The same `.karma` folder also holds the database (`karma.db`), logs, SSH host key and TLS files.
- Want your own token? Put `KARMA_ADMIN_TOKEN=<32+ random characters>` in `.env` and restart.
- Forgot or leaked it? Stop KARMA, delete `admin-token`, start again: a new token is created and
  all old logins stop working.
- Never paste the token into chat, screenshots or source control.

Security details: the dashboard (port 8000) only accepts connections from this PC, including
its API and WebSocket. Browser sessions expire after eight hours. API clients send
`Authorization: Bearer <token>`. Cookie-authenticated changes require `X-Karma-Request: 1`;
the dashboard adds it automatically.

### Step 7 – (Optional) Build the standalone `.exe` with `setup.py`

This makes a version that runs on any Windows PC **without Python, Git or pip**. Run it on
the PC where Steps 1–3 are done:

```powershell
python setup.py
```

`setup.py` installs PyInstaller if it is missing, compiles KARMA, and creates:

| Output | What it is |
| --- | --- |
| `dist\KARMA_Cloud_SIEM\KARMA_Cloud_SIEM.exe` | the application |
| `dist\KARMA_Cloud_SIEM\HOW_TO_RUN.txt` | short usage notes |
| `dist\KARMA_Cloud_SIEM_Standalone_v1.2.zip` | the whole folder zipped, to copy to another PC |

**Run the standalone app:**

1. Copy the zip to the target PC and extract it (keep the whole folder together — the `.exe`
   needs the files next to it).
2. Double-click **`KARMA_Cloud_SIEM.exe`**. If Windows SmartScreen warns, click
   **More info → Run anyway** (the exe is not code-signed).
3. Press **🚀 LAUNCH K.A.R.M.A SIEM SERVER** and open **http://localhost:8000**.
4. Log in with the token from `%USERPROFILE%\.karma\admin-token` on **that** PC (Step 6).
   Each PC gets its own token.

Smoke-test the `.exe` on the target Windows version before the demo.

### Step 8 – (Optional) Run the tests

```powershell
python -m pip install -r requirements-dev.txt
python -B -m unittest discover -s tests -v
node tests/frontend.test.cjs
```

The Node.js test needs Node.js installed (https://nodejs.org).

### Getting updates later

```powershell
cd $HOME\Desktop\KARMA-v1.2
git pull
python -m pip install -r requirements.txt
```

## Live demo setup: https://karma-honeypot.com with Windows and Linux attackers

Do Steps 1–3 of Getting started first: the setup script needs Python and the requirements.

### What the demo looks like

| PC | Role |
| --- | --- |
| KARMA PC (Windows) | Runs KARMA, shows the dashboard and the live visualizer on the projector |
| Attacker 1 (Windows) | Scans and attacks the KARMA PC |
| Attacker 2 (Linux) | Scans and attacks the KARMA PC |

Nothing needs to be installed on the attacker PCs: they use built-in tools (`ssh`, `curl`,
`ftp`, a browser; `nmap` if it is already there).

### What `karma-honeypot.com` is (and is not)

`karma-honeypot.com` is **not a website on the internet** and you do **not** buy or register it.
It is a local name that only works **on the KARMA PC**, made in two parts:

1. **Name → this PC.** A line is added to the Windows *hosts* file
   (`C:\Windows\System32\drivers\etc\hosts`):

   ```
   127.0.0.1 karma-honeypot.com www.karma-honeypot.com
   ```

   Windows checks this file before asking the internet, so on this PC the name opens KARMA itself.
2. **Padlock (HTTPS).** `tools\make_cert.py` creates a private "KARMA Local Demo CA" and a
   certificate for `karma-honeypot.com`, `www.karma-honeypot.com`, `localhost` and `127.0.0.1`.
   The CA is added to Windows' *Trusted Root Certification Authorities*, so Edge and Chrome
   show a valid padlock. The CA's private key is thrown away right after signing, so it can
   never sign anything else.

When the certificate exists, KARMA serves the dashboard at **https://karma-honeypot.com**
(port 443) instead of http://localhost:8000. The dashboard still only accepts connections from
the KARMA PC itself. Attacker PCs never use the domain; they target the KARMA PC's **IP address**
(or a `bore.pub` tunnel address, see Demo step 6).

To use a different name, put `KARMA_DOMAIN=your-name.com` in `.env` **before** running the
setup script. The script and the certificate both read it from there.

### Demo step 1 – Open PowerShell as Administrator

The script edits the hosts file, the trusted certificate store and the firewall, which need
administrator rights.

1. Press **Start**, type **PowerShell**.
2. Right-click **Windows PowerShell** → **Run as administrator** → **Yes**.
   The title bar must say **Administrator**.
3. Go to the project folder (use your own path from Step 2):

   ```powershell
   cd $HOME\Desktop\KARMA-v1.2
   ```

Use the same Windows account that will run KARMA: the certificate is saved in that
account's `%USERPROFILE%\.karma\tls` folder.

### Demo step 2 – Run `setup-demo.ps1` (with the execution-policy bypass)

```powershell
powershell -ExecutionPolicy Bypass -File tools\setup-demo.ps1
```

**Why `-ExecutionPolicy Bypass`?** By default Windows refuses to run `.ps1` scripts
(error: *"running scripts is disabled on this system"*), and this script is not code-signed.
`-ExecutionPolicy Bypass` starts a **new PowerShell process** that is allowed to run this one
script. It does **not** change your PC's policy permanently; when the script ends, the normal
policy applies again.

Alternative with the same effect (only for the current window, ends when you close it):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\tools\setup-demo.ps1
```

Do **not** use `Set-ExecutionPolicy Unrestricted` machine-wide; it is not needed.

**What the script does, in order:**

1. Finds the real `python.exe` (not the Microsoft Store shortcut) and reads KARMA's
   domain and data folder from its settings.
2. Adds the `127.0.0.1 karma-honeypot.com www.karma-honeypot.com` line to the hosts file
   (only if it is not there yet) and flushes the DNS cache.
3. Runs `tools\make_cert.py` and imports `karma-local-ca.pem` into
   **Local Machine → Trusted Root Certification Authorities**.
4. Creates an inbound Windows Firewall rule **KARMA Honeypot** that allows `python.exe` on all
   network profiles (Domain, Private and Public, so phone hotspots work). It first removes any
   old **Block** rule for Python, which Windows creates if someone pressed *Cancel* on the
   firewall pop-up (Block wins over Allow).
5. Warns if ports 21, 23, 443, 2222, 3389 or 8080 are already used by another program.
6. Prints the dashboard URL and the KARMA PC's IP addresses for the attackers.

Expected end of output:

```
Done. Start KARMA with: python run.py   then open https://karma-honeypot.com
Attacker PCs target this PC's LAN address: 192.168.137.1, ...
```

If you see `WARNING: Port 3389 is already used by svchost`, Remote Desktop holds that port.
Turn it off in **Settings → System → Remote Desktop → Off**, or simply leave the RDP decoy
unticked in the launcher.

The script is safe to run again. Each run creates a fresh certificate and adds one more
"KARMA Local Demo CA" entry to the trusted store; remove old ones with the undo commands below
if you like.

### Demo step 3 – Manual setup (only if you cannot run the script)

Run in the **Administrator PowerShell** from Demo step 1, in the project folder:

```powershell
# 1. Point the domain at this PC
Add-Content "$env:SystemRoot\System32\drivers\etc\hosts" "`r`n127.0.0.1 karma-honeypot.com www.karma-honeypot.com"
ipconfig /flushdns

# 2. Create the HTTPS certificate and trust its local CA
python tools\make_cert.py
Import-Certificate -FilePath "$env:USERPROFILE\.karma\tls\karma-local-ca.pem" -CertStoreLocation Cert:\LocalMachine\Root

# 3. Allow the attacker PCs to reach the decoys through Windows Firewall
$Python = python -c "import sys; print(sys.executable)"
New-NetFirewallRule -DisplayName 'KARMA Honeypot' -Direction Inbound -Program $Python -Action Allow -Profile Any

# 4. Show this PC's IP addresses (the attacker PCs target this)
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' } | Select-Object InterfaceAlias, IPAddress
```

### Demo step 4 – Start KARMA and open the dashboard

Use a normal (non-admin) PowerShell in the project folder:

```powershell
python run.py
```

1. Tick the decoys and press **🚀 LAUNCH K.A.R.M.A SIEM SERVER**.
2. If Windows Firewall asks about Python, tick **Private and Public** and press **Allow**
   (never *Cancel*).
3. Open in **Edge or Chrome** (restart the browser once after the setup script):
   - **https://karma-honeypot.com** – dashboard; log in with the admin token (Step 6 of Getting started)
   - **https://karma-honeypot.com/visualizer** – live attack map for the projector; press **Fullscreen**

Firefox uses its own certificate list: set `security.enterprise_roots.enabled` to `true` in
`about:config`, or use Edge/Chrome. Without the certificate KARMA falls back to
http://localhost:8000.

### Demo step 5 – Connect the attacker PCs (same network)

All three PCs must be on the **same network** so the attackers can reach the KARMA PC's IP:

1. On the KARMA PC: **Settings → Network & Internet → Mobile hotspot → On**. Note the network
   name and password. (Or put all three PCs on the same Wi-Fi/switch.)
2. Connect both attacker PCs to that hotspot.
3. The KARMA PC's hotspot address is usually **192.168.137.1**. Confirm it with the IPs printed
   in Demo step 2. That address is `<KARMA-IP>` in the attack script below.
4. Quick test from an attacker: `ssh root@<KARMA-IP> -p 2222` should show a login prompt.

An attacker on a **different** network or router cannot reach a private IP behind NAT;
use Demo step 6 instead of port-forwarding.

### Demo step 6 – Attacker on a different network (e.g. two phone hotspots)

Nothing is installed on either PC; the KARMA PC needs internet.

1. In the dashboard, open **Honeypot & Decoy Control** and press **Start Tunnel**.
2. KARMA's built-in client connects out to the free public [bore](https://github.com/ekzhang/bore)
   server `bore.pub` (TCP port 7835) and shows a public address for each decoy, such as
   `bore.pub:41234`. The addresses change on every start.
3. The attacker uses that host and port instead of `<KARMA-IP>` and the usual port:
   `ssh root@bore.pub -p 41234`, `curl http://bore.pub:<web-port>/`, `nmap -sT -sV -p 41234 bore.pub`.

Limits: every tunnelled attacker appears as `127.0.0.1`, so run one remote attacker at a time
and unblock `127.0.0.1` between runs. FTP downloads do not work through the tunnel; read
`deploy.env` over SSH with `cat` instead. The dashboard port is never tunnelled.

### Demo step 7 – Before going live (every rehearsal and the real demo)

Press **🗑️ Reset System** (top right of the dashboard). In one click it clears all telemetry,
unblocks every IP (including `127.0.0.1` from the tunnel) and switches the mode to **Contain**.

During the demo, open **Threats Overview → Adversary Forensic Profiler** and, for an attacker:

- **▶ Replay** plays back their whole session, command by command, with the MITRE technique and risk of each step.
- **📄 Report** opens a printable incident report (profile, location, techniques, recommended actions,
  full timeline). Use **Print / Save as PDF** to hand it in.

### Undo the demo setup

Run in an Administrator PowerShell:

```powershell
# Remove the karma-honeypot.com lines from the hosts file
$h = "$env:SystemRoot\System32\drivers\etc\hosts"
(Get-Content $h) | Where-Object { $_ -notmatch 'karma-honeypot\.com' } | Set-Content $h
ipconfig /flushdns

# Remove the firewall rule
Remove-NetFirewallRule -DisplayName 'KARMA Honeypot'

# Remove every KARMA Local Demo CA from the trusted store
Get-ChildItem Cert:\LocalMachine\Root | Where-Object Subject -eq 'CN=KARMA Local Demo CA' | Remove-Item

# Optional: delete the certificate files so KARMA goes back to http://localhost:8000
Remove-Item -Recurse "$env:USERPROFILE\.karma\tls"
```

### Troubleshooting

| Problem | Fix |
| --- | --- |
| `running scripts is disabled on this system` | Use the `-ExecutionPolicy Bypass` command from Demo step 2 |
| `Access to the path ... hosts is denied` / `Access is denied` | PowerShell is not running as Administrator (Demo step 1) |
| `Python not found` or the Microsoft Store opens | Reinstall Python from python.org with **Add python.exe to PATH**; turn off the `python.exe` entries in **Settings → Apps → Advanced app settings → App execution aliases** |
| `Could not load KARMA settings` | Run `python -m pip install -r requirements.txt` and run the script from the `KARMA-v1.2` folder |
| `karma-honeypot.com` does not open | Start the server first; run `ipconfig /flushdns`; check the hosts line with `Get-Content $env:SystemRoot\System32\drivers\etc\hosts` |
| Browser says *Not secure* | Restart the browser; use Edge/Chrome; re-run the setup script as the same Windows user that runs KARMA |
| Attackers cannot connect | Same hotspot? Correct IP? Re-run the setup script (fixes firewall Block rules); check the attacker IP is not blocked in **Attacker Profiles** |
| SSH says `Connection reset` | That attacker IP is quarantined; unblock it in **Attacker Profiles** |
| `Port ... is already used` | Close the other program (Remote Desktop for 3389) or untick that decoy |

**Attack script.** Replace `<KARMA-IP>` with the printed LAN IP. Run the rows top to bottom: everything
before the **Finale** only raises the threat score; the Finale quarantines that attacker.

The story: the attacker scouts the web portal, finds a leaked deploy file on the file server, and then
*uses* the stolen secrets. The secrets are honeytokens, so the moment they are used KARMA knows.

| Stage | Linux attacker | Windows attacker (PowerShell + Edge) |
| --- | --- | --- |
| Recon | `nmap -sT -sV -p 21,23,2222,3389,8080 <KARMA-IP>` | `Test-NetConnection <KARMA-IP> -Port 2222` (or Nmap) |
| Web recon | `curl http://<KARMA-IP>:8080/robots.txt` (lists the hidden admin and API paths), then `curl http://<KARMA-IP>:8080/` and read the `TODO(dev)` comment at the bottom | Open `http://<KARMA-IP>:8080` in Edge, press Ctrl+U to view source, read the `TODO(dev)` comment |
| Break-in | `ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@<KARMA-IP> -p 2222` (any password), then `ls`, `cd /srv/company`, `cat contacts.csv`, `exit` | Same in PowerShell `ssh`, with `UserKnownHostsFile=NUL`; then `cat /srv/company/operations/deploy.env` and `exit` |
| Loot the secrets | `ftp -p <KARMA-IP>`, user `Admin` (any password), `cd operations`, `get deploy.env`, `bye`, then `cat deploy.env` | (already read `deploy.env` over SSH above) |
| **Finale** | Use the stolen API key: `curl -H "X-API-Key: <API_KEY from deploy.env>" http://<KARMA-IP>:8080/api/v1/admin/db_export` | Log in with the stolen credentials: `ssh root@<KARMA-IP> -p 2222`, password from `STAGING_SSH` in deploy.env. KARMA rejects it and quarantines the PC |
| Proof of containment | Re-run any command: refused, shown as **BLOCKED** | Re-run the `ssh` or refresh the web page: refused, shown as **BLOCKED** |

Other finales that also quarantine (use one per attacker, or unblock between them):

- **SQL injection:** `curl "http://<KARMA-IP>:8080/?id=1+UNION+SELECT+password+FROM+users"`, or type `' OR 1=1 --` as the username on the portal's login form.
- **Hidden admin URL:** click **Backdoor Recovery Console (Legacy)** on the portal, or open `/secret-vault-admin-login-php`.
- **API trap without a key:** `curl http://<KARMA-IP>:8080/api/v1/auth/keys`.
- **Dangerous shell command:** `whoami` or `cat /etc/passwd` inside the SSH session.

In *Observe* mode none of these block, so you can rehearse the whole story; the Honeytoken Vault
tab still counts each use. Windows PowerShell's `curl` is an alias; use `curl.exe` for the commands above.

Use `nmap -sT` (connect scan): the default root SYN scan (`-sS`) never completes a TCP connection,
so no honeypot can see it. Keep `-sV` so Nmap sends an HTTP request; a bare connect to 8080 is not logged.
The visualizer labels each attacker's OS from its SSH client banner or
browser user agent (Nmap and curl don't reveal an OS).

The `-o StrictHostKeyChecking=no ...` options stop OpenSSH from refusing to connect if KARMA's SSH
host key changed (for example after deleting `%USERPROFILE%\.karma`).
Windows' built-in `ftp.exe` only supports active mode, so `ls`/`get` need the KARMA PC to connect back
through the attacker's firewall and usually fail with `425`; list and download files from the Linux attacker.

**Contain vs Observe.** In *Contain* mode scans, page views and logins are logged but never
blocked. Only high-risk actions (SQL injection, honeytokens, `whoami`/`cat /etc/...`) quarantine
the attacker. After that, every new attempt from that IP is refused and logged as **BLOCKED** (at most
one entry per port every 10 seconds). Use *Observe* to explore the fake shell freely.

**Offline network:** fonts, charts and the map library are bundled, so the dashboard looks the same without
internet. The maps use Esri satellite imagery (OpenStreetMap as fallback); with no internet they switch to
bundled country outlines and still show every attacker marker. Public-IP geolocation needs internet.
Don't press **Show** next to the DeepSeek key in the launcher while projecting.

## Network surfaces

| Port | Purpose |
| --- | --- |
| 8000 | Authenticated dashboard/API; localhost by default |
| 8080 | Public web decoy and honeytoken URL/API traps |
| 2222 | SSH simulation; commands are never executed by the OS |
| 21, 23, 3389 | FTP/Telnet/RDP decoys |

The previous public traps on port 8000 have moved to 8080. The misleading demo “production vault” login has been removed. Try `/secret-vault-admin-login-php` or `/api/v1/auth/keys` on the web sensor. Only enable sensors in networks you administer. Port conflicts are reported as ERROR in the dashboard rather than ACTIVE. Custom decoys create TCP listeners; toggles change actual listener state. API trap toggles depend on the web sensor being enabled.

Quarantine blocks new connections and subsequent interactions on KARMA sensors. By default it does **not** install OS firewall rules or isolate machines from other services. To also block quarantined IPs in **Windows Firewall** (or iptables on Linux), set `KARMA_FIREWALL_BLOCK=1` in `.env` and run KARMA as Administrator: each quarantine adds an inbound Block rule named **KARMA Quarantine**, Unblock and **Reset System** remove it, and `127.0.0.1` is never blocked so the tunnel can't cut the KARMA PC off from itself. Remove leftover rules with `netsh advfirewall firewall delete rule name="KARMA Quarantine"`. A triggering SSH login may now be rejected and later connections blocked; unblock the testing IP in the dashboard before repeating a demonstration. Desktop testing remains available from the launcher; the web API cannot launch desktop windows or attack simulations.

## AI SOC copilot

The **AI SOC Assistant** tab always has full context of the live telemetry — every attack,
attacker, MITRE technique and quarantine — and answers like a Tier-3 analyst. Ask things like:

- `tell me about 192.168.137.5` — full forensic profile of one attacker IP
- `top attackers`, `recent events`, `how many attacks`, `situation report`
- `explain T1110`, `show the MITRE breakdown`
- `ssh attacks`, `sql injection`, `honeytoken hits`, `what is quarantined`

With no `DEEPSEEK_API_KEY` set (the default), a built-in **offline analyst** answers these by
reading the live database directly — no data leaves the machine, and it needs no internet, so it
works in the exam hall. Set `DEEPSEEK_API_KEY` to also get free-form expert chat; the live
telemetry snapshot is then included in every request to DeepSeek (headers and the SIEM summary),
which is the only case where data leaves the PC.

## Production deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for TLS, service operation, backups, retention, upgrades, and operational limits. This repository includes hardening and regression tests; production readiness still requires validation on your actual host and traffic profile.

## Truthful analysis and privacy

- Event/attacker reports and MITRE mappings are deterministic heuristics, not external AI verdicts.
- Private LAN/loopback addresses use Bengaluru, India as an explicitly **configured lab location**, not a measured attacker origin. See `.env.example` to disable or change the lab marker.
- **Public** attacker IPs are located (city level) with the free [ip-api.com](https://ip-api.com) service when the event is logged: only the attacker's IP is sent, over plain HTTP (the free tier has no HTTPS). Results are cached for a day and stored with the event, and at most 40 lookups a minute are made (the free limit is 45). Without internet, or with `KARMA_GEOIP_ENABLED=0`, public IPs show as *Unknown*. IP geolocation is approximate: VPNs, proxies and cloud servers show the provider's location, not the person's.
- Without `DEEPSEEK_API_KEY`, chat/email analysis falls back locally. The email heuristic does not certify a message as legitimate.
- Configured email analysis sends headers and up to 2,500 characters of body text to DeepSeek. Chat sends the selected conversation history plus the live SIEM telemetry snapshot. This external send happens ONLY when DEEPSEEK_API_KEY is set; with no key the offline analyst reads the local database and nothing leaves the machine.
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

Download the decoy documents from another terminal:

```powershell
sftp -P 2222 root@192.168.137.1
# At the sftp prompt:
get /root/AEGIS_Financials.xlsm
get /root/AEGIS_Letterhead.docm
get /root/AEGIS_Project_Atlas_Pitch.pptm
bye
```

The dashboard records **Decoy file read started** when the first bytes are requested.
Every file in `backend/assets` is offered in `/root` and `/srv/company`; drop a file in to
offer it, remove it to withdraw it.

The AEGIS files are macro-enabled Office documents. If the reader clicks **Enable Content**,
the macro only runs locally on the reader's PC: it writes a greeting text file to `%TEMP%`
and opens it in Notepad, then opens a PowerShell window that runs `whoami`. It makes no
network connection, installs nothing and does not persist. Opening a document sends no
signal back to KARMA, so the download is the event the dashboard shows.

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
binary
get AEGIS_Financials.xlsm
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

See **Step 7** in Getting started. Runtime data and per-installation SSH keys are stored in `%USERPROFILE%\.karma`, outside the executable bundle.

## License

All rights reserved, Team K.A.R.M.A, 2025–2026.
