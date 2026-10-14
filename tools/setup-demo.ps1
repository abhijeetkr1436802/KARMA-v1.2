# One-time setup on the KARMA PC (Windows). Run in an *Administrator* PowerShell from the repo folder:
#   powershell -ExecutionPolicy Bypass -File tools\setup-demo.ps1
$ErrorActionPreference = 'Stop'
$Domain = if ($env:KARMA_DOMAIN) { $env:KARMA_DOMAIN } else { 'karma-honeypot.com' }
# Ask Python itself: (Get-Command python) can return the Microsoft Store alias stub, not the interpreter.
$Python = $null
foreach ($cmd in @('python', 'py')) {
    try { $Python = (& $cmd -c "import sys; print(sys.executable)") } catch { $Python = $null }
    if ($Python) { break }  # the Store alias stub prints nothing
}
if (-not $Python) { throw 'Python not found. Install Python 3.14 from python.org and tick "Add to PATH".' }
$Python = $Python.Trim()
$DataDir = if ($env:KARMA_DATA_DIR) { $env:KARMA_DATA_DIR } else { Join-Path $env:USERPROFILE '.karma' }

# 1. Domain -> this PC (dashboard stays loopback-only).
$Hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
if (-not (Select-String -Path $Hosts -Pattern "\s$([regex]::Escape($Domain))(\s|$)" -Quiet)) {
    Add-Content -Path $Hosts -Value "`r`n127.0.0.1 $Domain www.$Domain"
}
ipconfig /flushdns | Out-Null

# 2. HTTPS certificate signed by a local, single-use CA, trusted by Edge/Chrome/Firefox.
& $Python tools\make_cert.py
Import-Certificate -FilePath (Join-Path $DataDir 'tls\karma-local-ca.pem') -CertStoreLocation Cert:\LocalMachine\Root | Out-Null

# 3. Let the attacker PCs reach the decoys (all profiles, incl. hotspot 'Public' networks).
Get-NetFirewallRule -DisplayName 'KARMA Honeypot' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
# Pressing Cancel on Windows' firewall prompt leaves inbound Block rules for python.exe; Block beats Allow.
Get-NetFirewallApplicationFilter -Program $Python -ErrorAction SilentlyContinue | Get-NetFirewallRule |
    Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Block' } | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName 'KARMA Honeypot' -Direction Inbound -Program $Python -Action Allow -Profile Any | Out-Null

# 4. Warn about services already holding KARMA ports (e.g. Remote Desktop on 3389).
$busy = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object LocalPort -in 21,23,443,2222,3389,8080
foreach ($c in $busy) {
    $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
    Write-Warning "Port $($c.LocalPort) is already used by $($p.ProcessName) (PID $($c.OwningProcess))"
}

$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' }).IPAddress -join ', '
Write-Host "`nDone. Start KARMA with: python run.py   then open https://$Domain"
Write-Host "Attacker PCs target this PC's LAN address: $ip"
