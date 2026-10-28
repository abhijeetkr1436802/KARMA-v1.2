"""
K.A.R.M.A Cloud SIEM & Threat Deception Platform - Automated Build & Packaging Script
Usage:
    python setup.py

This script compiles K.A.R.M.A into a standalone executable package (dist/KARMA_Cloud_SIEM/)
that can be copied and run on ANY Windows PC without requiring Python, Git, or pip installation!
"""

import os
import sys
import subprocess
import shutil
import zipfile

def install_pyinstaller():
    try:
        import PyInstaller
        print("[+] PyInstaller is already installed.")
    except ImportError:
        print("[!] PyInstaller not found. Installing PyInstaller via pip...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

def build_standalone_app():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dist_dir = os.path.join(base_dir, "dist")
    build_dir = os.path.join(base_dir, "build")
    output_app_dir = os.path.join(dist_dir, "KARMA_Cloud_SIEM")
    
    icon_path = os.path.join(base_dir, "frontend", "Project_Assets", "logo_icon.ico")
    
    print("\n==================================================================")
    print("   K.A.R.M.A: AUTONOMOUS AI THREAT DECEPTION PLATFORM BUILDER    ")
    print("==================================================================\n")

    # Install PyInstaller if missing
    install_pyinstaller()

        # PyInstaller arguments
    # Bundles frontend, backend, config, and assets into standalone package
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--name=KARMA_Cloud_SIEM",
        "--onedir",
        # Bundle data directories (frontend assets & backend package)
        f"--add-data=frontend{os.pathsep}frontend",
        f"--add-data=backend/assets{os.pathsep}backend/assets",
        "--collect-submodules=backend",
        # Force-collect all submodules & data for third-party deps that PyInstaller
        # cannot statically trace (e.g. fastapi.middleware, uvicorn/lupa workers,
        # paramiko transport, websockets protocols, pydantic types)
        "--collect-submodules=fastapi",
        "--collect-submodules=uvicorn",
        "--collect-submodules=paramiko",
        "--collect-submodules=websockets",
        "--collect-submodules=pydantic",
        "--collect-all=fastapi",
        "--collect-all=uvicorn",
        "--collect-all=paramiko",
        "--collect-all=websockets",
        "--collect-all=pydantic",
        "--hidden-import=backend",
        "--hidden-import=backend.config",
        "--hidden-import=backend.database",
        "--hidden-import=backend.app",
        "--hidden-import=backend.honeytokens",
        "--hidden-import=backend.decoy_state",
        "--hidden-import=backend.launcher_gui",
        "--hidden-import=backend.tester_gui",
        "--hidden-import=backend.engine",
        "--hidden-import=backend.engine.active_defense",
        "--hidden-import=backend.engine.ai_analyst",
        "--hidden-import=backend.engine.csv_logger",
        "--hidden-import=backend.engine.ai_chat",
        "--hidden-import=backend.engine.mitre_mapper",
        "--hidden-import=backend.engine.phishing_analyzer",
        "--hidden-import=backend.engine.threat_score",
        "--hidden-import=backend.sensors",
        "--hidden-import=backend.sensors.raw_decoy",
        "--hidden-import=backend.sensors.ssh_honeypot",
        "--hidden-import=backend.sensors.web_honeypot",
        # Ensure Python's built-in _socket & selectors are bundled for socket sensors
        "--hidden-import=_socket",
        "--hidden-import=selectors",
    ]

    if os.path.exists(icon_path):
        cmd.append(f"--icon={icon_path}")

    cmd.append("run.py")

    print("[+] Executing PyInstaller compilation...")
    print(f"    Command: {' '.join(cmd)}\n")
    
    result = subprocess.run(cmd, cwd=base_dir)
    
    if result.returncode != 0:
        print("\n[❌ ERROR] Build failed! Check PyInstaller output above.")
        sys.exit(1)

    print("\n[+] PyInstaller compilation finished successfully!")

    # Ensure frontend assets are directly accessible in output folder
    dist_karma_dir = os.path.join(dist_dir, "KARMA_Cloud_SIEM")
    dist_frontend = os.path.join(dist_karma_dir, "frontend")
    
    if not os.path.exists(dist_frontend):
        print("[+] Copying frontend asset directory to dist bundle...")
        shutil.copytree(os.path.join(base_dir, "frontend"), dist_frontend)

    # Ensure logs folder exists in dist bundle
    dist_logs = os.path.join(dist_karma_dir, "logs")
    if not os.path.exists(dist_logs):
        os.makedirs(dist_logs)

    # Create Distribution Info Readme
    dist_readme = os.path.join(dist_karma_dir, "HOW_TO_RUN.txt")
    with open(dist_readme, "w", encoding="utf-8") as f:
        f.write(r"""==================================================================
   K.A.R.M.A: AUTONOMOUS AI THREAT DECEPTION PLATFORM (v1.2)
   Cyber Security & Engineering • Semester VI Diploma Major Project
   The Oxford Evening Polytechnic
==================================================================

HOW TO RUN ON ANY WINDOWS PC (NO PYTHON / PIP INSTALLATION REQUIRED):

1. Double-click 'KARMA_Cloud_SIEM.exe' to open the Control Panel.
   (Windows SmartScreen: click 'More info' -> 'Run anyway'; the exe is not code-signed.)
2. Tick the decoys you want and click '🚀 LAUNCH K.A.R.M.A SIEM SERVER'.
3. Open a browser on this PC at http://localhost:8000
   (or https://karma-honeypot.com if you ran tools\setup-demo.ps1).
4. Log in with the admin token stored in:
       %USERPROFILE%\.karma\admin-token
   Show it in PowerShell:  Get-Content $env:USERPROFILE\.karma\admin-token
5. Optional: click '🧪 Tester / Attacker' to fire sample attacks at the decoys.
6. To stop, click '🛑 STOP K.A.R.M.A SIEM SERVER'.

Optional AI Copilot: paste a DeepSeek API key in the Control Panel and click 'Save Key'.

DEVELOPER TEAM:
- Abhijeet Kumar (Team Lead & Core Architect)
- Kanaka C (Security Analyst & Frontend Engineer)
- Raghunandan T V (Backend Engineer & Threat Intelligence)
- Sanjay Kashyap (Security QA & Penetration Testing)

PROJECT GUIDE:
- Mr. Subhash J R (Lecturer, Dept of CSE)
==================================================================
""")

    # Zip the final bundle for easy distribution
    zip_path = os.path.join(dist_dir, "KARMA_Cloud_SIEM_Standalone_v1.2.zip")
    print(f"[+] Creating redistributable ZIP archive: {zip_path}...")
    
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(dist_karma_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, dist_dir)
                zipf.write(full_path, rel_path)

    print("\n==================================================================")
    print(" [OK] BUILD COMPLETE & REDISTRIBUTABLE PACKAGE CREATED!")
    print("==================================================================")
    print(f" Executable Folder : {dist_karma_dir}")
    print(f" ZIP Package File  : {zip_path}")
    print("==================================================================")
    print(" You can copy 'KARMA_Cloud_SIEM_Standalone_v1.2.zip' or the folder")
    print(" to any Windows PC and double-click 'KARMA_Cloud_SIEM.exe' to run!\n")

if __name__ == "__main__":
    build_standalone_app()
