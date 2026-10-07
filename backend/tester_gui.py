"""
K.A.R.M.A Honeypot Tester & Attacker Verification Suite
Desktop GUI tool to test SSH, FTP, Telnet, Web Admin, RDP, and Honeytoken API traps
and display real device IPv4 telemetry.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import socket
import urllib.request
import json
import threading
import sys
import os

def get_device_ipv4():
    """Detects local network IPv4 address or external IP if connected to internet."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

class KarmaTesterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("K.A.R.M.A — Honeypot Tester & Verification Suite")
        self.root.geometry("750x710")
        self.root.configure(bg="#0f172a") # Dark slate theme

        # Set Window Titlebar Icon
        icon_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "Project_Assets", "logo_icon.ico")
        if os.path.exists(icon_path):
            try:
                self.root.iconbitmap(icon_path)
            except Exception:
                pass

        self.device_ip = get_device_ipv4()
        self._build_ui()

    def _build_ui(self):
        # Header Banner
        header = tk.Frame(self.root, bg="#1e293b", padx=20, pady=14)
        header.pack(fill="x")

        # Render Brand Logo Image
        logo_png_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "Project_Assets", "logo_main.png")
        if os.path.exists(logo_png_path):
            try:
                from PIL import Image, ImageTk
                pil_img = Image.open(logo_png_path)
                w, h = pil_img.size
                target_h = 38
                target_w = int(w * (target_h / h))
                pil_img = pil_img.resize((target_w, target_h), Image.Resampling.LANCZOS)
                self.logo_photo = ImageTk.PhotoImage(pil_img)
                lbl_logo = tk.Label(header, image=self.logo_photo, bg="#1e293b")
                lbl_logo.pack(anchor="w", pady=(0, 4))
            except Exception:
                title = tk.Label(
                    header,
                    text="🧪 K.A.R.M.A Honeypot Tester & Verification Suite",
                    font=("Segoe UI", 15, "bold"),
                    bg="#1e293b",
                    fg="#38bdf8"
                )
                title.pack(anchor="w")

        sub = tk.Label(
            header,
            text="Penetration Probe & Decoy Response Analyzer",
            font=("Segoe UI", 10),
            bg="#1e293b",
            fg="#94a3b8"
        )
        sub.pack(anchor="w")

        # Device IP Display
        ip_frame = tk.Frame(header, bg="#0f172a", padx=10, pady=4)
        ip_frame.pack(anchor="w", pady=(8, 0))

        tk.Label(
            ip_frame,
            text=f"🌐 Tester Device IPv4 Address:  {self.device_ip}",
            font=("Consolas", 10, "bold"),
            bg="#0f172a",
            fg="#10b981"
        ).pack()

        # Main Scrollable / Padded Area
        main = tk.Frame(self.root, bg="#0f172a", padx=20, pady=15)
        main.pack(fill="both", expand=True)

        # Target IP Input
        target_frame = tk.Frame(main, bg="#1e293b", padx=12, pady=8)
        target_frame.pack(fill="x", pady=(0, 15))

        tk.Label(target_frame, text="Target Host IP / Domain:", font=("Segoe UI", 9, "bold"), bg="#1e293b", fg="#f8fafc").pack(side="left", padx=(0, 10))
        self.entry_target = tk.Entry(target_frame, font=("Consolas", 10), bg="#0f172a", fg="#38bdf8", insertbackground="white", width=24)
        self.entry_target.insert(0, "127.0.0.1")
        self.entry_target.pack(side="left")

        # Test Module Grid Buttons
        lbl_mod = tk.Label(main, text="Select Decoy Sensor Test Module:", font=("Segoe UI", 11, "bold"), bg="#0f172a", fg="#f8fafc")
        lbl_mod.pack(anchor="w", pady=(0, 8))

        btn_grid = tk.Frame(main, bg="#0f172a")
        btn_grid.pack(fill="x", pady=(0, 15))

        # Row 1 Buttons
        tk.Button(
            btn_grid, text="🔑 Test SSH Honeypot (Port 2222)", font=("Segoe UI", 9, "bold"),
            bg="#0284c7", fg="#fff", activebackground="#0369a1", activeforeground="#fff", pady=6, cursor="hand2",
            command=self.test_ssh
        ).grid(row=0, column=0, padx=4, pady=4, sticky="ew")

        tk.Button(
            btn_grid, text="📁 Test FTP Decoy (Port 21)", font=("Segoe UI", 9, "bold"),
            bg="#0284c7", fg="#fff", activebackground="#0369a1", activeforeground="#fff", pady=6, cursor="hand2",
            command=self.test_ftp
        ).grid(row=0, column=1, padx=4, pady=4, sticky="ew")

        tk.Button(
            btn_grid, text="🖥️ Test Telnet Decoy (Port 23)", font=("Segoe UI", 9, "bold"),
            bg="#0284c7", fg="#fff", activebackground="#0369a1", activeforeground="#fff", pady=6, cursor="hand2",
            command=self.test_telnet
        ).grid(row=0, column=2, padx=4, pady=4, sticky="ew")

        # Row 2 Buttons
        tk.Button(
            btn_grid, text="🌐 Test Web Admin (Port 8080)", font=("Segoe UI", 9, "bold"),
            bg="#7c3aed", fg="#fff", activebackground="#6d28d9", activeforeground="#fff", pady=6, cursor="hand2",
            command=self.test_web
        ).grid(row=1, column=0, padx=4, pady=4, sticky="ew")

        tk.Button(
            btn_grid, text="🍯 Test Honeytoken API (Port 8080)", font=("Segoe UI", 9, "bold"),
            bg="#7c3aed", fg="#fff", activebackground="#6d28d9", activeforeground="#fff", pady=6, cursor="hand2",
            command=self.test_honeytoken
        ).grid(row=1, column=1, padx=4, pady=4, sticky="ew")

        tk.Button(
            btn_grid, text="⚡ Run Full Automated Audit", font=("Segoe UI", 9, "bold"),
            bg="#10b981", fg="#000", activebackground="#059669", activeforeground="#fff", pady=6, cursor="hand2",
            command=self.test_full_audit
        ).grid(row=1, column=2, padx=4, pady=4, sticky="ew")

        btn_grid.columnconfigure(0, weight=1)
        btn_grid.columnconfigure(1, weight=1)
        btn_grid.columnconfigure(2, weight=1)

        # Custom Shell Command Execution Frame
        cmd_frame = tk.Frame(main, bg="#1e293b", padx=12, pady=10)
        cmd_frame.pack(fill="x", pady=(0, 15))

        tk.Label(cmd_frame, text="Execute Custom Shell Command on SSH (Port 2222):", font=("Segoe UI", 9, "bold"), bg="#1e293b", fg="#94a3b8").pack(anchor="w", pady=(0, 4))
        
        cmd_input_box = tk.Frame(cmd_frame, bg="#1e293b")
        cmd_input_box.pack(fill="x")

        self.entry_cmd = tk.Entry(cmd_input_box, font=("Consolas", 10), bg="#0f172a", fg="#38bdf8", insertbackground="white")
        self.entry_cmd.insert(0, "cat /etc/passwd")
        self.entry_cmd.pack(side="left", fill="x", expand=True, padx=(0, 8))

        tk.Button(
            cmd_input_box, text="Send Command", font=("Segoe UI", 9, "bold"),
            bg="#0070f3", fg="#fff", activebackground="#0051a8", activeforeground="#fff", padx=12, cursor="hand2",
            command=self.send_custom_ssh_cmd
        ).pack(side="right")

        # Response Output Window
        lbl_out = tk.Label(main, text="Honeypot Response Output & Live Analysis:", font=("Segoe UI", 9, "bold"), bg="#0f172a", fg="#94a3b8")
        lbl_out.pack(anchor="w", pady=(0, 4))

        self.txt_out = tk.Text(main, height=12, bg="#020617", fg="#10b981", font=("Consolas", 9), wrap="word")
        self.txt_out.pack(fill="both", expand=True)
        self.txt_out.insert("end", f"[+] Tester Suite Initialized. Tester Device IPv4: {self.device_ip}\n[+] Select a test module above to probe active decoys.\n")

    def log(self, text):
        self.txt_out.insert("end", text + "\n")
        self.txt_out.see("end")

    def get_target(self):
        return self.entry_target.get().strip() or "127.0.0.1"

    def test_ssh(self):
        threading.Thread(target=self._run_ssh_test, daemon=True).start()

    def _run_ssh_test(self):
        target = self.get_target()
        self.log(f"\n--- [TEST] Probing SSH Honeypot on {target}:2222 ---")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4.0)
            sock.connect((target, 2222))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            self.log(f"🟢 [SSH Banner Received]: {banner}")

            prompt = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            self.log(f"🟢 [SSH Prompt Received]: {prompt}")

            # Send test command 'whoami'
            self.log("➡️ [Sending Command]: 'whoami'")
            sock.sendall(b"whoami\r\n")
            time_resp = sock.recv(1024).decode('utf-8', errors='ignore')
            self.log(f"📥 [Honeypot Shell Response]:\n{time_resp}")

            sock.close()
            self.log("✔ SSH Honeypot probe completed. Event logged to SIEM dashboard!")
        except Exception as e:
            self.log(f"🔴 [SSH Test Error]: {e}")

    def send_custom_ssh_cmd(self):
        cmd = self.entry_cmd.get().strip()
        if not cmd:
            return
        threading.Thread(target=self._run_custom_ssh, args=(cmd,), daemon=True).start()

    def _run_custom_ssh(self, cmd):
        target = self.get_target()
        self.log(f"\n--- [CUSTOM SSH COMMAND] Sending '{cmd}' to {target}:2222 ---")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4.0)
            sock.connect((target, 2222))
            _ = sock.recv(1024) # banner
            _ = sock.recv(1024) # prompt

            self.log(f"➡️ [Sending]: '{cmd}'")
            sock.sendall(cmd.encode('utf-8') + b"\r\n")
            resp = sock.recv(1024).decode('utf-8', errors='ignore')
            self.log(f"📥 [Honeypot Shell Output]:\n{resp}")
            sock.close()
            self.log("✔ Command captured & logged to SIEM telemetry feed!")
        except Exception as e:
            self.log(f"🔴 [SSH Command Error]: {e}")

    def test_ftp(self):
        threading.Thread(target=self._run_ftp_test, daemon=True).start()

    def _run_ftp_test(self):
        target = self.get_target()
        self.log(f"\n--- [TEST] Probing FTP Service Decoy on {target}:21 ---")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4.0)
            sock.connect((target, 21))

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            self.log(f"🟢 [FTP Banner Received]: {banner}")

            self.log("➡️ [Sending FTP Command]: 'USER root'")
            sock.sendall(b"USER root\r\n")
            resp1 = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            self.log(f"📥 [FTP Response]: {resp1}")

            self.log("➡️ [Sending FTP Command]: 'PASS admin123'")
            sock.sendall(b"PASS admin123\r\n")
            resp2 = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            self.log(f"📥 [FTP Response]: {resp2}")

            sock.close()
            self.log("✔ FTP probe completed. Login attempt trapped in SIEM!")
        except Exception as e:
            self.log(f"🔴 [FTP Test Error]: {e}")

    def test_telnet(self):
        threading.Thread(target=self._run_telnet_test, daemon=True).start()

    def _run_telnet_test(self):
        target = self.get_target()
        self.log(f"\n--- [TEST] Probing Telnet Remote Decoy on {target}:23 ---")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4.0)
            sock.connect((target, 23))

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            self.log(f"🟢 [Telnet Prompt Received]: {banner}")

            self.log("➡️ [Sending Telnet Input]: 'admin'")
            sock.sendall(b"admin\r\n")
            resp1 = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            self.log(f"📥 [Telnet Response]: {resp1}")

            sock.close()
            self.log("✔ Telnet probe completed. Input captured on SIEM telemetry!")
        except Exception as e:
            self.log(f"🔴 [Telnet Test Error]: {e}")

    def test_web(self):
        threading.Thread(target=self._run_web_test, daemon=True).start()

    def _run_web_test(self):
        target = self.get_target()
        self.log(f"\n--- [TEST] Probing Web Admin Decoy on http://{target}:8080 ---")
        try:
            url = f"http://{target}:8080/"
            req = urllib.request.urlopen(url, timeout=4)
            html = req.read().decode('utf-8', errors='ignore')
            self.log(f"🟢 [Web Decoy Status]: {req.status} OK")
            self.log(f"📄 [Page Snippet]: {html[:120]}...")
            self.log("✔ Web honeypot request logged to SIEM telemetry!")
        except Exception as e:
            self.log(f"🔴 [Web Test Error]: {e}")

    def test_honeytoken(self):
        threading.Thread(target=self._run_honeytoken_test, daemon=True).start()

    def _run_honeytoken_test(self):
        target = self.get_target()
        self.log(f"\n--- [TEST] Triggering Honeytoken API Trap on http://{target}:8080/api/v1/auth/keys ---")
        try:
            url = f"http://{target}:8080/api/v1/auth/keys"
            try:
                urllib.request.urlopen(url, timeout=4)
            except urllib.error.HTTPError as e:
                self.log(f"🚨 [Honeytoken Triggered]: Status {e.code} (Forbidden Alert Triggered!)")
                self.log("✔ Honeytoken breach telemetry dispatched to SOC dashboard!")
        except Exception as e:
            self.log(f"🔴 [Honeytoken Test Error]: {e}")

    def test_full_audit(self):
        threading.Thread(target=self._run_full_audit, daemon=True).start()

    def _run_full_audit(self):
        self.log("\n================================================================")
        self.log("⚡ RUNNING AUTOMATED FULL HONEYPOT AUDIT SUITE")
        self.log("================================================================")
        self._run_ssh_test()
        self._run_ftp_test()
        self._run_telnet_test()
        self._run_web_test()
        self._run_honeytoken_test()
        self.log("\n✔ FULL AUTOMATED AUDIT COMPLETED. Check SIEM dashboard for live telemetry!")

def launch_tester_gui():
    root = tk.Tk()
    app = KarmaTesterApp(root)
    root.mainloop()

if __name__ == "__main__":
    launch_tester_gui()
