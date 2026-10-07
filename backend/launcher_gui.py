"""
K.A.R.M.A Cloud SIEM — Desktop Decoy Control Panel
Desktop Control Panel allowing administrators to configure active honeypots, open decoy ports,
and deception banners before launching the backend server and web dashboard.
"""

import tkinter as tk
from tkinter import messagebox
import threading
import sys
import os
import uvicorn

# Ensure parent directory is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.config import HOST, PORT_API
from backend.decoy_state import DECOYS, toggle_decoy, initialize_decoys
from backend.database import init_db

class KarmaPreflightLauncher:
    def __init__(self, root):
        self.root = root
        self.root.title("K.A.R.M.A Cloud SIEM — Desktop Control Panel")
        self.root.geometry("700x710")
        self.root.configure(bg="#0f172a") # Dark Slate Theme matching SIEM UI

        # Set Window Titlebar Icon
        icon_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "Project_Assets", "logo_icon.ico")
        if os.path.exists(icon_path):
            try:
                self.root.iconbitmap(icon_path)
            except Exception:
                pass

        self.vars = {}
        self.check_widgets = []
        self.server_running = False
        self.uvicorn_server = None

        init_db()
        initialize_decoys()
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.close)

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
                target_h = 42
                target_w = int(w * (target_h / h))
                pil_img = pil_img.resize((target_w, target_h), Image.Resampling.LANCZOS)
                self.logo_photo = ImageTk.PhotoImage(pil_img)
                lbl_logo = tk.Label(header, image=self.logo_photo, bg="#1e293b")
                lbl_logo.pack(anchor="w", pady=(0, 4))
            except Exception:
                title = tk.Label(
                    header, 
                    text="🛡️ K.A.R.M.A CLOUD SIEM", 
                    font=("Segoe UI", 16, "bold"), 
                    bg="#1e293b", 
                    fg="#38bdf8"
                )
                title.pack(anchor="w")

        subtitle = tk.Label(
            header, 
            text="Cybersecurity Active Defense & Decoy Listener Configuration", 
            font=("Segoe UI", 10), 
            bg="#1e293b", 
            fg="#94a3b8"
        )
        subtitle.pack(anchor="w", pady=(2, 0))

        team_info = tk.Label(
            header,
            text="Created by Kanaka C, Abhijeet Kumar, Raghunandan T V & Sanjay Kashyap • Sem VI Major Project | Guide: Mr. Subhash J R",
            font=("Segoe UI", 9, "italic"),
            bg="#1e293b",
            fg="#10b981"
        )
        team_info.pack(anchor="w", pady=(4, 0))

        # Main Container
        main_frame = tk.Frame(self.root, bg="#0f172a", padx=20, pady=15)
        main_frame.pack(fill="both", expand=True)

        # Section 1: Decoy Listeners Selection
        lbl_decoys = tk.Label(
            main_frame, 
            text="1. Select Decoy Ports & Traps to Bind at Server Launch:", 
            font=("Segoe UI", 11, "bold"), 
            bg="#0f172a", 
            fg="#f8fafc"
        )
        lbl_decoys.pack(anchor="w", pady=(0, 8))

        decoy_grid = tk.Frame(main_frame, bg="#1e293b", padx=12, pady=10)
        decoy_grid.pack(fill="x", pady=(0, 15))

        # Decoy Items List
        decoy_items = [
            ("ssh_2222", "SSH Honeypot Server (Port 2222)", "Traps SSH brute-force & interactive bash commands"),
            ("web_8080", "Corporate Admin Portal Decoy (Port 8080)", "Traps web admin authentication & SQLi attacks"),
            ("port_21", "FTP Service Decoy (Port 21)", "Traps interactive FTP logins & command probes"),
            ("port_23", "Telnet Remote Decoy (Port 23)", "Traps interactive Telnet logins & command probes"),
            ("port_3389", "RDP Remote Desktop Decoy (Port 3389)", "Listens for Remote Desktop Connection probes"),
            ("api_auth_keys", "Honeytoken API Traps (Port 8000)", "Fake REST endpoints `/api/v1/auth/keys` & `db_export`"),
        ]

        row = 0
        for item_id, item_name, desc in decoy_items:
            var = tk.BooleanVar(value=DECOYS.get(item_id, {}).get("enabled", True))
            self.vars[item_id] = var

            chk = tk.Checkbutton(
                decoy_grid,
                text=f"{item_name}  —  {desc}",
                variable=var,
                font=("Segoe UI", 9, "bold"),
                bg="#1e293b",
                fg="#38bdf8",
                selectcolor="#0f172a",
                activebackground="#1e293b",
                activeforeground="#10b981"
            )
            chk.grid(row=row, column=0, sticky="w", pady=4)
            self.check_widgets.append(chk)
            row += 1

        # Section 2: Custom Banners
        lbl_banners = tk.Label(
            main_frame,
            text="2. Deception Banners & Response Customization:",
            font=("Segoe UI", 11, "bold"),
            bg="#0f172a",
            fg="#f8fafc"
        )
        lbl_banners.pack(anchor="w", pady=(5, 6))

        banner_frame = tk.Frame(main_frame, bg="#1e293b", padx=12, pady=10)
        banner_frame.pack(fill="x", pady=(0, 15))

        tk.Label(banner_frame, text="SSH Service Banner (Port 2222):", font=("Segoe UI", 9, "bold"), bg="#1e293b", fg="#94a3b8").grid(row=0, column=0, sticky="w")
        self.entry_ssh_banner = tk.Entry(banner_frame, font=("Consolas", 9), bg="#0f172a", fg="#38bdf8", insertbackground="white", width=42)
        self.entry_ssh_banner.insert(0, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
        self.entry_ssh_banner.grid(row=0, column=1, padx=10, pady=4)

        tk.Label(banner_frame, text="FTP Server Banner (Port 21):", font=("Segoe UI", 9, "bold"), bg="#1e293b", fg="#94a3b8").grid(row=1, column=0, sticky="w")
        self.entry_ftp_banner = tk.Entry(banner_frame, font=("Consolas", 9), bg="#0f172a", fg="#38bdf8", insertbackground="white", width=42)
        self.entry_ftp_banner.insert(0, "220 ProFTPD 1.3.5 Server Ready.")
        self.entry_ftp_banner.grid(row=1, column=1, padx=10, pady=4)

        # Button Container (Launch Server + Tester Button)
        btn_box = tk.Frame(main_frame, bg="#0f172a")
        btn_box.pack(fill="x", pady=(0, 10))

        self.btn_start = tk.Button(
            btn_box,
            text="🚀 LAUNCH K.A.R.M.A SIEM SERVER",
            font=("Segoe UI", 11, "bold"),
            bg="#0070f3",
            fg="#ffffff",
            activebackground="#0051a8",
            activeforeground="#ffffff",
            pady=8,
            relief="flat",
            cursor="hand2",
            command=self.toggle_server_state
        )
        self.btn_start.pack(side="left", fill="x", expand=True, padx=(0, 6), ipady=4)

        self.btn_tester = tk.Button(
            btn_box,
            text="🧪 Tester / Attacker",
            font=("Segoe UI", 11, "bold"),
            bg="#7c3aed",
            fg="#ffffff",
            activebackground="#6d28d9",
            activeforeground="#ffffff",
            pady=8,
            relief="flat",
            cursor="hand2",
            command=self.open_tester_gui
        )
        self.btn_tester.pack(side="right", padx=(6, 0), ipady=4)

        # Log Output Text
        lbl_logs = tk.Label(main_frame, text="Live Server Startup Console Output:", font=("Segoe UI", 9, "bold"), bg="#0f172a", fg="#94a3b8")
        lbl_logs.pack(anchor="w", pady=(4, 2))

        self.txt_log = tk.Text(main_frame, height=7, bg="#020617", fg="#10b981", font=("Consolas", 9), wrap="word")
        self.txt_log.pack(fill="both", expand=True)
        self.txt_log.insert("end", "[+] Desktop Control Panel Ready. Select enabled decoys and click 'LAUNCH K.A.R.M.A SIEM SERVER'.\n")

    def open_tester_gui(self):
        from backend.tester_gui import launch_tester_gui
        threading.Thread(target=launch_tester_gui, daemon=True).start()
        self.log("[+] Tester/Attacker Verification Suite window opened.")

    def close(self):
        if self.uvicorn_server:
            self.uvicorn_server.should_exit = True
        self.root.after(500, self._finish_close)

    def _finish_close(self):
        if hasattr(self, "server_thread") and self.server_thread.is_alive():
            self.root.after(500, self._finish_close)
        else:
            self.root.destroy()

    def log(self, text):
        if threading.current_thread() is not threading.main_thread():
            self.root.after(0, self.log, text)
            return
        self.txt_log.insert("end", text + "\n")
        self.txt_log.see("end")

    def toggle_server_state(self):
        if not self.server_running:
            self.start_server()
        else:
            self.stop_server()

    def start_server(self):
        if hasattr(self, "server_thread") and self.server_thread.is_alive():
            self.log("[!] Previous server is still shutting down; please wait.")
            return
        # Apply Checkbox States to Global DECOYS State
        for item_id, var in self.vars.items():
            is_enabled = var.get()
            toggle_decoy(item_id, is_enabled)
            status_str = "ENABLED (binding pending)" if is_enabled else "DISABLED"
            self.log(f"[+] Decoy '{item_id}': {status_str}")

        # Disable checkboxes while running
        for chk in self.check_widgets:
            chk.config(state="disabled")

        self.btn_start.config(
            text="🛑 STOP K.A.R.M.A SIEM SERVER",
            bg="#ef4444",
            activebackground="#dc2626"
        )
        self.server_running = True

        self.log("================================================================")
        self.log(f"[+] Starting Dashboard & API Server on http://localhost:{PORT_API}")
        self.log("================================================================")

        # Launch Uvicorn in Background Thread
        self.server_thread = threading.Thread(target=self._run_uvicorn, daemon=True)
        self.server_thread.start()

    def _run_uvicorn(self):
        try:
            config = uvicorn.Config("backend.app:app", host=HOST, port=PORT_API, reload=False, log_level="info", proxy_headers=False, limit_concurrency=128, timeout_graceful_shutdown=15)
            self.uvicorn_server = uvicorn.Server(config)
            self.uvicorn_server.run()
        except (Exception, SystemExit) as e:
            self.log(f"[!] Server Error: {e}")
        finally:
            self.root.after(0, self.stop_server)

    def stop_server(self):
        if self.uvicorn_server:
            self.uvicorn_server.should_exit = True

        self.server_running = False

        # Re-enable checkboxes
        for chk in self.check_widgets:
            chk.config(state="normal")

        self.btn_start.config(
            text="🚀 LAUNCH K.A.R.M.A SIEM SERVER",
            bg="#0070f3",
            activebackground="#0051a8"
        )

        self.log("================================================================")
        self.log("[+] K.A.R.M.A SIEM Server shutdown requested.")
        self.log("[+] You may modify decoy settings above and click LAUNCH again.")
        self.log("================================================================")

def launch_gui():
    root = tk.Tk()
    app = KarmaPreflightLauncher(root)
    root.mainloop()

if __name__ == "__main__":
    launch_gui()
