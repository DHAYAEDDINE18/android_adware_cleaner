import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import subprocess, threading, json, os, re

# Google Gen AI SDK (pip install google-genai)
from google import genai
from google.genai import types

# ---------- Configuration ----------
DEFAULT_MODEL = "gemini-2.5-flash"
ONLY_USER_APPS = True  # list only non-system apps by default
WHITELIST_PREFIXES = {"com.android", "com.google.android", "com.qualcomm", "com.samsung", "com.huawei", "com.miui"}
WHITELIST_PACKAGES = {"com.google.android.gms", "com.android.chrome", "com.android.settings"}

# ---------- ADB helpers ----------
def run(cmd, timeout=30):
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = p.communicate(timeout=timeout)
        return p.returncode, out, err
    except subprocess.TimeoutExpired:
        p.kill()
        return 124, "", "Timeout"

def adb(args, device=None, timeout=30):
    base = ["adb"]
    if device:
        base += ["-s", device]
    return run(base + args, timeout=timeout)

def check_adb_version():
    code, out, err = run(["adb", "--version"])
    return code == 0, (out or err)

def parse_packages(list_output):
    pkgs = []
    for line in list_output.splitlines():
        m = re.search(r"package:(?:[^=]*=)?([a-zA-Z0-9._]+)", line)
        if m:
            pkgs.append(m.group(1))
    return sorted(set(pkgs))

def list_installed(device, user_only=True):
    args = ["shell", "pm", "list", "packages"]
    if user_only:
        args.append("-3")
    code, out, err = adb(args, device=device)
    if code != 0:
        raise RuntimeError(err or "Failed to list packages")
    return parse_packages(out)

def get_recent_packages(device):
    pkgs = set()
    # Strategy 1: recents list
    code, out, err = adb(["shell", "dumpsys", "activity", "recents"], device=device, timeout=20)
    for line in (out or "").splitlines():
        for m in re.finditer(r"\b([a-zA-Z0-9_]+\.[a-zA-Z0-9._]+)\b", line):
            token = m.group(1)
            if "." in token and len(token) > 5:
                pkgs.add(token)
    # Strategy 2: top activities (ACTIVITY ...)
    code2, out2, err2 = adb(["shell", "dumpsys", "activity", "top"], device=device, timeout=15)
    if out2:
        for line in out2.splitlines():
            m = re.search(r"ACTIVITY\s+([a-zA-Z0-9._]+)\/", line)
            if m:
                pkgs.add(m.group(1))
    # Strategy 3: current focus (works on many Android versions)
    code3, out3, err3 = adb(["shell", "dumpsys", "activity"], device=device, timeout=20)
    if out3:
        m = re.search(r"mCurrentFocus=\S+\s+\S+\s+([a-zA-Z0-9._]+)\/", out3)
        if m:
            pkgs.add(m.group(1))
    return sorted(pkgs)

def is_whitelisted(pkg, user_whitelist=None):
    if user_whitelist and pkg in user_whitelist:
        return True
    if pkg in WHITELIST_PACKAGES:
        return True
    return any(pkg.startswith(p) for p in WHITELIST_PREFIXES)

def uninstall_user0(device, pkg):
    code, out, err = adb(["shell", "pm", "uninstall", "--user", "0", pkg], device=device)
    return (code == 0) or ("Success" in (out or ""))

# ---------- Gemini (google-genai) ----------
def make_client(api_key: str | None):
    if api_key:
        return genai.Client(api_key=api_key)
    return genai.Client()

def list_models(client: genai.Client):
    try:
        models = client.models.list()
        names = []
        for m in models:
            names.append(getattr(m, "name", str(m)))
        return names
    except Exception as e:
        raise RuntimeError(f"List models failed: {e}")

def gemini_pick_suspects(client: genai.Client, model_name: str, installed, recent):
    payload = {
        "instructions": (
            "Given 'installed' and 'recent' Android package lists, return ONLY a JSON array "
            "with package names most likely responsible for intrusive ad overlays/pop-ups. "
            "Only include names present in the inputs and avoid system packages."
        ),
        "installed": installed[:500],
        "recent": recent[:50],
    }
    text = json.dumps(payload)
    resp = client.models.generate_content(
        model=model_name,
        contents=text,
        config=types.GenerateContentConfig(temperature=0.1, max_output_tokens=256),
    )
    output = getattr(resp, "text", "") or ""
    m = re.search(r"\[[^\]]*\]", output, re.S)
    if not m:
        return []
    try:
        arr = json.loads(m.group(0))
        return [p for p in arr if isinstance(p, str)]
    except Exception:
        return []

# ---------- GUI ----------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Android Adware Cleaner (ADB + Google GenAI)")
        self.geometry("1120x740")
        self.minsize(980, 640)

        # State
        self.device = None
        self.installed = []
        self.recent = []
        self.suspects = []

        # UI Vars
        self.api_key_var = tk.StringVar(value=os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or "")
        self.model_var = tk.StringVar(value=DEFAULT_MODEL)
        self.dry_run_var = tk.BooleanVar(value=True)
        self.filter_var = tk.StringVar(value="")
        self.auto_refresh_var = tk.BooleanVar(value=False)
        self.refresh_time_var = tk.StringVar(value="5")
        self.add_to_db_var = tk.BooleanVar(value=False)
        self._refresh_job = None
        self.known_adware = set()
        self.user_whitelist = set()
        self.theme_var = tk.StringVar(value="White")

        self.load_known_adware()
        self.load_user_whitelist()

        # Theme setup
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        self._style = style
        self.apply_theme("White")  # default

        self.create_widgets()
        # Global key binding: press K to full scan (AI)
        self.bind_all("<Key-k>", lambda e: self.on_scan_click())
        self.after(200, self.preflight_adb)

    # ---------- Theme ----------
    THEMES = {
        "Dark": {
            "bg":        "#2d2d2d",
            "fg":        "#e0e0e0",
            "field_bg":  "#333333",
            "sel_bg":    "#005599",
            "tab_sel":   "#2d2d2d",
            "log_bg":    "#2b2b2b",
            "log_fg":    "#e0e0e0",
        },
        "White": {
            "bg":        "#f5f5f5",
            "fg":        "#1a1a1a",
            "field_bg":  "#ffffff",
            "sel_bg":    "#4a90d9",
            "tab_sel":   "#f5f5f5",
            "log_bg":    "#ffffff",
            "log_fg":    "#1a1a1a",
        },
        "Black": {
            "bg":        "#000000",
            "fg":        "#cccccc",
            "field_bg":  "#111111",
            "sel_bg":    "#004488",
            "tab_sel":   "#000000",
            "log_bg":    "#0a0a0a",
            "log_fg":    "#cccccc",
        },
    }

    def apply_theme(self, name):
        t = self.THEMES.get(name, self.THEMES["Dark"])
        self.configure(bg=t["bg"])
        s = self._style
        s.configure(".",
            background=t["bg"], foreground=t["fg"],
            fieldbackground=t["field_bg"], insertcolor=t["fg"])
        s.configure("Treeview",
            background=t["field_bg"], foreground=t["fg"],
            fieldbackground=t["field_bg"])
        s.map("Treeview", background=[("selected", t["sel_bg"])])
        s.configure("TButton", background=t["field_bg"], foreground=t["fg"])
        s.configure("TLabelFrame", background=t["bg"], foreground=t["fg"])
        s.configure("TNotebook", background=t["bg"])
        s.configure("TNotebook.Tab", background=t["field_bg"], foreground=t["fg"])
        s.map("TNotebook.Tab", background=[("selected", t["tab_sel"])])
        s.configure("TFrame", background=t["bg"])
        s.configure("TLabel", background=t["bg"], foreground=t["fg"])
        s.configure("TCheckbutton", background=t["bg"], foreground=t["fg"])
        s.configure("TCombobox",
            fieldbackground=t["field_bg"], foreground=t["fg"],
            background=t["field_bg"])
        # Update log widget if it already exists
        if hasattr(self, "log"):
            self.log.configure(bg=t["log_bg"], fg=t["log_fg"],
                               insertbackground=t["fg"])

    def on_theme_change(self, *_):
        self.apply_theme(self.theme_var.get())

    def load_known_adware(self):
        self.known_adware = set()
        if os.path.exists("known_adware.txt"):
            try:
                with open("known_adware.txt", "r") as f:
                    for line in f:
                        pkg = line.strip()
                        if pkg:
                            self.known_adware.add(pkg)
            except Exception as e:
                pass

    def add_to_known_adware(self, pkg):
        if pkg not in self.known_adware:
            self.known_adware.add(pkg)
            try:
                with open("known_adware.txt", "a") as f:
                    f.write(pkg + "\n")
            except Exception as e:
                pass

    def toggle_auto_refresh(self):
        if self.auto_refresh_var.get():
            self.auto_refresh_loop()
        else:
            if self._refresh_job is not None:
                self.after_cancel(self._refresh_job)
                self._refresh_job = None
            self.log_msg("Auto-refresh stopped.")

    def auto_refresh_loop(self):
        if not self.auto_refresh_var.get():
            return
        
        if self.device:
            self.on_scan_recent_only(silent=True)

        try:
            delay_sec = float(self.refresh_time_var.get())
            if delay_sec <= 0: delay_sec = 5
        except ValueError:
            delay_sec = 5
            self.refresh_time_var.set("5")
            
        self._refresh_job = self.after(int(delay_sec * 1000), self.auto_refresh_loop)

    def load_user_whitelist(self):
        self.user_whitelist = set()
        if os.path.exists("whitelist.txt"):
            try:
                with open("whitelist.txt", "r") as f:
                    for line in f:
                        if line.strip(): self.user_whitelist.add(line.strip())
            except Exception: pass

    def add_to_whitelist(self, pkg):
        if pkg not in self.user_whitelist:
            self.user_whitelist.add(pkg)
            try:
                with open("whitelist.txt", "a") as f:
                    f.write(pkg + "\n")
            except Exception: pass
        self.log_msg(f"Added {pkg} to Safe Apps Whitelist.")
        self.refresh_installed()

    def export_log(self):
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="adware_cleaner_log.txt", title="Save Log")
        if path:
            try:
                with open(path, "w") as f:
                    f.write(self.log.get("1.0", "end"))
                messagebox.showinfo("Export Log", "Log saved successfully.")
            except Exception as e:
                messagebox.showerror("Export Failed", str(e))

    def show_context_menu(self, event, tree):
        iid = tree.identify_row(event.y)
        if iid:
            tree.selection_set(iid)
            pkg = tree.item(iid, "values")[0]
            menu = tk.Menu(self, tearoff=0)
            menu.add_command(label="Mark as Safe (Whitelist)", command=lambda: self.add_to_whitelist(pkg))
            menu.add_command(label="Open in Play Store", command=lambda: self.open_play_store(pkg))
            menu.add_command(label="Check Permissions", command=lambda: self.check_permissions(pkg))
            menu.post(event.x_root, event.y_root)

    def open_play_store(self, pkg):
        import webbrowser
        webbrowser.open(f"https://play.google.com/store/apps/details?id={pkg}")
        self.log_msg(f"Opened Play Store for {pkg}")

    def check_permissions(self, pkg):
        if not self.device: return
        def task():
            code, out, err = adb(["shell", "dumpsys", "package", pkg], device=self.device)
            perms = []
            capture = False
            for line in (out or "").splitlines():
                if "requested permissions:" in line: capture = True
                elif "install permissions:" in line or "runtime permissions:" in line or "queries:" in line: capture = False
                elif capture and line.strip().startswith("android.permission"):
                    perms.append(line.strip())
            disp = "\n".join(perms) if perms else "No permissions found or failed to parse."
            self.after(0, lambda: messagebox.showinfo(f"Permissions: {pkg}", disp))
        threading.Thread(target=task, daemon=True).start()

    def create_widgets(self):
        # ---- Row 1: Connection controls ----
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=(8, 2))
        ttk.Button(top, text="Connect USB", command=self.connect_usb).pack(side="left", padx=4)
        ttk.Button(top, text="Connect Wireless", command=self.connect_wireless).pack(side="left", padx=4)
        self.dev_label = ttk.Label(top, text="Device: <none>")
        self.dev_label.pack(side="left", padx=10)
        ttk.Button(top, text="List Installed", command=self.refresh_installed).pack(side="left", padx=4)
        ttk.Checkbutton(top, text="Dry run", variable=self.dry_run_var).pack(side="left", padx=10)
        ttk.Button(top, text="Restart ADB", command=self.restart_adb).pack(side="left", padx=6)
        # Theme selector on the right of row 1
        theme_menu = ttk.OptionMenu(
            top, self.theme_var, self.theme_var.get(),
            *self.THEMES.keys(),
            command=self.on_theme_change,
        )
        theme_menu.pack(side="right", padx=(0, 6))
        ttk.Label(top, text="Theme:").pack(side="right", padx=(4, 2))

        # ---- Row 2: Scan controls ----
        top2 = ttk.Frame(self)
        top2.pack(fill="x", padx=10, pady=(0, 6))
        ttk.Button(top2, text="Ad appears: Scan now (K)", command=self.on_scan_click).pack(side="left", padx=6)
        ttk.Button(top2, text="Scan Recent (no AI)", command=self.on_scan_recent_only).pack(side="left", padx=6)
        ttk.Button(top2, text="Scan Hidden Apps", command=self.on_scan_hidden).pack(side="left", padx=6)
        ttk.Checkbutton(top2, text="Refresh scanning each", variable=self.auto_refresh_var, command=self.toggle_auto_refresh).pack(side="left", padx=(10, 2))
        ttk.Entry(top2, textvariable=self.refresh_time_var, width=5).pack(side="left", padx=2)
        ttk.Label(top2, text="s").pack(side="left", padx=(0, 6))


        # Gemini panel
        gem = ttk.LabelFrame(self, text="Gemini (google-genai)")
        gem.pack(fill="x", padx=10, pady=(0,8))
        ttk.Label(gem, text="API Key:").pack(side="left", padx=(10,4))
        api_entry = ttk.Entry(gem, textvariable=self.api_key_var, width=48, show="*")
        api_entry.pack(side="left", padx=(0,10))
        ttk.Label(gem, text="Model:").pack(side="left", padx=(10,4))
        self.model_box = ttk.Combobox(
            gem,
            textvariable=self.model_var,
            width=28,
            values=[
                "gemini-2.5-flash",
                "gemini-2.5-pro",
                "gemini-2.0-flash",
                "gemini-2.0-flash-lite",
            ],
        )
        self.model_box.pack(side="left", padx=(0,10))
        ttk.Button(gem, text="Test API", command=self.test_api).pack(side="left", padx=6)

        # Notebook
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=8)

        # Installed tab with action bar
        inst_frame = ttk.Frame(nb)
        nb.add(inst_frame, text="Installed Packages")

        inst_bar = ttk.Frame(inst_frame)
        inst_bar.pack(fill="x", padx=6, pady=(6, 0))
        ttk.Label(inst_bar, text="Filter:").pack(side="left")
        inst_filter = ttk.Entry(inst_bar, textvariable=self.filter_var, width=32)
        inst_filter.pack(side="left", padx=(4, 10))
        inst_filter.bind("<KeyRelease>", lambda e: self.apply_installed_filter())

        self.uninstall_user0_btn = ttk.Button(inst_bar, text="Uninstall (user 0)", command=self.uninstall_selected_user0)
        self.uninstall_user0_btn.pack(side="left", padx=4)

        self.uninstall_full_btn = ttk.Button(inst_bar, text="Uninstall (full)", command=self.uninstall_selected_full)
        self.uninstall_full_btn.pack(side="left", padx=4)

        ttk.Checkbutton(inst_bar, text="Add removed app to database", variable=self.add_to_db_var).pack(side="left", padx=8)

        self.refresh_inst_btn = ttk.Button(inst_bar, text="Refresh", command=self.refresh_installed)
        self.refresh_inst_btn.pack(side="left", padx=8)

        # Installed tree
        self.installed_tree = self.make_table(inst_frame, ("package",), "Installed")

        # Recent tab
        recent_frame = ttk.Frame(nb)
        nb.add(recent_frame, text="Recent / Foreground")
        self.recent_tree = self.make_table(recent_frame, ("package",), "Recent/Foreground")

        # Suspects tab
        suspects_frame = ttk.Frame(nb)
        nb.add(suspects_frame, text="Gemini Suspects")
        self.suspects_tree = self.make_table(suspects_frame, ("package", "action"), "Suspects")

        # Log panel
        log_frame = ttk.Frame(self)
        log_frame.pack(fill="x", padx=10, pady=(0,8))
        t = self.THEMES.get(self.theme_var.get(), self.THEMES["Dark"])
        self.log = tk.Text(log_frame, height=8, wrap="word",
                           bg=t["log_bg"], fg=t["log_fg"],
                           insertbackground=t["fg"])
        self.log.pack(side="left", fill="x", expand=True)
        self.log.configure(state="disabled")
        ttk.Button(log_frame, text="Save Log", command=self.export_log).pack(side="right", padx=(8,0), anchor="s")

    def make_table(self, parent, columns, title):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="extended")
        tree.tag_configure("adware", background="#cc6666", foreground="white")
        tree.tag_configure("whitelist", background="#339933", foreground="white")
        tree.bind("<Button-3>", lambda e: self.show_context_menu(e, tree))
        for c in columns:
            tree.heading(c, text=c.title())
            tree.column(c, width=520 if c == "package" else 160, anchor="w")
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        return tree

    def log_msg(self, msg):
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def preflight_adb(self):
        ok, out = check_adb_version()
        if not ok:
            self.log_msg("ADB not found. Install Platform-Tools and add to PATH.")
            messagebox.showerror("ADB missing", "ADB not found. Install Platform-Tools and add to PATH.")
            return
        self.log_msg("ADB OK: " + (out or "").strip().splitlines()[0])
        # Auto-detect connected devices
        threading.Thread(target=self._startup_device_scan, daemon=True).start()

    def _startup_device_scan(self):
        """Run on a background thread immediately after ADB is confirmed OK."""
        try:
            code, out, err = run(["adb", "devices"])
            if code != 0:
                self.log_msg("Could not query devices on startup.")
                return
            devs = []
            for line in (out or "").splitlines()[1:]:
                line = line.strip()
                if line.endswith("\tdevice") or line.endswith(" device"):
                    serial = line.split()[0]
                    devs.append(serial)
                elif "\tdevice" in line:
                    serial = line.split("\t")[0]
                    devs.append(serial)
            if not devs:
                self.log_msg("No devices connected at startup.")
                return
            if len(devs) == 1:
                # Auto-select the only device
                self.after(0, lambda: self._select_device(devs[0]))
            else:
                # Multiple devices — show chooser on main thread
                self.after(0, lambda: self._show_device_chooser(devs))
        except Exception as e:
            self.log_msg(f"Startup device scan failed: {e}")

    def _select_device(self, serial):
        self.device = serial
        self.dev_label.config(text=f"Device: {serial}")
        self.log_msg(f"Auto-selected device: {serial}")

    def _show_device_chooser(self, devs):
        """Modal dialog to pick one device from a list."""
        dlg = tk.Toplevel(self)
        dlg.title("Select Device")
        dlg.resizable(False, False)
        dlg.grab_set()          # modal
        dlg.lift()
        dlg.focus_force()

        # Apply current theme colours
        t = self.THEMES.get(self.theme_var.get(), self.THEMES["Dark"])
        dlg.configure(bg=t["bg"])

        ttk.Label(dlg, text="Multiple devices detected.\nSelect the device to use:",
                  justify="left").pack(padx=20, pady=(16, 8))

        choice_var = tk.StringVar(value=devs[0])
        lb_frame = ttk.Frame(dlg)
        lb_frame.pack(padx=20, fill="x")
        lb = tk.Listbox(lb_frame, selectmode="single", height=min(len(devs), 8),
                        bg=t["field_bg"], fg=t["fg"],
                        selectbackground=t["sel_bg"], activestyle="none",
                        font=("Consolas", 10))
        for d in devs:
            lb.insert("end", d)
        lb.select_set(0)
        lb.pack(side="left", fill="x", expand=True)
        vsb = ttk.Scrollbar(lb_frame, orient="vertical", command=lb.yview)
        lb.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")

        def confirm():
            sel = lb.curselection()
            if not sel:
                return
            serial = devs[sel[0]]
            dlg.destroy()
            self._select_device(serial)

        def cancel():
            dlg.destroy()
            self.log_msg("Device selection cancelled.")

        btn_frame = ttk.Frame(dlg)
        btn_frame.pack(pady=(10, 16))
        ttk.Button(btn_frame, text="Connect", command=confirm).pack(side="left", padx=8)
        ttk.Button(btn_frame, text="Cancel",  command=cancel).pack(side="left", padx=8)
        dlg.bind("<Return>", lambda e: confirm())
        dlg.bind("<Escape>", lambda e: cancel())

        # Centre over parent
        self.update_idletasks()
        dlg.update_idletasks()
        pw, ph = self.winfo_width(), self.winfo_height()
        px, py = self.winfo_rootx(), self.winfo_rooty()
        dw, dh = dlg.winfo_reqwidth(), dlg.winfo_reqheight()
        dlg.geometry(f"+{px + (pw - dw)//2}+{py + (ph - dh)//2}")

    # ---------- Connect ----------
    def connect_usb(self):
        def task():
            code, out, err = adb(["devices"])
            if code != 0:
                self.log_msg("adb devices failed.")
                return
            devs = []
            for line in (out or "").splitlines()[1:]:
                line = line.strip()
                if line.endswith("\tdevice") or line.endswith(" device"):
                    serial = line.split()[0]
                    devs.append(serial)
                elif "\tdevice" in line:
                    devs.append(line.split("\t")[0])
            if not devs:
                self.log_msg("No USB device found. Plug in and authorize USB debugging.")
                return
            if len(devs) == 1:
                self.after(0, lambda: self._select_device(devs[0]))
            else:
                self.after(0, lambda: self._show_device_chooser(devs))
        threading.Thread(target=task, daemon=True).start()
    def restart_adb(self):
        # Run ADB server restart without blocking UI
        def task():
            try:
                self.log_msg("Restarting ADB server...")
                code1, out1, err1 = run(["adb", "kill-server"])
                if err1.strip():
                    self.log_msg(err1.strip())
                if out1.strip():
                    self.log_msg(out1.strip())
                code2, out2, err2 = run(["adb", "start-server"])
                if err2.strip():
                    self.log_msg(err2.strip())
                if out2.strip():
                    self.log_msg(out2.strip())
                # Verify and refresh devices
                code3, out3, err3 = run(["adb", "devices"])
                if out3.strip():
                    self.log_msg(out3.strip())
                if err3.strip():
                    self.log_msg(err3.strip())
                # Pick a device if available
                dev = None
                lines = (out3 or "").splitlines()
                for line in lines[1:]:
                    if "\tdevice" in line:
                        dev = line.split("\t")[0]
                        break
                self.device = dev
                self.after(0, lambda: self.dev_label.config(text=f"Device: {self.device or '<none>'}"))
            except Exception as e:
                self.log_msg(f"Restart ADB failed: {e}")
        threading.Thread(target=task, daemon=True).start()


    def connect_wireless(self):
        # Main-thread dialog flow: Pair (Android 11+) then Connect
        def ask_and_run():
            # Ask pairing info (Android 11+ Wireless debugging)
            if not messagebox.askyesno(
                "Wireless Debugging",
                "Use Android 11+ Wireless debugging pairing flow?\n\n"
                "Yes = Pair with pairing code, then Connect using the connection port.\n"
                "No = Legacy TCP/IP via USB (set adbd to listen on a fixed port).",
                parent=self
            ):
                # Legacy TCP/IP via USB path (stable port)
                ip = simpledialog.askstring("Legacy TCP/IP", "Phone IP (e.g. 192.168.1.50):", parent=self)
                if not ip:
                    return
                port_str = simpledialog.askstring("Legacy TCP/IP", "TCP port (default 5555):", parent=self)
                port = (port_str or "5555").strip()
                if not port.isdigit():
                    messagebox.showerror("Invalid port", "Port must be a number.", parent=self)
                    return
                usb_serial = None

                # pick a USB device to switch into tcpip
                def legacy_task():
                    try:
                        code, out, err = run(["adb", "devices"])
                        if code != 0:
                            self.log_msg(f"adb devices failed: {(err or out).strip()}")
                            return
                        for line in (out or "").splitlines()[1:]:
                            if "\tdevice" in line and ":" not in line:
                                usb_serial = line.split("\t")[0]
                                break
                        if not usb_serial:
                            self.log_msg("No USB device found; connect via USB once to enable tcpip.")
                            return
                        run(["adb", "-s", usb_serial, "tcpip", port])
                        code2, out2, err2 = run(["adb", "connect", f"{ip}:{port}"])
                        self.log_msg((out2 or err2 or "").strip())
                        code3, out3, err3 = run(["adb", "devices"])
                        dev = None
                        for line in (out3 or "").splitlines()[1:]:
                            if "\tdevice" in line and f"{ip}:{port}" in line:
                                dev = f"{ip}:{port}"
                                break
                        self.device = dev
                        self.after(0, lambda: self.dev_label.config(text=f"Device: {self.device or '<none>'}"))
                    except Exception as e:
                        self.log_msg(f"Legacy connect failed: {e}")
                threading.Thread(target=legacy_task, daemon=True).start()
                return

            # Android 11+ pairing flow
            pair_host = simpledialog.askstring(
                "Pairing",
                "Enter IP:PairingPort from Wireless debugging (e.g. 192.168.1.10:47539):",
                parent=self
            )
            if not pair_host or ":" not in pair_host:
                return
            pair_code = simpledialog.askstring(
                "Pairing Code",
                "Enter 6-digit pairing code displayed on the phone:",
                parent=self
            )
            if not pair_code or not pair_code.strip():
                return

            conn_host = simpledialog.askstring(
                "Connect",
                "Enter IP:ConnectionPort from Wireless debugging main screen (NOT pairing port):",
                parent=self
            )
            if not conn_host or ":" not in conn_host:
                return

            def pair_and_connect_task():
                try:
                    # 1) Pair
                    self.log_msg(f"Pairing with {pair_host} ...")
                    code_p, out_p, err_p = run(["adb", "pair", pair_host, pair_code.strip()])
                    self.log_msg((out_p or err_p or "").strip())

                    # 2) Connect using the connection port
                    self.log_msg(f"Connecting to {conn_host} ...")
                    code_c, out_c, err_c = run(["adb", "connect", conn_host])
                    self.log_msg((out_c or err_c or "").strip())

                    # 3) VERIFY + POLL: refresh device list immediately and after a short delay
                    def refresh_devices(select_target):
                        code_d, out_d, err_d = run(["adb", "devices"])
                        dev_found = None
                        for line in (out_d or "").splitlines()[1:]:
                            if "\tdevice" in line:
                                serial = line.split("\t")[0]
                                if select_target in serial:
                                    dev_found = serial
                                    break
                        if dev_found:
                            self.device = dev_found
                            self.after(0, lambda: self.dev_label.config(text=f"Device: {self.device}"))
                            return True
                        return False

                    # Try immediately
                    ok_now = refresh_devices(conn_host)
                    # Try again after 1s if not yet visible
                    if not ok_now:
                        self.after(1000, lambda: refresh_devices(conn_host))

                    # Optional: early exit log if still not visible
                    if not ok_now:
                        self.log_msg("Waiting for device to appear in adb devices...")
                        connect_usb()

                    # 4) Optional stabilize port (unchanged)
                    # ... your existing optional tcpip 5555 block ...

                except Exception as e:
                    self.log_msg(f"Wireless debugging failed: {e}")

            threading.Thread(target=pair_and_connect_task, daemon=True).start()

        # Ensure dialogs run on Tk main thread
        self.after(0, ask_and_run)

    # ---------- Installed ----------
    def refresh_installed(self):
        if not self.device:
            messagebox.showwarning("No device", "Connect a device first.")
            return
        def task():
            try:
                pkgs = list_installed(self.device, user_only=ONLY_USER_APPS)
                self.installed = pkgs
                self.apply_installed_filter()
                self.log_msg(f"Installed packages: {len(pkgs)}")
            except Exception as e:
                self.log_msg(f"List installed failed: {e}")
        threading.Thread(target=task, daemon=True).start()

    def apply_installed_filter(self):
        query = self.filter_var.get().strip().lower()
        rows = [(p,) for p in self.installed if (query in p.lower())]
        self.populate(self.installed_tree, rows)

    def populate(self, tree, rows):
        tree.delete(*tree.get_children())
        for r in rows:
            pkg = r[0]
            if getattr(self, "known_adware", None) and pkg in self.known_adware:
                tree.insert("", "end", values=r, tags=("adware",))
            elif getattr(self, "user_whitelist", None) and pkg in self.user_whitelist:
                tree.insert("", "end", values=r, tags=("whitelist",))
            else:
                tree.insert("", "end", values=r)

    def get_selected_installed(self):
        sel = self.installed_tree.selection()
        pkgs = []
        for item in sel:
            vals = self.installed_tree.item(item, "values")
            if vals:
                pkgs.append(vals[0])
        return pkgs

    # ---------- Uninstall actions ----------
    def uninstall_selected_user0(self):
        pkgs = self.get_selected_installed()
        if not pkgs:
            messagebox.showinfo("No selection", "Select one or more packages in the Installed tab.")
            return
        msg = "Uninstall for user 0:\n" + "\n".join(pkgs) + "\n\nProceed?"
        if not messagebox.askyesno("Confirm", msg):
            return
        if not self.device:
            messagebox.showwarning("No device", "Connect a device first.")
            return
        def task():
            for pkg in pkgs:
                ok = uninstall_user0(self.device, pkg)
                self.log_msg(f"Uninstall (user 0) {pkg}: {'Success' if ok else 'Failed'}")
                if ok and getattr(self, "add_to_db_var", None) and self.add_to_db_var.get():
                    self.add_to_known_adware(pkg)
            try:
                pkgs2 = list_installed(self.device, user_only=ONLY_USER_APPS)
                self.installed = pkgs2
                self.apply_installed_filter()
            except Exception as e:
                self.log_msg(f"Refresh failed: {e}")
        threading.Thread(target=task, daemon=True).start()

    def uninstall_selected_full(self):
        pkgs = self.get_selected_installed()
        if not pkgs:
            messagebox.showinfo("No selection", "Select one or more packages in the Installed tab.")
            return
        warn_core = [p for p in pkgs if p.startswith(("com.android", "com.google.android"))]
        extra = ""
        if warn_core:
            extra = "\n\nWarning: Some selections look like core packages; full uninstall may fail or impact system. Prefer user-0."
        msg = "Full uninstall:\n" + "\n".join(pkgs) + f"{extra}\n\nProceed?"
        if not messagebox.askyesno("Confirm", msg):
            return
        if not self.device:
            messagebox.showwarning("No device", "Connect a device first.")
            return
        def task():
            for pkg in pkgs:
                code, out, err = adb(["uninstall", pkg], device=self.device)
                ok = (code == 0) or ("Success" in (out or ""))
                self.log_msg(f"Uninstall (full) {pkg}: {'Success' if ok else 'Failed'}")
                if ok and getattr(self, "add_to_db_var", None) and self.add_to_db_var.get():
                    self.add_to_known_adware(pkg)
            try:
                pkgs2 = list_installed(self.device, user_only=ONLY_USER_APPS)
                self.installed = pkgs2
                self.apply_installed_filter()
            except Exception as e:
                self.log_msg(f"Refresh failed: {e}")
        threading.Thread(target=task, daemon=True).start()

    # ---------- Gemini integration ----------
    def test_api(self):
        key = (self.api_key_var.get() or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or "").strip()
        if not key:
            messagebox.showwarning("API key missing", "Enter a Gemini API key.")
            return
        model = (self.model_var.get() or DEFAULT_MODEL).strip()
        self.log_msg(f"Testing API with model: {model}")
        def task():
            try:
                client = make_client(key)
                names = list_models(client)
                preview = ", ".join(names[:8]) + (" ..." if len(names) > 8 else "")
                self.log_msg(f"models.list OK. Examples: {preview}")
                resp = client.models.generate_content(model=model, contents="ping")
                ok_text = getattr(resp, "text", "") or "<no text>"
                self.log_msg(f"generate_content OK. Sample: {ok_text[:80]}")
                messagebox.showinfo("API test", "API key and model validated.")
            except Exception as e:
                self.log_msg(f"API test failed: {e}")
                messagebox.showerror("API test failed", str(e))
        threading.Thread(target=task, daemon=True).start()

    # ---------- Scan flows ----------
    def on_scan_hidden(self):
        if not self.device:
            messagebox.showwarning("No device", "Connect a device first.")
            return
        self.log_msg("Scanning for hidden apps (no launcher icon)...")
        def task():
            try:
                all_pkgs = list_installed(self.device, user_only=ONLY_USER_APPS)
                hidden = []
                wl = getattr(self, "user_whitelist", set())
                self.log_msg(f"Checking {len(all_pkgs)} packages...")
                for p in all_pkgs:
                    if is_whitelisted(p, wl): continue
                    c, o, e = adb(["shell", "cmd", "package", "resolve-activity", "--brief", p], device=self.device)
                    if "No activity found" in (o or "") or not o.strip():
                        hidden.append(p)

                self.suspects = hidden
                self.after(0, lambda: self.populate(self.suspects_tree, [(p, "hidden") for p in hidden]))
                
                if hidden:
                    self.log_msg("Found hidden packages: " + ", ".join(hidden))
                else:
                    self.log_msg("No hidden non-whitelisted packages found.")
            except Exception as e:
                self.log_msg(f"Hidden scan failed: {e}")
        threading.Thread(target=task, daemon=True).start()

    def on_scan_recent_only(self, silent=False):
        if not self.device:
            if not silent: messagebox.showwarning("No device", "Connect a device first.")
            return
        if not silent: self.log_msg("Scanning recent/foreground apps (no AI)...")
        def task():
            try:
                recent = get_recent_packages(self.device)
                self.recent = recent
                self.populate(self.recent_tree, [(p,) for p in recent])
                recent_non_sys = [p for p in recent if not is_whitelisted(p, getattr(self, "user_whitelist", set()))]
                if not silent:
                    if recent_non_sys:
                        self.log_msg("Recent non-whitelisted packages: " + ", ".join(recent_non_sys))
                    else:
                        self.log_msg("No non-whitelisted recent packages found.")
            except Exception as e:
                if not silent: self.log_msg(f"Recent-only scan failed: {e}")
        threading.Thread(target=task, daemon=True).start()

    def on_scan_click(self):
        if not self.device:
            messagebox.showwarning("No device", "Connect a device first.")
            return
        key = (self.api_key_var.get() or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or "").strip()
        model = (self.model_var.get() or DEFAULT_MODEL).strip()
        if not key:
            messagebox.showwarning("API key missing", "Enter a Gemini API key.")
            return
        self.log_msg("Scanning recent/foreground apps...")
        def task():
            try:
                recent = get_recent_packages(self.device)
                wl = getattr(self, "user_whitelist", set())
                recent_f = [p for p in recent if not is_whitelisted(p, wl)]
                self.recent = recent
                self.populate(self.recent_tree, [(p,) for p in recent])

                client = make_client(key)
                suspects = gemini_pick_suspects(client, model, self.installed or [], recent_f or recent)
                suspects = [p for p in suspects if not is_whitelisted(p, wl)]
                self.suspects = suspects
                self.populate(self.suspects_tree, [(p, "planned" if self.dry_run_var.get() else "remove") for p in suspects])

                if not suspects:
                    self.log_msg("No suspects returned; try again when the ad is visible.")
                    return
                if self.dry_run_var.get():
                    self.log_msg("[Dry run] Would uninstall: " + ", ".join(suspects))
                    return

                for pkg in suspects:
                    ok = uninstall_user0(self.device, pkg)
                    self.log_msg(f"Uninstall {pkg}: {'Success' if ok else 'Failed'}")
                    if ok and getattr(self, "add_to_db_var", None) and self.add_to_db_var.get():
                        self.add_to_known_adware(pkg)

                try:
                    pkgs = list_installed(self.device, user_only=ONLY_USER_APPS)
                    self.installed = pkgs
                    self.apply_installed_filter()
                except Exception as e:
                    self.log_msg(f"Refresh after uninstall failed: {e}")

                self.log_msg("Ready. Press K or click Scan when ads reappear.")
            except Exception as e:
                self.log_msg(f"Scan failed: {e}")
        threading.Thread(target=task, daemon=True).start()

if __name__ == "__main__":
    App().mainloop()
