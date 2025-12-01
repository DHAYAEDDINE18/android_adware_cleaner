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

def is_whitelisted(pkg):
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

        self.create_widgets()
        # Global key binding: press K to full scan (AI)
        self.bind_all("<Key-k>", lambda e: self.on_scan_click())
        self.after(200, self.preflight_adb)

    def create_widgets(self):
        # Top bar
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=8)
        ttk.Button(top, text="Connect USB", command=self.connect_usb).pack(side="left", padx=4)
        ttk.Button(top, text="Connect Wireless", command=self.connect_wireless).pack(side="left", padx=4)
        self.dev_label = ttk.Label(top, text="Device: <none>")
        self.dev_label.pack(side="left", padx=10)
        ttk.Button(top, text="List Installed", command=self.refresh_installed).pack(side="left", padx=4)
        ttk.Checkbutton(top, text="Dry run", variable=self.dry_run_var).pack(side="left", padx=10)

        # Scan buttons
        ttk.Button(top, text="Ad appears: Scan now (K)", command=self.on_scan_click).pack(side="left", padx=6)
        ttk.Button(top, text="Scan Recent (no AI)", command=self.on_scan_recent_only).pack(side="left", padx=6)
        ttk.Button(top, text="Restart ADB", command=self.restart_adb).pack(side="left", padx=6)


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
        self.log = tk.Text(self, height=8, wrap="word")
        self.log.pack(fill="x", padx=10, pady=(0,8))
        self.log.configure(state="disabled")

    def make_table(self, parent, columns, title):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="extended")
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
        if ok:
            self.log_msg("ADB OK:\n" + (out or "").strip())
        else:
            self.log_msg("ADB not found. Install Platform-Tools and add to PATH.")
            messagebox.showerror("ADB missing", "ADB not found. Install Platform-Tools and add to PATH.")

    # ---------- Connect ----------
    def connect_usb(self):
        def task():
            code, out, err = adb(["devices"])
            if code != 0:
                self.log_msg("adb devices failed.")
                return
            devs = []
            for line in out.splitlines()[1:]:
                if "\tdevice" in line:
                    devs.append(line.split("\t")[0])
            if not devs:
                self.log_msg("No USB device. Plug in and authorize USB debugging.")
                return
            self.device = devs[0]
            self.dev_label.config(text=f"Device: {self.device}")
            self.log_msg(f"Using USB device: {self.device}")
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
    def on_scan_recent_only(self):
        if not self.device:
            messagebox.showwarning("No device", "Connect a device first.")
            return
        self.log_msg("Scanning recent/foreground apps (no AI)...")
        def task():
            try:
                recent = get_recent_packages(self.device)
                self.recent = recent
                self.populate(self.recent_tree, [(p,) for p in recent])
                recent_non_sys = [p for p in recent if not is_whitelisted(p)]
                if recent_non_sys:
                    self.log_msg("Recent non-whitelisted packages: " + ", ".join(recent_non_sys))
                else:
                    self.log_msg("No non-whitelisted recent packages found.")
            except Exception as e:
                self.log_msg(f"Recent-only scan failed: {e}")
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
                recent_f = [p for p in recent if not is_whitelisted(p)]
                self.recent = recent
                self.populate(self.recent_tree, [(p,) for p in recent])

                client = make_client(key)
                suspects = gemini_pick_suspects(client, model, self.installed or [], recent_f or recent)
                suspects = [p for p in suspects if not is_whitelisted(p)]
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
