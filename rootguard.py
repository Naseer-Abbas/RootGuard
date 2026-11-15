"""RootGuard: a Python rootkit and persistence detection tool for Windows.

Checks for hidden processes (cross-view detection), tampered or unsigned
system files, suspicious services, suspicious autostart entries, drivers
loaded from unusual locations or matching known-bad signatures, and
anomalous process behaviour. Runs with a Tkinter GUI or from the command line.

Usage:
    python rootguard.py              # GUI
    python rootguard.py --cli        # full scan in the terminal
    python rootguard.py --baseline   # (re)create the system file baseline
"""

import argparse
import ctypes
import hashlib
import json
import os
import queue
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

try:
    import psutil
except ImportError:
    sys.exit("psutil is required. Run: pip install -r requirements.txt")

IS_WINDOWS = os.name == "nt"
if IS_WINDOWS:
    import winreg
    from ctypes import wintypes

BASE_DIR = Path(__file__).resolve().parent
BASELINE_FILE = BASE_DIR / "baseline.json"
SIGNATURES_FILE = BASE_DIR / "signatures.json"
REPORTS_DIR = BASE_DIR / "reports"

SYSTEM_ROOT = os.environ.get("SystemRoot", r"C:\Windows")
CRITICAL_FILES = [
    rf"{SYSTEM_ROOT}\System32\cmd.exe",
    rf"{SYSTEM_ROOT}\System32\svchost.exe",
    rf"{SYSTEM_ROOT}\System32\lsass.exe",
    rf"{SYSTEM_ROOT}\System32\winlogon.exe",
    rf"{SYSTEM_ROOT}\System32\services.exe",
    rf"{SYSTEM_ROOT}\System32\csrss.exe",
    rf"{SYSTEM_ROOT}\System32\smss.exe",
    rf"{SYSTEM_ROOT}\System32\ntoskrnl.exe",
    rf"{SYSTEM_ROOT}\System32\taskmgr.exe",
    rf"{SYSTEM_ROOT}\explorer.exe",
]

# Folders any user can write to; system components should not run from here
USER_WRITABLE_MARKERS = ["\\users\\", "\\appdata\\", "\\temp\\", "\\tmp\\", "\\downloads\\", "\\public\\"]

# Command-line tricks often used by malware to start at logon
SUSPICIOUS_COMMAND_MARKERS = [
    "-enc ", "-encodedcommand", "frombase64string", "mshta", "wscript", "cscript",
    "regsvr32 /i:http", "certutil -urlcache", "bitsadmin /transfer", "iex(", "invoke-expression",
]

AUTOSTART_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
]

CPU_THRESHOLD = 80  # percent of total CPU for one process


# Helpers

def sha256_file(path):
    """Return the SHA-256 hash of a file, reading it in chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def in_user_writable_folder(path):
    """True if the path is inside a folder ordinary users can write to."""
    lowered = path.lower().replace("/", "\\")
    return any(marker in lowered for marker in USER_WRITABLE_MARKERS)


def has_suspicious_command(command):
    """True if a command line uses a technique common in malware autostarts."""
    lowered = command.lower()
    return any(marker in lowered for marker in SUSPICIOUS_COMMAND_MARKERS)


def extract_executable(command):
    """Pull the program path out of a command line or service binary path."""
    command = os.path.expandvars(command.strip())
    if command.startswith('"'):
        end = command.find('"', 1)
        return command[1:end] if end > 0 else command[1:]
    lowered = command.lower()
    for ext in (".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js"):
        index = lowered.find(ext)
        if index != -1:
            return command[: index + len(ext)]
    return command.split(" ")[0]


def is_unquoted_path_with_spaces(command):
    """True for an unquoted service path with spaces (a privilege-escalation risk)."""
    command = command.strip()
    if command.startswith('"'):
        return False
    exe = extract_executable(command)
    return " " in exe and exe.lower().endswith(".exe")


def normalise_driver_path(path):
    """Convert kernel-style driver paths to normal Windows paths."""
    if path.lower().startswith("\\systemroot\\"):
        return SYSTEM_ROOT + path[len("\\SystemRoot"):]
    if path.startswith("\\??\\"):
        return path[4:]
    if path.lower().startswith("system32\\"):
        return os.path.join(SYSTEM_ROOT, path)
    return path


def authenticode_status(path):
    """Ask PowerShell whether a file's digital signature is valid."""
    safe_path = path.replace("'", "''")  # escape quotes for PowerShell
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"(Get-AuthenticodeSignature -LiteralPath '{safe_path}').Status"],
            capture_output=True, text=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return result.stdout.strip() or "Unknown"
    except (OSError, subprocess.SubprocessError):
        return "Unknown"


def is_admin():
    """True if running with administrator rights."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def load_signatures():
    """Load known-bad driver names and SHA-256 hashes from signatures.json."""
    try:
        data = json.loads(SIGNATURES_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set(), set()
    names = {n.lower() for n in data.get("driver_names", [])}
    hashes = {h.lower() for h in data.get("sha256", [])}
    return names, hashes


# Scanner

class Scanner:
    """Runs the detection checks and collects findings."""

    def __init__(self, log):
        self.log = log            # function(level, message)
        self.findings = []        # (level, check, message)
        self.lock = threading.Lock()

    def report(self, level, check, message):
        """Record a finding and pass it to the log display."""
        with self.lock:
            self.findings.append((level, check, message))
        self.log(level, f"[{check}] {message}")

    # Hidden processes: compare the normal process list with brute-force PID probing
    def check_hidden_processes(self):
        """Find processes that exist but are missing from the normal process list."""
        check = "Hidden processes"
        self.log("INFO", f"--- {check} ---")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        query_limited, still_active, access_denied = 0x1000, 259, 5

        def pid_exists(pid):
            handle = kernel32.OpenProcess(query_limited, False, pid)
            if not handle:
                return ctypes.get_last_error() == access_denied  # exists but protected
            try:
                code = wintypes.DWORD()
                return bool(kernel32.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == still_active
            finally:
                kernel32.CloseHandle(handle)

        listed_before = set(psutil.pids())
        highest = max(65536, max(listed_before, default=0) + 4096)
        probed = {pid for pid in range(4, highest, 4) if pid_exists(pid)}
        listed_after = set(psutil.pids())

        # Re-check candidates to rule out processes that started or ended during the scan
        hidden = sorted(pid for pid in probed - listed_before - listed_after if pid_exists(pid))
        if hidden:
            self.report("HIGH", check, f"Processes hidden from the process list: {hidden}")
        else:
            self.report("OK", check, f"No hidden processes ({len(listed_after)} listed, {len(probed)} probed)")

        unnamed = []
        for proc in psutil.process_iter(["pid", "name"]):
            if not proc.info["name"] and proc.info["pid"] not in (0, 4):
                unnamed.append(proc.info["pid"])
        if unnamed:
            self.report("INFO", check, f"Processes with no readable name (often protected system processes): {unnamed}")

    # Critical system files: baseline hashes plus digital signature
    def check_critical_files(self, rebuild=False):
        """Compare critical system files with the saved baseline and check their signatures."""
        check = "System files"
        self.log("INFO", f"--- {check} ---")
        current = {}
        for path in CRITICAL_FILES:
            try:
                current[path] = sha256_file(path)
            except OSError as error:
                self.report("MEDIUM", check, f"Cannot read {path}: {error}")

        if rebuild or not BASELINE_FILE.exists():
            BASELINE_FILE.write_text(json.dumps(current, indent=2), encoding="utf-8")
            self.report("INFO", check, f"Baseline saved for {len(current)} files. Future scans will compare against it.")
        else:
            baseline = json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
            changed = [p for p, h in current.items() if p in baseline and baseline[p] != h]
            for path in changed:
                self.report("HIGH", check, f"Hash changed since baseline: {path} "
                                           "(expected after a Windows update; rebuild the baseline if so)")
            if not changed:
                self.report("OK", check, f"All {len(current)} files match the baseline")

        for path in current:
            status = authenticode_status(path)
            if status == "Valid":
                self.log("OK", f"[{check}] Signature valid: {path}")
            elif status != "Unknown":
                self.report("HIGH", check, f"Signature {status}: {path}")

    # Services: binaries in user-writable folders, missing files, unquoted paths
    def check_services(self):
        """Flag Windows services with risky or suspicious binary paths."""
        check = "Services"
        self.log("INFO", f"--- {check} ---")
        flagged = 0
        for service in psutil.win_service_iter():
            try:
                info = service.as_dict()
            except (psutil.Error, OSError):
                continue
            binpath = info.get("binpath") or ""
            if not binpath:
                continue
            exe = extract_executable(binpath)
            name = info.get("name")
            reasons = []
            if in_user_writable_folder(exe):
                reasons.append("binary in a user-writable folder")
            if not os.path.exists(exe) and not exe.lower().endswith("svchost.exe"):
                reasons.append("binary file missing")
            if is_unquoted_path_with_spaces(binpath):
                reasons.append("unquoted path with spaces (privilege-escalation risk)")
            if reasons:
                flagged += 1
                level = "HIGH" if "binary in a user-writable folder" in reasons else "MEDIUM"
                self.report(level, check, f"{name} ({info.get('status')}): {'; '.join(reasons)} -> {binpath}")
        if not flagged:
            self.report("OK", check, "No suspicious services found")

    # Autostart: Run keys and Startup folders
    def check_autostart(self):
        """Inspect Run/RunOnce registry keys and Startup folders for suspicious entries."""
        check = "Autostart"
        self.log("INFO", f"--- {check} ---")
        hives = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
        entries = []
        for hive, subkey in AUTOSTART_KEYS:
            try:
                with winreg.OpenKey(hives[hive], subkey) as key:
                    index = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, index)
                        except OSError:
                            break
                        entries.append((f"{hive}\\{subkey}\\{name}", str(value)))
                        index += 1
            except OSError:
                continue

        startup_folders = [
            Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
            Path(os.environ.get("ProgramData", r"C:\ProgramData")) / r"Microsoft\Windows\Start Menu\Programs\StartUp",
        ]
        for folder in startup_folders:
            if folder.is_dir():
                for item in folder.iterdir():
                    if item.name.lower() != "desktop.ini":
                        entries.append((str(item), str(item)))

        flagged = 0
        for location, command in entries:
            exe = extract_executable(command)
            reasons = []
            if has_suspicious_command(command):
                reasons.append("suspicious command technique")
            if in_user_writable_folder(exe) and "\\start menu\\" not in location.lower():
                reasons.append("runs from a user-writable folder")
            if exe and ":" in exe and not os.path.exists(exe):
                reasons.append("target file missing")
            if reasons:
                flagged += 1
                self.report("MEDIUM", check, f"{location}: {'; '.join(reasons)} -> {command}")
            else:
                self.log("INFO", f"[{check}] {location} -> {command}")
        if not flagged:
            self.report("OK", check, f"No suspicious autostart entries ({len(entries)} reviewed)")

    # Drivers: unusual load locations and known-bad signatures
    def check_drivers(self):
        """List loaded kernel drivers and flag unusual locations or signature matches."""
        check = "Drivers"
        self.log("INFO", f"--- {check} ---")
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        psapi.EnumDeviceDrivers.argtypes = [ctypes.POINTER(ctypes.c_void_p), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        psapi.GetDeviceDriverFileNameW.argtypes = [ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]

        needed = wintypes.DWORD()
        psapi.EnumDeviceDrivers(None, 0, ctypes.byref(needed))
        count = needed.value // ctypes.sizeof(ctypes.c_void_p)
        bases = (ctypes.c_void_p * count)()
        if not psapi.EnumDeviceDrivers(bases, needed, ctypes.byref(needed)):
            self.report("MEDIUM", check, "Could not list drivers (try running as administrator)")
            return

        bad_names, bad_hashes = load_signatures()
        trusted = (SYSTEM_ROOT.lower() + "\\system32\\", SYSTEM_ROOT.lower() + "\\syswow64\\")
        flagged = checked = 0
        for base in bases:
            if not base:
                continue
            buffer = ctypes.create_unicode_buffer(1024)
            if not psapi.GetDeviceDriverFileNameW(base, buffer, 1024):
                continue
            path = normalise_driver_path(buffer.value)
            name = os.path.basename(path).lower()
            checked += 1

            if name in bad_names:
                flagged += 1
                self.report("HIGH", check, f"Driver name matches a known-bad signature: {path}")
            if not path.lower().startswith(trusted):
                flagged += 1
                self.report("MEDIUM", check, f"Driver loaded from outside System32: {path}")
            if bad_hashes and os.path.exists(path):
                try:
                    if sha256_file(path) in bad_hashes:
                        flagged += 1
                        self.report("HIGH", check, f"Driver hash matches a known-bad signature: {path}")
                except OSError:
                    pass
        if checked == 0:
            self.report("MEDIUM", check, "Driver addresses are hidden from this account (run as administrator)")
        elif not flagged:
            self.report("OK", check, f"{checked} drivers checked, none suspicious")

    # Behaviour: heavy CPU use, programs in odd folders, their network connections
    def check_behaviour(self):
        """Look for processes with sustained high CPU or running from user-writable folders."""
        check = "Behaviour"
        self.log("INFO", f"--- {check} ---")
        procs = list(psutil.process_iter(["pid", "name", "exe"]))
        for proc in procs:
            try:
                proc.cpu_percent(None)
            except psutil.Error:
                pass
        total = psutil.cpu_percent(interval=2)
        cores = psutil.cpu_count() or 1
        self.log("INFO", f"[{check}] Total CPU usage: {total:.1f}%")

        flagged = 0
        odd_location = {}
        for proc in procs:
            try:
                usage = proc.cpu_percent(None) / cores
                name, exe = proc.info["name"], proc.info["exe"] or ""
            except psutil.Error:
                continue
            if usage >= CPU_THRESHOLD and proc.pid != 0:
                flagged += 1
                self.report("MEDIUM", check, f"High CPU: {name} (PID {proc.pid}) at {usage:.0f}% of total")
            if exe and in_user_writable_folder(exe) and "\\appdata\\local\\programs\\" not in exe.lower():
                odd_location[proc.pid] = f"{name} ({exe})"

        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.Error, OSError):
            connections = []
        connected = {}
        for conn in connections:
            if conn.pid in odd_location and conn.raddr and conn.status == psutil.CONN_ESTABLISHED:
                connected.setdefault(conn.pid, set()).add(f"{conn.raddr.ip}:{conn.raddr.port}")

        for pid, desc in odd_location.items():
            if pid in connected:
                flagged += 1
                self.report("MEDIUM", check, f"Process in a user-writable folder with network connections: "
                                             f"{desc} -> {', '.join(sorted(connected[pid]))}")
            else:
                self.log("INFO", f"[{check}] Running from a user-writable folder: {desc}")
        if not flagged:
            self.report("OK", check, "No anomalous behaviour found")

    def full_scan(self):
        """Run every check in order and return the findings."""
        self.findings = []
        if not is_admin():
            self.log("MEDIUM", "Not running as administrator: some checks will see less.")
        for step in (self.check_hidden_processes, self.check_critical_files, self.check_services,
                     self.check_autostart, self.check_drivers, self.check_behaviour):
            try:
                step()
            except Exception as error:  # one failing check should not stop the scan
                self.report("MEDIUM", step.__name__, f"Check failed: {error}")
        self.log("INFO", "--- Scan complete ---")
        return self.findings


def write_report(findings, log_lines):
    """Save a timestamped text report and return its path."""
    REPORTS_DIR.mkdir(exist_ok=True)
    path = REPORTS_DIR / f"report_{datetime.now():%Y%m%d_%H%M%S}.txt"
    counts = {level: sum(1 for f in findings if f[0] == level) for level in ("HIGH", "MEDIUM", "OK", "INFO")}
    with open(path, "w", encoding="utf-8") as f:
        f.write("RootGuard scan report\n")
        f.write(f"Host: {os.environ.get('COMPUTERNAME', 'unknown')} | Time: {datetime.now():%Y-%m-%d %H:%M:%S} | "
                f"Administrator: {is_admin()}\n")
        f.write(f"Summary: {counts['HIGH']} high, {counts['MEDIUM']} medium\n\n")
        f.write("FINDINGS\n")
        for level, check, message in sorted(findings, key=lambda x: ("HIGH", "MEDIUM", "OK", "INFO").index(x[0])):
            f.write(f"[{level}] {check}: {message}\n")
        f.write("\nFULL LOG\n")
        f.write("\n".join(log_lines) + "\n")
    return path


def notify(title, message):
    """Show a desktop notification if plyer is installed."""
    try:
        from plyer import notification
        notification.notify(title=title, message=message[:250], timeout=8)
    except Exception:
        pass


# GUI

def run_gui():
    """Start the Tkinter interface."""
    import tkinter as tk
    from tkinter import messagebox, scrolledtext

    root = tk.Tk()
    root.title("RootGuard - Rootkit Detection")
    root.geometry("980x640")

    messages = queue.Queue()
    log_lines = []
    scanner = Scanner(lambda level, msg: messages.put((level, msg)))
    state = {"busy": False, "report": None}

    output = scrolledtext.ScrolledText(root, font=("Consolas", 10), state="disabled")
    output.pack(fill="both", expand=True, padx=8, pady=(8, 4))
    for level, colour in (("HIGH", "#c62828"), ("MEDIUM", "#ef6c00"), ("OK", "#2e7d32"), ("INFO", "#333333")):
        output.tag_config(level, foreground=colour)

    status = tk.StringVar(value="Ready" + ("" if is_admin() else " (not administrator: run as admin for full results)"))
    tk.Label(root, textvariable=status, anchor="w").pack(fill="x", padx=8)

    buttons = tk.Frame(root)
    buttons.pack(fill="x", padx=8, pady=8)
    all_buttons = []

    def drain_queue():
        """Move log messages from worker threads into the text box (Tkinter is not thread-safe)."""
        while not messages.empty():
            level, msg = messages.get()
            line = f"{datetime.now():%H:%M:%S} [{level}] {msg}"
            log_lines.append(line)
            output.configure(state="normal")
            output.insert("end", line + "\n", level)
            output.see("end")
            output.configure(state="disabled")
        root.after(100, drain_queue)

    def run_in_thread(task, label):
        """Run a check in a background thread so the window stays responsive."""
        if state["busy"]:
            return

        def worker():
            try:
                task()
            except Exception as error:
                messages.put(("MEDIUM", f"{label} failed: {error}"))
            finally:
                root.after(0, finished)

        def finished():
            state["busy"] = False
            for b in all_buttons:
                b.configure(state="normal")
            high = [f for f in scanner.findings if f[0] == "HIGH"]
            status.set(f"{label} finished: {len(high)} high, "
                       f"{sum(1 for f in scanner.findings if f[0] == 'MEDIUM')} medium findings")
            if high:
                notify("RootGuard: suspicious findings", high[0][2])

        state["busy"] = True
        scanner.findings = []
        for b in all_buttons:
            b.configure(state="disabled")
        status.set(f"Running: {label}...")
        threading.Thread(target=worker, daemon=True).start()

    def create_report():
        state["report"] = write_report(scanner.findings, log_lines)
        messagebox.showinfo("Report", f"Report created:\n{state['report']}")

    def view_report():
        if state["report"] and Path(state["report"]).exists():
            os.startfile(state["report"])
        else:
            messagebox.showwarning("Report", "Create a report first.")

    actions = [
        ("Full scan", lambda: run_in_thread(scanner.full_scan, "Full scan")),
        ("Hidden processes", lambda: run_in_thread(scanner.check_hidden_processes, "Hidden processes")),
        ("System files", lambda: run_in_thread(scanner.check_critical_files, "System files")),
        ("Services", lambda: run_in_thread(scanner.check_services, "Services")),
        ("Autostart", lambda: run_in_thread(scanner.check_autostart, "Autostart")),
        ("Drivers", lambda: run_in_thread(scanner.check_drivers, "Drivers")),
        ("Behaviour", lambda: run_in_thread(scanner.check_behaviour, "Behaviour")),
        ("Rebuild baseline", lambda: run_in_thread(lambda: scanner.check_critical_files(rebuild=True), "Baseline")),
        ("Create report", create_report),
        ("View report", view_report),
    ]
    for label, command in actions:
        button = tk.Button(buttons, text=label, command=command, padx=6)
        button.pack(side="left", padx=2)
        all_buttons.append(button)

    drain_queue()
    root.mainloop()


# Command line

def run_cli(rebuild_baseline=False):
    """Run a full scan in the terminal and save a report."""
    log_lines = []

    def log(level, msg):
        line = f"{datetime.now():%H:%M:%S} [{level}] {msg}"
        log_lines.append(line)
        print(line, flush=True)

    scanner = Scanner(log)
    if rebuild_baseline:
        scanner.check_critical_files(rebuild=True)
        return 0
    findings = scanner.full_scan()
    path = write_report(findings, log_lines)
    high = sum(1 for f in findings if f[0] == "HIGH")
    print(f"\nReport saved to {path}")
    return 1 if high else 0


def main():
    parser = argparse.ArgumentParser(description="RootGuard rootkit detection tool for Windows")
    parser.add_argument("--cli", action="store_true", help="run a full scan in the terminal")
    parser.add_argument("--baseline", action="store_true", help="(re)create the system file baseline")
    args = parser.parse_args()

    if not IS_WINDOWS:
        sys.exit("RootGuard checks Windows internals and must be run on Windows.")
    if args.cli or args.baseline:
        sys.exit(run_cli(rebuild_baseline=args.baseline))
    run_gui()


if __name__ == "__main__":
    main()
