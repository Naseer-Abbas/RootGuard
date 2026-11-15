# RootGuard

A Python rootkit and persistence detection tool for Windows, with a Tkinter GUI and a command-line mode. It looks for the techniques rootkits and other malware use to hide and survive reboots, and writes a timestamped report.

## Checks

| Check | What it does |
|---|---|
| **Hidden processes** | Cross-view detection: compares the normal process list with brute-force probing of every process ID through the Windows API (`OpenProcess` via `ctypes`). A process that exists but is missing from the list is a classic sign of a user-mode rootkit. |
| **System files** | Hashes critical binaries (`lsass.exe`, `svchost.exe`, `ntoskrnl.exe` and others) with SHA-256, compares them with a saved baseline, and checks their Authenticode signatures. |
| **Services** | Flags services whose binary is in a user-writable folder, is missing, or uses an unquoted path with spaces (a known privilege-escalation weakness). |
| **Autostart** | Reviews `Run`/`RunOnce` registry keys and Startup folders, flagging encoded PowerShell, `mshta`, `wscript`, `certutil` downloads, programs in user-writable folders and missing targets. |
| **Drivers** | Lists loaded kernel drivers (`EnumDeviceDrivers`), flags drivers loaded from outside `System32`, and matches names and SHA-256 hashes against `signatures.json`. |
| **Behaviour** | Flags processes with sustained high CPU use, and processes running from user-writable folders, especially those with active network connections. |

Findings are rated **HIGH**, **MEDIUM**, **OK** or **INFO**.

## Requirements

- Windows 10 or 11
- Python 3.8+
- `psutil` (required) and `plyer` (optional, for desktop notifications)

```
pip install -r requirements.txt
```

## Usage

Run from an **administrator** terminal for full results:

```
python rootguard.py              # GUI
python rootguard.py --cli        # full scan in the terminal (exit code 1 if HIGH findings)
python rootguard.py --baseline   # rebuild the system file baseline
```

The first scan saves `baseline.json` with the hashes of the critical system files. Later scans compare against it. Windows updates legitimately change these files, so rebuild the baseline after updating.

### GUI

- Run each check on its own or as a full scan
- Colour-coded live log; the window stays responsive because checks run in background threads
- Create a report and open it in your default text editor
- Desktop notification when HIGH findings appear

### Reports

Saved to `reports/report_YYYYMMDD_HHMMSS.txt`, with a summary, findings sorted by severity and the full scan log.

## Signatures

`signatures.json` holds known-bad driver file names and SHA-256 hashes. It ships empty; add entries from threat intelligence sources such as [LOLDrivers](https://www.loldrivers.io/) or MalwareBazaar.

```json
{
  "driver_names": ["example_bad_driver.sys"],
  "sha256": ["<sha256 of a known malicious driver>"]
}
```

## Limitations

- A kernel-mode rootkit can hide from every tool running inside the infected system, including this one. For a suspected kernel rootkit, analyse a memory image offline (for example with Volatility) or boot from trusted media.
- Path- and keyword-based rules can produce false positives (some legitimate software runs from `AppData`) and miss well-disguised malware.
- Covers the most common autostart locations, not all of them (scheduled tasks, WMI subscriptions and others are not yet checked).

## Future improvements

- Scheduled task and WMI persistence checks
- Export reports as HTML or JSON
- Compare results with an offline memory analysis

This project was built for learning. Test it in a lab VM before relying on it.
