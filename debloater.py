"""
Windows 10 Debloat Tool v2 2026 update

Fő változások az eredetihez képest:
  * PowerShell helyett közvetlenül a Python winreg moduljával dolgozik (gyorsabb, megbízhatóbb)
  * Admin jogot ellenőriz, és szükség esetén UAC-val újraindítja magát
  * Minden módosítás előtt elmenti az eredeti értékeket -> bármelyik tweak VISSZAVONHATÓ
  * Opcionális rendszer-visszaállítási pont létrehozása
  * Több tweak egyszerre kiválasztható, a GUI nem fagy le (háttérszál), van naplóablak
  * Adatvezérelt felépítés: új tweak hozzáadása egyetlen listaelem
"""

import ctypes
import json
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
import winreg
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText

APP_NAME = "Windows Debloat Tool"
BACKUP_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "DebloatTool")
BACKUP_FILE = os.path.join(BACKUP_DIR, "backup.json")
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

HIVES = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
WOW64 = winreg.KEY_WOW64_64KEY

# ----------------------------------------------------------------------------
# Tweak definíciók
# ----------------------------------------------------------------------------
CV = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
POL = r"SOFTWARE\Policies\Microsoft\Windows"
CDM = CV + r"\ContentDeliveryManager"
NS_3D = r"\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"


def dw(hive, path, name, value):
    """DWORD érték beállítása."""
    return ("value", hive, path, name, winreg.REG_DWORD, value)


def delkey(hive, path):
    """Registry kulcs törlése (visszaállításhoz elmentjük az értékeit)."""
    return ("key", hive, path, None, None, None)


TWEAKS = [
    # ---------------- Adatvédelem ----------------
    {
        "id": "telemetry", "cat": "Adatvédelem", "default": True,
        "name": "Telemetria kikapcsolása",
        "desc": "Minimálisra állítja az adatgyűjtést, kikapcsolja a visszajelzési értesítéseket.",
        "ops": [
            dw("HKLM", POL + r"\DataCollection", "AllowTelemetry", 0),
            dw("HKLM", POL + r"\DataCollection", "DoNotShowFeedbackNotifications", 1),
            dw("HKLM", CV + r"\Policies\DataCollection", "AllowTelemetry", 0),
            dw("HKLM", r"SOFTWARE\Wow6432Node" + CV[len("SOFTWARE"):] + r"\Policies\DataCollection", "AllowTelemetry", 0),
        ],
    },
    {
        "id": "advertising", "cat": "Adatvédelem", "default": True,
        "name": "Hirdetési azonosító letiltása",
        "desc": "Az alkalmazások nem követhetnek a hirdetési azonosítóddal.",
        "ops": [
            dw("HKCU", CV + r"\AdvertisingInfo", "Enabled", 0),
            dw("HKLM", CV + r"\AdvertisingInfo", "Enabled", 0),
            dw("HKLM", POL + r"\AdvertisingInfo", "DisabledByGroupPolicy", 1),
        ],
    },
    {
        "id": "feedback", "cat": "Adatvédelem", "default": True,
        "name": "Visszajelzés-kérések kikapcsolása",
        "desc": "A Windows nem kér többé visszajelzést.",
        "ops": [
            dw("HKCU", r"SOFTWARE\Microsoft\Siuf\Rules", "PeriodInNanoSeconds", 0),
            dw("HKCU", r"SOFTWARE\Microsoft\Siuf\Rules", "NumberOfSIUFInPeriod", 0),
        ],
    },
    {
        "id": "websearch", "cat": "Adatvédelem", "default": True,
        "name": "Webes (Bing) keresés a Start menüben",
        "desc": "A Start menü keresője csak a gépen keres, nem küld le semmit a Bingnek.",
        "ops": [
            dw("HKCU", CV + r"\Search", "BingSearchEnabled", 0),
            dw("HKLM", POL + r"\Windows Search", "DisableWebSearch", 1),
            dw("HKLM", POL + r"\Windows Search", "ConnectedSearchUseWeb", 0),
        ],
    },
    {
        "id": "cortana", "cat": "Adatvédelem", "default": True,
        "name": "Cortana és beviteli személyre szabás letiltása",
        "desc": "Letiltja a Cortanát, a gépelési/kézírási minták és a névjegyek gyűjtését.",
        "ops": [
            dw("HKLM", POL + r"\Windows Search", "AllowCortana", 0),
            dw("HKCU", r"SOFTWARE\Microsoft\Personalization\Settings", "AcceptedPrivacyPolicy", 0),
            dw("HKCU", r"SOFTWARE\Microsoft\InputPersonalization", "RestrictImplicitTextCollection", 1),
            dw("HKCU", r"SOFTWARE\Microsoft\InputPersonalization", "RestrictImplicitInkCollection", 1),
            dw("HKCU", r"SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore", "HarvestContacts", 0),
        ],
    },
    {
        "id": "wifisense", "cat": "Adatvédelem", "default": True,
        "name": "Wi-Fi Sense letiltása",
        "desc": "Nem csatlakozik automatikusan megosztott hotspotokhoz.",
        "ops": [
            dw("HKLM", r"SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting", "Value", 0),
            dw("HKLM", r"SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots", "Value", 0),
            dw("HKLM", r"SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config", "AutoConnectAllowedOEM", 0),
        ],
    },
    {
        "id": "location", "cat": "Adatvédelem", "default": False,
        "name": "Helymeghatározás kikapcsolása",
        "desc": "Figyelem: a Térkép, Időjárás és hasonló alkalmazások nem fognak helyet kapni.",
        "ops": [
            dw("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}", "SensorPermissionState", 0),
            dw("HKLM", r"SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration", "Status", 0),
        ],
    },
    {
        "id": "telemetry_services", "cat": "Adatvédelem", "default": False,
        "name": "Telemetria-szolgáltatások letiltása (DiagTrack, dmwappushservice)",
        "desc": "Leállítja és letiltja a két szolgáltatást. Vállalati (MDM) környezetben ne használd.",
        "stop": ["DiagTrack", "dmwappushservice"],
        "ops": [
            dw("HKLM", r"SYSTEM\CurrentControlSet\Services\DiagTrack", "Start", 4),
            dw("HKLM", r"SYSTEM\CurrentControlSet\Services\dmwappushservice", "Start", 4),
        ],
    },
    # ---------------- Felesleges tartalmak ----------------
    {
        "id": "consumer", "cat": "Felesleges tartalmak", "default": True,
        "name": "Ajánlott alkalmazások és reklámok tiltása",
        "desc": "Nincs automatikus telepítés (Candy Crush stb.), nincsenek Start menü javaslatok.",
        "ops": [
            dw("HKLM", POL + r"\CloudContent", "DisableWindowsConsumerFeatures", 1),
            dw("HKCU", CDM, "ContentDeliveryAllowed", 0),
            dw("HKCU", CDM, "OemPreInstalledAppsEnabled", 0),
            dw("HKCU", CDM, "PreInstalledAppsEnabled", 0),
            dw("HKCU", CDM, "PreInstalledAppsEverEnabled", 0),
            dw("HKCU", CDM, "SilentInstalledAppsEnabled", 0),
            dw("HKCU", CDM, "SystemPaneSuggestionsEnabled", 0),
            dw("HKCU", CDM, "SoftLandingEnabled", 0),
            dw("HKCU", CDM, "SubscribedContent-338388Enabled", 0),
            dw("HKCU", CDM, "SubscribedContent-338389Enabled", 0),
            dw("HKCU", CDM, "SubscribedContent-310093Enabled", 0),
        ],
    },
    {
        "id": "livetiles", "cat": "Felesleges tartalmak", "default": True,
        "name": "Élő csempe értesítések kikapcsolása",
        "desc": "A Start menü csempéi nem töltenek le hálózati tartalmat.",
        "ops": [dw("HKCU", r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications", "NoTileApplicationNotification", 1)],
    },
    {
        "id": "people", "cat": "Felesleges tartalmak", "default": True,
        "name": "Névjegyek (People) sáv eltávolítása",
        "desc": "Eltünteti a People ikont a tálcáról.",
        "ops": [dw("HKCU", CV + r"\Explorer\Advanced\People", "PeopleBand", 0)],
    },
    {
        "id": "edge", "cat": "Felesleges tartalmak", "default": True,
        "name": "Edge háttérfutásának és előbetöltésének tiltása",
        "desc": "Az Edge nem indul el a háttérben és nem tölt be előre a rendszerindításkor.",
        "ops": [
            dw("HKLM", r"SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main", "AllowPrelaunch", 0),
            dw("HKLM", r"SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader", "AllowTabPreloading", 0),
            dw("HKLM", r"SOFTWARE\Policies\Microsoft\Edge", "BackgroundModeEnabled", 0),
            dw("HKLM", r"SOFTWARE\Policies\Microsoft\Edge", "StartupBoostEnabled", 0),
        ],
    },
    {
        "id": "3dobjects", "cat": "Felesleges tartalmak", "default": True,
        "name": "3D Objects mappa eltávolítása a Gépből",
        "desc": "Eltünteti a 3D Objects mappát a Intéző „Ez a gép” nézetéből.",
        "ops": [
            delkey("HKLM", CV + NS_3D),
            delkey("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion" + NS_3D),
        ],
    },
]

# ----------------------------------------------------------------------------
# Registry segédfüggvények
# ----------------------------------------------------------------------------


def _enc(value, rtype):
    return value.hex() if rtype == winreg.REG_BINARY and isinstance(value, bytes) else value


def _dec(value, rtype):
    return bytes.fromhex(value) if rtype == winreg.REG_BINARY and isinstance(value, str) else value


def read_value(hive, path, name):
    try:
        with winreg.OpenKey(HIVES[hive], path, 0, winreg.KEY_READ | WOW64) as k:
            val, typ = winreg.QueryValueEx(k, name)
            return {"existed": True, "type": typ, "value": _enc(val, typ)}
    except FileNotFoundError:
        return {"existed": False}


def write_value(hive, path, name, rtype, value):
    with winreg.CreateKeyEx(HIVES[hive], path, 0, winreg.KEY_SET_VALUE | WOW64) as k:
        winreg.SetValueEx(k, name, 0, rtype, _dec(value, rtype))


def delete_value(hive, path, name):
    try:
        with winreg.OpenKey(HIVES[hive], path, 0, winreg.KEY_SET_VALUE | WOW64) as k:
            winreg.DeleteValue(k, name)
    except FileNotFoundError:
        pass


def snapshot_key(hive, path):
    try:
        with winreg.OpenKey(HIVES[hive], path, 0, winreg.KEY_READ | WOW64) as k:
            values, i = [], 0
            while True:
                try:
                    n, v, t = winreg.EnumValue(k, i)
                except OSError:
                    break
                values.append({"name": n, "type": t, "value": _enc(v, t)})
                i += 1
            return {"existed": True, "values": values}
    except FileNotFoundError:
        return {"existed": False}


def restore_key(hive, path, snap):
    if not snap.get("existed"):
        return
    with winreg.CreateKeyEx(HIVES[hive], path, 0, winreg.KEY_SET_VALUE | WOW64) as k:
        for v in snap["values"]:
            winreg.SetValueEx(k, v["name"], 0, v["type"], _dec(v["value"], v["type"]))


def delete_key(hive, path):
    try:
        winreg.DeleteKeyEx(HIVES[hive], path, WOW64, 0)
    except FileNotFoundError:
        pass


# ----------------------------------------------------------------------------
# Mentés / alkalmazás / visszavonás
# ----------------------------------------------------------------------------


def load_backup():
    try:
        with open(BACKUP_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_backup(backup):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    with open(BACKUP_FILE, "w", encoding="utf-8") as f:
        json.dump(backup, f, indent=2)


def apply_tweak(tweak, backup):
    # Az ELSŐ (eredeti) állapotot őrizzük meg: ha már van mentés, nem írjuk felül.
    if tweak["id"] not in backup:
        snaps = []
        for kind, hive, path, name, rtype, value in tweak["ops"]:
            snap = read_value(hive, path, name) if kind == "value" else snapshot_key(hive, path)
            snaps.append({"kind": kind, "hive": hive, "path": path, "name": name, "snap": snap})
        backup[tweak["id"]] = snaps
        save_backup(backup)  # előbb mentünk, hogy félbeszakadt futás is visszavonható legyen

    for kind, hive, path, name, rtype, value in tweak["ops"]:
        if kind == "value":
            write_value(hive, path, name, rtype, value)
        else:
            delete_key(hive, path)

    for svc in tweak.get("stop", []):
        subprocess.run(["sc", "stop", svc], capture_output=True, creationflags=NO_WINDOW)


def revert_tweak(tweak, backup):
    snaps = backup.get(tweak["id"])
    if not snaps:
        return False
    for e in reversed(snaps):
        if e["kind"] == "value":
            s = e["snap"]
            if s["existed"]:
                write_value(e["hive"], e["path"], e["name"], s["type"], s["value"])
            else:
                delete_value(e["hive"], e["path"], e["name"])
        else:
            restore_key(e["hive"], e["path"], e["snap"])
    del backup[tweak["id"]]
    save_backup(backup)
    return True


def create_restore_point(log):
    log("Visszaállítási pont létrehozása...")
    cmd = ('Checkpoint-Computer -Description "Debloat Tool" '
           '-RestorePointType MODIFY_SETTINGS -ErrorAction Stop')
    r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
                       capture_output=True, text=True, creationflags=NO_WINDOW)
    if r.returncode == 0:
        log("[OK] Visszaállítási pont létrehozva.")
    else:
        err = (r.stderr or r.stdout).strip().splitlines()
        log("[FIGYELEM] Nem sikerült visszaállítási pontot létrehozni "
            "(Rendszervédelem kikapcsolva, vagy 24 órán belül már készült egy).")
        if err:
            log("          " + err[0][:150])


# ----------------------------------------------------------------------------
# Rendszergazdai jog
# ----------------------------------------------------------------------------


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    if getattr(sys, "frozen", False):
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
    else:
        params = " ".join(f'"{a}"' for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)


# ----------------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------------


class App:
    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self.busy = False
        self.vars = {}

        root.title(APP_NAME)
        root.geometry("780x800")
        root.minsize(660, 600)
        try:
            icon = os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))), "logo.ico")
            root.iconbitmap(icon)
        except Exception:
            pass  # ikon nélkül is működik

        ttk.Label(root, text=APP_NAME, font=("Segoe UI", 16, "bold")).pack(anchor="w", padx=14, pady=(12, 0))
        ttk.Label(root, foreground="#666",
                  text="Jelöld be a kívánt módosításokat. Minden módosítás visszavonható.").pack(anchor="w", padx=14)

        self._build_tweak_list()
        self._build_buttons()
        self._build_log()
        self.root.after(100, self._poll)

    # --- felépítés ---
    def _build_tweak_list(self):
        outer = ttk.Frame(self.root)
        outer.pack(fill="both", expand=True, padx=14, pady=8)
        canvas = tk.Canvas(outer, highlightthickness=0)
        sb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)
        win = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(win, width=e.width))
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-e.delta / 120), "units"))
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        cats = {}
        for t in TWEAKS:
            if t["cat"] not in cats:
                cats[t["cat"]] = ttk.LabelFrame(inner, text=t["cat"], padding=(10, 4))
                cats[t["cat"]].pack(fill="x", pady=5)
            var = tk.BooleanVar(value=t["default"])
            self.vars[t["id"]] = var
            ttk.Checkbutton(cats[t["cat"]], text=t["name"], variable=var).pack(anchor="w", pady=(4, 0))
            ttk.Label(cats[t["cat"]], text=t["desc"], foreground="#777", wraplength=640,
                      justify="left").pack(anchor="w", padx=(24, 0))

    def _build_buttons(self):
        bar = ttk.Frame(self.root)
        bar.pack(fill="x", padx=14)
        self.rp_var = tk.BooleanVar(value=True)
        self.btns = [
            ttk.Button(bar, text="Mind", command=lambda: self._set_all(True)),
            ttk.Button(bar, text="Egyik sem", command=lambda: self._set_all(False)),
        ]
        for b in self.btns:
            b.pack(side="left", padx=(0, 6))
        ttk.Checkbutton(bar, text="Visszaállítási pont", variable=self.rp_var).pack(side="left", padx=10)
        self.apply_btn = ttk.Button(bar, text="Alkalmaz", command=self.on_apply)
        self.revert_btn = ttk.Button(bar, text="Visszavonás", command=self.on_revert)
        self.revert_btn.pack(side="right")
        self.apply_btn.pack(side="right", padx=6)
        self.btns += [self.apply_btn, self.revert_btn]
        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill="x", padx=14, pady=(8, 0))

    def _build_log(self):
        self.logbox = ScrolledText(self.root, height=9, state="disabled", font=("Consolas", 9))
        self.logbox.pack(fill="x", padx=14, pady=10)

    # --- segédek ---
    def _set_all(self, value):
        for v in self.vars.values():
            v.set(value)

    def _selected(self):
        return [t for t in TWEAKS if self.vars[t["id"]].get()]

    def log(self, msg):
        self.q.put(("log", msg))

    def _poll(self):
        try:
            while True:
                kind, msg = self.q.get_nowait()
                if kind == "log":
                    self.logbox.configure(state="normal")
                    self.logbox.insert("end", msg + "\n")
                    self.logbox.see("end")
                    self.logbox.configure(state="disabled")
                elif kind == "done":
                    self.busy = False
                    self.progress.stop()
                    for b in self.btns:
                        b.state(["!disabled"])
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def _run_async(self, fn, *args):
        if self.busy:
            return
        self.busy = True
        self.progress.start(12)
        for b in self.btns:
            b.state(["disabled"])

        def work():
            try:
                fn(*args)
            except Exception as e:  # noqa: BLE001
                self.log(f"[HIBA] Váratlan hiba: {e}")
            finally:
                self.q.put(("done", None))

        threading.Thread(target=work, daemon=True).start()

    # --- műveletek ---
    def on_apply(self):
        sel = self._selected()
        if not sel:
            messagebox.showinfo(APP_NAME, "Nincs kijelölt módosítás.")
            return
        if not messagebox.askyesno(APP_NAME, f"{len(sel)} módosítás alkalmazása. Folytatod?"):
            return
        self._run_async(self._do_apply, sel, self.rp_var.get())

    def _do_apply(self, sel, make_rp):
        if make_rp:
            create_restore_point(self.log)
        backup = load_backup()
        ok = fail = 0
        for t in sel:
            try:
                apply_tweak(t, backup)
                ok += 1
                self.log(f"[OK] {t['name']}")
            except PermissionError:
                fail += 1
                self.log(f"[HIBA] {t['name']}: hozzáférés megtagadva (védett kulcs)")
            except Exception as e:  # noqa: BLE001
                fail += 1
                self.log(f"[HIBA] {t['name']}: {e}")
        self.log(f"--- Kész: {ok} sikeres, {fail} sikertelen. Egyes változások kijelentkezés/újraindítás után lépnek életbe. ---")

    def on_revert(self):
        sel = self._selected()
        if not sel:
            messagebox.showinfo(APP_NAME, "Nincs kijelölt módosítás.")
            return
        if not messagebox.askyesno(APP_NAME, f"{len(sel)} módosítás visszavonása az elmentett eredeti értékekre. Folytatod?"):
            return
        self._run_async(self._do_revert, sel)

    def _do_revert(self, sel):
        backup = load_backup()
        ok = skipped = 0
        for t in sel:
            try:
                if revert_tweak(t, backup):
                    ok += 1
                    self.log(f"[VISSZAVONVA] {t['name']}")
                else:
                    skipped += 1
                    self.log(f"[KIHAGYVA] {t['name']}: nincs mentett állapot (nem lett alkalmazva)")
            except Exception as e:  # noqa: BLE001
                self.log(f"[HIBA] {t['name']}: {e}")
        self.log(f"--- Kész: {ok} visszavonva, {skipped} kihagyva. ---")


def main():
    if os.name != "nt":
        print("Ez az eszköz csak Windows alatt fut.")
        return
    if not is_admin():
        relaunch_as_admin()
        return
    root = tk.Tk()
    try:
        ttk.Style().theme_use("vista")
    except tk.TclError:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
