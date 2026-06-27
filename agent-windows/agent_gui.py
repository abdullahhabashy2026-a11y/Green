from __future__ import annotations

import getpass
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Any

import pystray
import requests
from dns_filter import DNSFilterServer, DomainDecision
from PIL import Image, ImageDraw


APP_VERSION = "0.1.0"
BUILD_NAME = "GreenAgentIPv6Fix"
DEFAULT_SERVER_URL = "http://127.0.0.1:8000"
DEFAULT_INTERVAL_SECONDS = 60
BLOCKLIST_REFRESH_SECONDS = 300
DOMAIN_CHECK_CACHE_SECONDS = 600
LOCAL_BLOCKLIST_CATEGORIES = ("adult", "social", "custom")
LOCAL_BLOCKLIST_CACHE: tuple[dict[str, str], list[str]] | None = None
PROTECTED_BLOCKLIST_PERMISSIONS_APPLIED = False


def config_path() -> Path:
    appdata = os.getenv("APPDATA")
    if appdata:
        config_dir = Path(appdata) / "Green"
    else:
        config_dir = Path.home() / ".green"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "agent.config.json"


def load_config() -> dict[str, Any]:
    path = config_path()
    if not path.exists():
        return {
            "server_url": DEFAULT_SERVER_URL,
            "interval_seconds": DEFAULT_INTERVAL_SECONDS,
        }

    with path.open("r", encoding="utf-8") as config_file:
        config = json.load(config_file)

    config.setdefault("server_url", DEFAULT_SERVER_URL)
    config.setdefault("interval_seconds", DEFAULT_INTERVAL_SECONDS)
    return config


def save_config(config: dict[str, Any]) -> None:
    with config_path().open("w", encoding="utf-8") as config_file:
        json.dump(config, config_file, indent=2)


def resource_dir() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent


def protected_blocklist_dir() -> Path | None:
    program_data = os.getenv("PROGRAMDATA")
    if not program_data:
        return None
    return Path(program_data) / "Green" / "blocklists"


def bundled_blocklist_dir() -> Path:
    return resource_dir() / "blocklists"


def development_blocklist_dir() -> Path:
    return resource_dir().parent / "server" / "blocklists"


def bundled_blocklist_paths() -> list[tuple[Path, str]]:
    paths: list[tuple[Path, str]] = []
    for blocklist_dir in (bundled_blocklist_dir(), development_blocklist_dir()):
        for category in LOCAL_BLOCKLIST_CATEGORIES:
            path = blocklist_dir / f"{category}.txt"
            if path.exists() and (path, category) not in paths:
                paths.append((path, category))
        if paths:
            return paths
    return paths


def apply_protected_blocklist_permissions(blocklist_dir: Path) -> None:
    global PROTECTED_BLOCKLIST_PERMISSIONS_APPLIED
    if PROTECTED_BLOCKLIST_PERMISSIONS_APPLIED or os.name != "nt":
        return

    try:
        subprocess.run(
            [
                "icacls",
                str(blocklist_dir),
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
                "*S-1-5-32-545:(OI)(CI)RX",
                "/C",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        )
        for blocklist_file in blocklist_dir.glob("*.txt"):
            subprocess.run(
                [
                    "icacls",
                    str(blocklist_file),
                    "/inheritance:r",
                    "/grant:r",
                    "*S-1-5-18:F",
                    "*S-1-5-32-544:F",
                    "*S-1-5-32-545:R",
                    "/C",
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=True,
            )
        PROTECTED_BLOCKLIST_PERMISSIONS_APPLIED = True
    except Exception:
        pass


def ensure_protected_blocklists() -> Path | None:
    blocklist_dir = protected_blocklist_dir()
    if blocklist_dir is None:
        return None

    source_paths = bundled_blocklist_paths()
    if not source_paths:
        return blocklist_dir if blocklist_dir.exists() else None

    try:
        blocklist_dir.mkdir(parents=True, exist_ok=True)
        for source_path, category in source_paths:
            target_path = blocklist_dir / f"{category}.txt"
            should_copy = not target_path.exists()
            if not should_copy:
                try:
                    should_copy = target_path.stat().st_size != source_path.stat().st_size
                except OSError:
                    should_copy = True
            if should_copy:
                shutil.copyfile(source_path, target_path)

        apply_protected_blocklist_permissions(blocklist_dir)
        return blocklist_dir
    except OSError:
        return None


def normalize_local_domain(domain: str) -> str:
    value = domain.strip().lower().rstrip(".")
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if value.startswith("www."):
        value = value[4:]
    return value


def is_local_domain(value: str) -> bool:
    if not value or len(value) > 255 or "." not in value:
        return False
    labels = value.split(".")
    return all(label and all(char.isalnum() or char == "-" for char in label) for label in labels)


def local_blocklist_paths() -> list[tuple[Path, str]]:
    protected_dir = ensure_protected_blocklists()
    candidate_dirs = [protected_dir] if protected_dir is not None else []
    candidate_dirs.extend([bundled_blocklist_dir(), development_blocklist_dir()])

    paths: list[tuple[Path, str]] = []
    for blocklist_dir in candidate_dirs:
        for category in LOCAL_BLOCKLIST_CATEGORIES:
            path = blocklist_dir / f"{category}.txt"
            if path.exists() and (path, category) not in paths:
                paths.append((path, category))
    return paths


def parse_local_blocklist_line(line: str) -> str:
    value = line.strip()
    if not value or value.startswith(("#", "!", "[", "@@")):
        return ""

    if value.startswith("||"):
        value = value[2:].split("^", 1)[0].split("$", 1)[0]
    elif value.startswith("|"):
        value = value.lstrip("|").split("^", 1)[0].split("$", 1)[0]
    else:
        parts = [part for part in value.replace("\t", " ").split(" ") if part]
        if len(parts) >= 2 and parts[0] in {"0.0.0.0", "127.0.0.1", "::", "::1"}:
            value = parts[1]
        elif parts:
            value = parts[0]

    if value.startswith("*."):
        value = value[2:]
    return normalize_local_domain(value.strip().strip("|").strip("^"))


def load_local_blocklist() -> tuple[dict[str, str], list[str]]:
    global LOCAL_BLOCKLIST_CACHE
    if LOCAL_BLOCKLIST_CACHE is not None:
        return LOCAL_BLOCKLIST_CACHE

    domains: dict[str, str] = {}
    for path, category in local_blocklist_paths():
        try:
            with path.open("r", encoding="utf-8", errors="replace") as blocklist_file:
                for line in blocklist_file:
                    domain = parse_local_blocklist_line(line)
                    if is_local_domain(domain):
                        domains[domain] = category
        except OSError:
            continue

    LOCAL_BLOCKLIST_CACHE = (domains, [])
    return LOCAL_BLOCKLIST_CACHE


def device_metadata() -> dict[str, str]:
    return {
        "device_name": socket.gethostname(),
        "windows_user": getpass.getuser(),
        "agent_version": APP_VERSION,
    }


def activate_device(server_url: str, enrollment_token: str) -> dict[str, str]:
    response = requests.post(
        f"{server_url.rstrip('/')}/api/activate",
        json={
            "enrollment_token": enrollment_token.strip(),
            **device_metadata(),
        },
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def send_heartbeat(config: dict[str, Any], status: str = "running", timeout: int = 15) -> None:
    response = requests.post(
        f"{str(config['server_url']).rstrip('/')}/api/heartbeat",
        json={
            "device_id": config["device_id"],
            "token": config["token"],
            **device_metadata(),
            "status": status,
        },
        timeout=timeout,
    )
    response.raise_for_status()


def send_domain_event(config: dict[str, Any], decision: DomainDecision) -> None:
    response = requests.post(
        f"{str(config['server_url']).rstrip('/')}/api/domain-event",
        json={
            "device_id": config["device_id"],
            "token": config["token"],
            "domain": decision.domain,
            "category": decision.category,
            "decision": decision.decision,
            "reason": decision.reason,
        },
        timeout=5,
    )
    response.raise_for_status()


def fetch_blocklist(config: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    response = requests.get(
        f"{str(config['server_url']).rstrip('/')}/api/blocklist",
        params={
            "device_id": config["device_id"],
            "token": config["token"],
        },
        timeout=10,
    )
    response.raise_for_status()
    payload = response.json()
    domains = {
        str(item["domain"]).strip().lower().rstrip("."): str(item["category"]).strip().lower()
        for item in payload.get("blocked_domains", [])
        if item.get("domain") and item.get("category")
    }
    keywords = [
        str(item["keyword"]).strip().lower()
        for item in payload.get("blocked_keywords", [])
        if item.get("keyword")
    ]
    return domains, keywords


def check_domain_policy(config: dict[str, Any], domain: str) -> DomainDecision | None:
    response = requests.post(
        f"{str(config['server_url']).rstrip('/')}/api/domain-check",
        json={
            "device_id": config["device_id"],
            "token": config["token"],
            "domain": domain,
        },
        timeout=3,
    )
    response.raise_for_status()
    payload = response.json()
    return DomainDecision(
        domain=str(payload.get("domain") or domain).strip().lower().rstrip("."),
        category=str(payload.get("category") or "unknown"),
        decision=str(payload.get("decision") or "allowed"),
        reason=str(payload.get("reason") or "Server domain check"),
    )


def is_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def quote_ps(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def run_powershell(command: str) -> str:
    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
    return completed.stdout.strip()


def powershell_json(command: str) -> Any:
    output = run_powershell(f"{command} | ConvertTo-Json -Compress")
    if not output:
        return []
    return json.loads(output)


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def active_dns_interfaces() -> list[str]:
    result = powershell_json(
        "Get-NetIPConfiguration | "
        "Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq 'Up'} | "
        "Select-Object -ExpandProperty InterfaceAlias"
    )
    return [str(item) for item in as_list(result) if str(item).strip()]


def current_dns_servers(interface_alias: str, address_family: str = "IPv4") -> list[str]:
    result = powershell_json(
        f"(Get-DnsClientServerAddress -InterfaceAlias {quote_ps(interface_alias)} "
        f"-AddressFamily {address_family}).ServerAddresses"
    )
    return [str(item) for item in as_list(result) if str(item).strip()]


def set_interface_dns(interface_alias: str, servers: list[str]) -> None:
    if servers:
        server_list = ",".join(quote_ps(server) for server in servers)
        run_powershell(
            f"Set-DnsClientServerAddress -InterfaceAlias {quote_ps(interface_alias)} "
            f"-ServerAddresses @({server_list})"
        )
        return

    run_powershell(
        f"Set-DnsClientServerAddress -InterfaceAlias {quote_ps(interface_alias)} "
        "-ResetServerAddresses"
    )


def restore_dns_from_config(config: dict[str, Any]) -> None:
    previous_dns_v4 = config.get("dns_previous_v4") or config.get("dns_previous", {})
    previous_dns_v6 = config.get("dns_previous_v6", {})
    if previous_dns_v4 or previous_dns_v6:
        interfaces = set(previous_dns_v4) | set(previous_dns_v6)
        for interface in interfaces:
            servers = [
                str(server)
                for server in [
                    *previous_dns_v4.get(interface, []),
                    *previous_dns_v6.get(interface, []),
                ]
                if str(server).strip()
            ]
            set_interface_dns(str(interface), servers)
        return

    for interface in active_dns_interfaces():
        set_interface_dns(interface, [])


def flatten_dns_servers(dns_by_interface: dict[str, list[str]]) -> list[str]:
    servers: list[str] = []
    for interface_servers in dns_by_interface.values():
        for server in interface_servers:
            if server and server != "127.0.0.1" and server not in servers:
                servers.append(server)
    return servers or ["8.8.8.8", "1.1.1.1"]


class GreenAgentApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.config = load_config()
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.blocklist_worker: threading.Thread | None = None
        self.blocklist_stop_event = threading.Event()
        self.tray_icon: pystray.Icon | None = None
        self.tray_thread: threading.Thread | None = None
        self.dns_filter: DNSFilterServer | None = None
        self.domain_check_cache: dict[str, tuple[DomainDecision | None, float]] = {}
        self.hide_notice_shown = False

        self.server_url = tk.StringVar(value=str(self.config.get("server_url", DEFAULT_SERVER_URL)))
        self.activation_token = tk.StringVar()
        self.status_text = tk.StringVar(value="Not activated")
        self.details_text = tk.StringVar(value="Enter the activation token from the admin dashboard.")
        self.last_heartbeat_text = tk.StringVar(value="-")
        self.protection_text = tk.StringVar(value="Blocking is off")
        self.blocklist_text = tk.StringVar(value="Admin blocklist not loaded")
        self.exit_button: ttk.Button | None = None
        self.start_blocking_button: ttk.Button | None = None
        self.stop_blocking_button: ttk.Button | None = None
        self.restore_dns_button: ttk.Button | None = None

        self.build_ui()
        self.recover_stale_dns_state()

        if self.is_activated:
            self.status_text.set("Activated")
            self.details_text.set(f"Device ID: {self.config['device_id']}")
            self.start_heartbeat_loop()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.start_tray_icon()

    @property
    def is_activated(self) -> bool:
        return bool(self.config.get("device_id") and self.config.get("token"))

    def build_ui(self) -> None:
        self.root.title(f"Green Agent - {BUILD_NAME}")
        self.root.geometry("540x660")
        self.root.minsize(460, 620)

        outer = ttk.Frame(self.root)
        outer.pack(fill="both", expand=True)

        canvas = tk.Canvas(outer, highlightthickness=0)
        scrollbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        frame = ttk.Frame(canvas, padding=18)
        frame_window = canvas.create_window((0, 0), window=frame, anchor="nw")

        def update_scroll_region(event: tk.Event | None = None) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def update_frame_width(event: tk.Event) -> None:
            canvas.itemconfigure(frame_window, width=event.width)

        frame.bind("<Configure>", update_scroll_region)
        canvas.bind("<Configure>", update_frame_width)

        title = ttk.Label(frame, text=f"Green Agent - {BUILD_NAME}", font=("Segoe UI", 20, "bold"))
        title.pack(anchor="w")

        subtitle = ttk.Label(frame, text="Activate this computer with the token from your admin.")
        subtitle.pack(anchor="w", pady=(4, 12))

        server_label = ttk.Label(frame, text="Server URL")
        server_label.pack(anchor="w")
        server_row = ttk.Frame(frame)
        server_row.pack(fill="x", pady=(4, 10))
        self.server_entry = ttk.Entry(server_row, textvariable=self.server_url)
        self.server_entry.pack(side="left", fill="x", expand=True)
        self.server_entry.bind("<Control-v>", self.paste_server_url)
        self.server_entry.bind("<Control-V>", self.paste_server_url)
        self.server_entry.bind("<Shift-Insert>", self.paste_server_url)
        server_paste_button = ttk.Button(server_row, text="Paste", command=self.paste_server_url)
        server_paste_button.pack(side="left", padx=(8, 0))

        token_label = ttk.Label(frame, text="Activation Token")
        token_label.pack(anchor="w")
        token_row = ttk.Frame(frame)
        token_row.pack(fill="x", pady=(4, 10))
        self.token_entry = ttk.Entry(token_row, textvariable=self.activation_token, show="*")
        self.token_entry.pack(side="left", fill="x", expand=True)
        self.token_entry.bind("<Control-v>", self.paste_token)
        self.token_entry.bind("<Control-V>", self.paste_token)
        self.token_entry.bind("<Shift-Insert>", self.paste_token)
        paste_button = ttk.Button(token_row, text="Paste", command=self.paste_token)
        paste_button.pack(side="left", padx=(8, 0))

        self.activate_button = ttk.Button(frame, text="Activate", command=self.on_activate)
        self.activate_button.pack(anchor="w")

        separator = ttk.Separator(frame)
        separator.pack(fill="x", pady=12)

        ttk.Label(frame, text="Status", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(frame, textvariable=self.status_text).pack(anchor="w", pady=(4, 0))
        ttk.Label(frame, textvariable=self.details_text).pack(anchor="w", pady=(4, 0))
        ttk.Label(frame, text="Last heartbeat", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(12, 0))
        ttk.Label(frame, textvariable=self.last_heartbeat_text).pack(anchor="w", pady=(4, 0))

        ttk.Label(frame, text="Blocking", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(12, 0))
        ttk.Label(frame, textvariable=self.protection_text).pack(anchor="w", pady=(4, 6))
        ttk.Label(frame, textvariable=self.blocklist_text).pack(anchor="w", pady=(0, 6))
        protection_row = ttk.Frame(frame)
        protection_row.pack(fill="x")
        self.start_blocking_button = ttk.Button(
            protection_row,
            text="Start Blocking",
            command=self.start_protection,
        )
        self.start_blocking_button.pack(side="left")
        self.stop_blocking_button = ttk.Button(
            protection_row,
            text="Stop Blocking",
            command=self.stop_protection,
        )
        self.stop_blocking_button.pack(side="left", padx=(8, 0))
        self.restore_dns_button = ttk.Button(
            frame,
            text="Restore Internet DNS",
            command=self.restore_dns_now,
        )
        self.restore_dns_button.pack(anchor="w", pady=(8, 0))

        self.exit_button = ttk.Button(frame, text="Exit Agent", command=self.request_exit)
        self.exit_button.pack(anchor="w", pady=(14, 0))

        if self.is_activated:
            self.activate_button.configure(state="normal")
        else:
            self.exit_button.configure(state="disabled")
            self.start_blocking_button.configure(state="disabled")
            self.stop_blocking_button.configure(state="disabled")
            self.token_entry.focus_set()

    def create_tray_image(self) -> Image.Image:
        image = Image.new("RGB", (64, 64), "#19a55b")
        draw = ImageDraw.Draw(image)
        draw.ellipse((10, 10, 54, 54), fill="#def8e9")
        draw.text((24, 20), "G", fill="#14211b")
        return image

    def start_tray_icon(self) -> None:
        if self.tray_icon:
            return

        self.tray_icon = pystray.Icon(
            "GreenAgent",
            self.create_tray_image(),
            "Green Agent",
            menu=pystray.Menu(
                pystray.MenuItem("Open", self.show_window, default=True),
                pystray.MenuItem("Exit Agent", self.request_exit),
            ),
        )
        self.tray_thread = threading.Thread(target=self.tray_icon.run, daemon=True)
        self.tray_thread.start()

    def show_window(self, icon: pystray.Icon | None = None, item: object | None = None) -> None:
        self.root.after(0, self._show_window)

    def _show_window(self) -> None:
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def hide_window(self) -> None:
        self.root.withdraw()
        if not self.hide_notice_shown:
            self.hide_notice_shown = True
            messagebox.showinfo(
                "Green Agent is still running",
                "Green Agent will keep running in the background and sending status updates.",
            )

    def paste_token(self, event: tk.Event | None = None) -> str:
        try:
            clipboard_text = self.root.clipboard_get().strip()
        except tk.TclError:
            return "break"

        if clipboard_text:
            self.activation_token.set(clipboard_text)
            self.token_entry.icursor("end")

        return "break"

    def paste_server_url(self, event: tk.Event | None = None) -> str:
        try:
            clipboard_text = self.root.clipboard_get().strip()
        except tk.TclError:
            return "break"

        if clipboard_text:
            self.server_url.set(clipboard_text.rstrip("/"))
            self.server_entry.icursor("end")

        return "break"

    def on_activate(self) -> None:
        server_url = self.server_url.get().strip()
        token = self.activation_token.get().strip()

        if not server_url or not token:
            messagebox.showerror("Activation failed", "Server URL and activation token are required.")
            return

        self.activate_button.configure(state="disabled")
        self.status_text.set("Activating...")

        def worker() -> None:
            try:
                result = activate_device(server_url, token)
                self.config.update(
                    {
                        "server_url": server_url,
                        "device_id": result["device_id"],
                        "token": result["token"],
                        "recovery_name": result.get("recovery_name", ""),
                        "interval_seconds": DEFAULT_INTERVAL_SECONDS,
                    }
                )
                save_config(self.config)
                self.root.after(0, self.on_activation_success)
            except requests.RequestException as exc:
                self.root.after(0, lambda: self.on_activation_error(str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def on_activation_success(self) -> None:
        self.status_text.set("Activated")
        self.details_text.set(f"Device ID: {self.config['device_id']}")
        if self.exit_button:
            self.exit_button.configure(state="normal")
        if self.start_blocking_button:
            self.start_blocking_button.configure(state="normal")
        if self.stop_blocking_button:
            self.stop_blocking_button.configure(state="normal")
        self.start_heartbeat_loop()
        messagebox.showinfo("Activated", "This computer is now activated.")

    def on_activation_error(self, error: str) -> None:
        self.status_text.set("Activation failed")
        self.activate_button.configure(state="normal")
        messagebox.showerror("Activation failed", error)

    def reset_activation(self, message: str) -> None:
        self.stop_event.set()
        self.blocklist_stop_event.set()
        for key in ("device_id", "token", "recovery_name"):
            self.config.pop(key, None)
        self.config["protection_enabled"] = False
        save_config(self.config)

        self.activation_token.set("")
        self.status_text.set("Activation needed")
        self.details_text.set(message)
        self.last_heartbeat_text.set("-")
        self.blocklist_text.set("Admin blocklist not loaded")
        if self.activate_button:
            self.activate_button.configure(state="normal")
        if self.exit_button:
            self.exit_button.configure(state="disabled")
        if self.start_blocking_button:
            self.start_blocking_button.configure(state="disabled")
        if self.stop_blocking_button:
            self.stop_blocking_button.configure(state="disabled")
        self.token_entry.focus_set()

    def start_heartbeat_loop(self) -> None:
        if self.worker and self.worker.is_alive():
            return

        self.stop_event.clear()
        self.worker = threading.Thread(target=self.heartbeat_loop, daemon=True)
        self.worker.start()

    def heartbeat_loop(self) -> None:
        interval_seconds = int(self.config.get("interval_seconds", DEFAULT_INTERVAL_SECONDS))

        while not self.stop_event.is_set():
            try:
                send_heartbeat(self.config)
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                self.root.after(0, lambda value=timestamp: self.last_heartbeat_text.set(value))
                self.root.after(0, lambda: self.status_text.set("Running"))
            except requests.RequestException as exc:
                status_code = getattr(exc.response, "status_code", None)
                if status_code == 401:
                    self.root.after(
                        0,
                        lambda: self.reset_activation(
                            "This saved activation is no longer valid. Paste a new activation token."
                        ),
                    )
                    return
                self.root.after(0, lambda error=str(exc): self.status_text.set(f"Heartbeat failed: {error}"))

            self.stop_event.wait(interval_seconds)

    def record_domain_event(self, decision: DomainDecision) -> None:
        if not self.is_activated:
            return
        try:
            send_domain_event(self.config, decision)
        except requests.RequestException:
            pass

    def check_domain_policy_cached(self, domain: str) -> DomainDecision | None:
        normalized = domain.strip().lower().rstrip(".")
        cached = self.domain_check_cache.get(normalized)
        now = time.time()
        if cached and now - cached[1] < DOMAIN_CHECK_CACHE_SECONDS:
            return cached[0]

        try:
            decision = check_domain_policy(self.config, normalized)
        except requests.RequestException:
            decision = None

        self.domain_check_cache[normalized] = (decision, now)
        return decision

    def refresh_blocklist_once(self) -> None:
        if not self.dns_filter or not self.is_activated:
            return

        try:
            domains, keywords = fetch_blocklist(self.config)
            source_label = "Admin blocklist loaded"
        except requests.RequestException:
            domains, keywords = load_local_blocklist()
            source_label = "Local fallback blocklist loaded"

        if domains or keywords:
            self.dns_filter.update_dynamic_domains(domains)
            self.dns_filter.update_blocked_keywords(keywords)
            self.root.after(
                0,
                lambda label=source_label, domain_count=len(domains), keyword_count=len(keywords): self.blocklist_text.set(
                    f"{label}: {domain_count} domains, {keyword_count} keywords"
                ),
            )
        else:
            self.root.after(
                0,
                lambda: self.blocklist_text.set("Using server domain-check fallback"),
            )

    def start_blocklist_refresh_loop(self) -> None:
        if self.blocklist_worker and self.blocklist_worker.is_alive():
            return

        self.blocklist_stop_event.clear()
        self.blocklist_worker = threading.Thread(target=self.blocklist_refresh_loop, daemon=True)
        self.blocklist_worker.start()

    def blocklist_refresh_loop(self) -> None:
        while not self.blocklist_stop_event.is_set():
            self.refresh_blocklist_once()
            self.blocklist_stop_event.wait(BLOCKLIST_REFRESH_SECONDS)

    def stop_blocklist_refresh_loop(self) -> None:
        self.blocklist_stop_event.set()
        self.blocklist_worker = None

    def recover_stale_dns_state(self) -> None:
        if not self.config.get("protection_enabled"):
            return

        self.protection_text.set("Previous blocking session detected")
        if not is_admin():
            messagebox.showwarning(
                "DNS restore needed",
                "A previous blocking session did not close cleanly. Start GreenAgent.exe as administrator and click Restore Internet DNS.",
            )
            return

        try:
            restore_dns_from_config(self.config)
            self.config["protection_enabled"] = False
            save_config(self.config)
            self.protection_text.set("Blocking is off; DNS restored")
        except Exception as exc:
            self.protection_text.set("DNS restore failed")
            messagebox.showerror("DNS restore failed", str(exc))

    def restore_dns_now(self) -> None:
        if not is_admin():
            messagebox.showerror(
                "Administrator required",
                "Start GreenAgent.exe as administrator to restore DNS.",
            )
            return

        try:
            restore_dns_from_config(self.config)
            if self.dns_filter:
                self.dns_filter.stop()
                self.dns_filter = None
            self.config["protection_enabled"] = False
            save_config(self.config)
            self.protection_text.set("DNS restored; blocking is off")
            messagebox.showinfo("DNS restored", "Internet DNS settings were restored.")
        except Exception as exc:
            messagebox.showerror("DNS restore failed", str(exc))

    def start_protection(self) -> None:
        if not self.is_activated:
            messagebox.showerror("Blocking", "Activate the agent first.")
            return

        if not is_admin():
            messagebox.showerror(
                "Administrator required",
                "Start GreenAgent.exe as administrator to enable DNS blocking.",
            )
            return

        changed_interfaces: list[str] = []

        try:
            self.protection_text.set("Starting blocking...")
            self.root.update_idletasks()

            interfaces = active_dns_interfaces()
            if not interfaces:
                raise RuntimeError("No active network interfaces found.")

            previous_dns_v4: dict[str, list[str]] = {}
            previous_dns_v6: dict[str, list[str]] = {}
            for interface in interfaces:
                previous_dns_v4[interface] = current_dns_servers(interface, address_family="IPv4")
                previous_dns_v6[interface] = current_dns_servers(interface, address_family="IPv6")

            self.config["dns_previous_v4"] = previous_dns_v4
            self.config["dns_previous_v6"] = previous_dns_v6
            self.config.pop("dns_previous", None)
            self.config["protection_enabled"] = False
            save_config(self.config)

            upstream_servers = flatten_dns_servers(previous_dns_v4)
            if not self.dns_filter:
                self.dns_filter = DNSFilterServer(
                    self.record_domain_event,
                    policy_callback=self.check_domain_policy_cached,
                    upstream_servers=upstream_servers,
                )
            self.dns_filter.start()
            self.refresh_blocklist_once()
            self.start_blocklist_refresh_loop()

            for interface in interfaces:
                set_interface_dns(interface, ["127.0.0.1", "::1"])
                changed_interfaces.append(interface)

            self.config["protection_enabled"] = True
            save_config(self.config)
            self.protection_text.set("Blocking is on")
        except Exception as exc:
            if changed_interfaces:
                try:
                    restore_dns_from_config(self.config)
                except Exception:
                    pass
            if self.dns_filter:
                self.dns_filter.stop()
                self.dns_filter = None
            self.stop_blocklist_refresh_loop()
            self.config["protection_enabled"] = False
            save_config(self.config)
            self.protection_text.set("Blocking failed")
            messagebox.showerror("Blocking failed", str(exc))

    def stop_protection(self, silent: bool = False) -> bool:
        try:
            if not is_admin():
                raise RuntimeError("Administrator permission is required to restore DNS.")

            restore_dns_from_config(self.config)

            if self.dns_filter:
                self.dns_filter.stop()
                self.dns_filter = None
            self.stop_blocklist_refresh_loop()
            self.blocklist_text.set("Admin blocklist not loaded")

            self.config["protection_enabled"] = False
            save_config(self.config)
            self.protection_text.set("Blocking is off")
            return True
        except Exception as exc:
            if not silent:
                messagebox.showerror("Stop blocking failed", str(exc))
            return False

    def request_exit(self, icon: pystray.Icon | None = None, item: object | None = None) -> None:
        self.root.after(0, self.exit_agent)

    def exit_agent(self) -> None:
        if not self.is_activated:
            self.stop_event.set()
            if self.tray_icon:
                self.tray_icon.stop()
            self.root.destroy()
            return

        should_exit = messagebox.askyesno(
            "Exit Green Agent",
            "Exit Green Agent now? The admin dashboard will show this device as Exited.",
        )
        if not should_exit:
            return

        if not self.stop_protection(silent=False):
            messagebox.showwarning(
                "Exit cancelled",
                "Green Agent did not exit because DNS settings were not restored.",
            )
            return

        self.stop_event.set()
        try:
            send_heartbeat(self.config, status="exited", timeout=5)
        except requests.RequestException:
            pass

        if self.tray_icon:
            self.tray_icon.stop()
        self.root.destroy()

    def on_close(self) -> None:
        if self.is_activated:
            self.hide_window()
            return

        if self.tray_icon:
            self.tray_icon.stop()
        self.stop_event.set()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    app = GreenAgentApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
