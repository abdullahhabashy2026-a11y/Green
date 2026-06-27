from __future__ import annotations

import getpass
import json
import argparse
import os
import platform
import socket
import time
from pathlib import Path
from typing import Any

import requests


APP_VERSION = "0.1.0"
EXAMPLE_CONFIG_PATH = Path(__file__).with_name("agent.example.json")


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
        raise SystemExit(
            "Missing agent.config.json. Activate the device with agent_gui.py first."
        )

    with path.open("r", encoding="utf-8") as config_file:
        config = json.load(config_file)

    required_keys = ["server_url", "device_id", "token"]
    missing = [key for key in required_keys if not config.get(key)]
    if missing:
        raise SystemExit(f"Missing required config keys: {', '.join(missing)}")

    config.setdefault("interval_seconds", 60)
    return config


def build_payload(config: dict[str, Any]) -> dict[str, str]:
    return {
        "device_id": str(config["device_id"]),
        "token": str(config["token"]),
        "device_name": socket.gethostname(),
        "windows_user": getpass.getuser(),
        "agent_version": APP_VERSION,
        "status": "running",
    }


def send_heartbeat(config: dict[str, Any]) -> None:
    server_url = str(config["server_url"]).rstrip("/")
    response = requests.post(
        f"{server_url}/api/heartbeat",
        json=build_payload(config),
        timeout=15,
    )
    response.raise_for_status()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Green Windows Agent")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Send one heartbeat and exit.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = load_config()
    interval_seconds = int(config.get("interval_seconds", 60))

    print("Green Windows Agent")
    print(f"Version: {APP_VERSION}")
    print(f"Device ID: {config['device_id']}")
    print(f"Server: {str(config['server_url']).rstrip('/')}")
    print(f"Computer: {socket.gethostname()}")
    print(f"User: {getpass.getuser()}")
    print(f"Platform: {platform.platform()}")
    print(f"Heartbeat interval: {interval_seconds} seconds")
    if args.once:
        send_heartbeat(config)
        print(time.strftime("%Y-%m-%d %H:%M:%S"), "heartbeat sent")
        return

    print("Press Ctrl+C to stop.")

    while True:
        try:
            send_heartbeat(config)
            print(time.strftime("%Y-%m-%d %H:%M:%S"), "heartbeat sent")
        except requests.RequestException as exc:
            print(time.strftime("%Y-%m-%d %H:%M:%S"), f"heartbeat failed: {exc}")
        except Exception as exc:
            print(time.strftime("%Y-%m-%d %H:%M:%S"), f"unexpected error: {exc}")

        time.sleep(interval_seconds)


if __name__ == "__main__":
    main()
