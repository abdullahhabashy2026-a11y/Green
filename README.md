# Green

Green v0.1 is a local proof of concept for monitoring whether a Windows agent is installed and running.

## Current Phase

**Phase:** `windows-effective-adult-site-blocking`

This phase marks a working Windows version for blocking known adult websites using local DNS filtering, imported adult blocklists, DNS restore safety, and basic false-positive protection through an Agent allowlist.

## Components

- `server`: FastAPI backend, SQLite database, and a simple color-based admin dashboard.
- `agent-windows`: Python agent that sends a heartbeat every 60 seconds.
- `agent-android`: native Android/Kotlin prototype using VPNService for DNS-level filtering.
- `server/blocklists`: exported starter blocklists used to seed a fresh database.
- `docs`: v0.1 notes and API shape.

## Quick Start

### 1. Start the server

```powershell
cd "E:\HABASHY\Python Codes\Green\server"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:ADMIN_USERNAME="admin"
$env:ADMIN_PASSWORD="change-this-local-password"
$env:APP_SECRET_KEY="change-this-to-a-long-random-secret"
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open:

```text
http://127.0.0.1:8000
```

The dashboard is protected by a single admin login. For production, use `ADMIN_PASSWORD_HASH`
instead of `ADMIN_PASSWORD`. Generate a hash with:

```powershell
python -c "from app.main import hash_password; import getpass; print(hash_password(getpass.getpass()))"
```

See `server/.env.example` for the production environment variables. Do not commit a real `.env`
file or real secrets.

SQLite remains the local default. For production PostgreSQL, set:

```powershell
$env:DATABASE_URL="postgresql://green_user:password@host:5432/green"
```

### Render prototype deployment

For a quick shared prototype:

1. Push this repository to GitHub.
2. In Render, create a managed PostgreSQL database.
3. Create a Web Service from the GitHub repository.
4. Use Docker as the runtime.
5. Set the Dockerfile path to:

```text
server/Dockerfile
```

6. Set the Docker build context directory to:

```text
server
```

7. Add these environment variables in Render:

```text
DATABASE_URL=<Render PostgreSQL internal database URL>
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=<generated password hash>
APP_SECRET_KEY=<long random secret>
```

8. Set the Health Check Path to:

```text
/health
```

9. Open the Render service URL and log in to the dashboard.

On first run, if `server/data/green.db` does not exist or has no blocked domains, the server imports starter lists from:

```text
server/blocklists/adult.txt
server/blocklists/custom.txt
```

Runtime data is stored locally in `server/data/green.db` and is intentionally ignored by Git.

### 2. Start the Windows agent GUI

In a second PowerShell window:

```powershell
cd "E:\HABASHY\Python Codes\Green\agent-windows"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python agent_gui.py
```

Enter the activation token from the dashboard. The dashboard should show the device as active after activation.

### End-user click-only build

The Windows Agent executable is built here:

```text
E:\HABASHY\Python Codes\Green\agent-windows\dist\GreenAgent.exe
```

The latest fixed experimental build is also available here:

```text
E:\HABASHY\Python Codes\Green\agent-windows\dist\GreenAgentFixed.exe
```

The end user only needs to double-click `GreenAgent.exe`, paste the activation token, and click `Activate`.
After activation, closing the window hides it to the background. The Agent keeps sending heartbeats and can be opened again from the tray icon near the Windows clock.
For the experimental phase, the user can exit manually from the `Exit Agent` button or the tray menu. The Agent sends an immediate `Exited` status to the dashboard before closing.

### Experimental blocking

The current Agent includes an experimental DNS-level blocker:

- `Start Blocking`: starts a local DNS filter and points active Windows DNS interfaces to `127.0.0.1`.
- `Stop Blocking`: stops the filter and restores the previous DNS settings saved by the Agent.
- Blocked and allowed domain events are sent to the dashboard under `Domain Activity`.
- Domain activity is hidden from the main dashboard and opened per device from the `View` link in the devices table.
- Admin-managed blocked domains are configured from the dashboard under `Blocked Domains`.
- The dashboard supports bulk paste/import of domains under one selected category.
- The Agent loads the admin blocklist when blocking starts and refreshes it every 5 minutes.

The executable requests administrator permission because Windows DNS settings and port 53 require elevated access.

Safety notes:

- The Agent now stores previous DNS settings before changing anything.
- Allowed DNS queries are forwarded to the computer's previous DNS servers instead of a hardcoded DNS server.
- If a previous blocking session did not close cleanly, the Agent attempts to restore DNS on startup.
- `Restore Internet DNS` restores saved DNS settings from the GUI.
- `agent-windows/Restore-DNS.ps1` is an emergency manual restore script.
- `Stop Blocking` and `Exit Agent` now restore DNS first. If DNS restore fails, exit is cancelled to avoid leaving the computer without DNS.

To rebuild the executable:

```powershell
cd "E:\HABASHY\Python Codes\Green\agent-windows"
.\Build-GreenAgent.ps1
```

### Optional command-line agent

After activation creates `agent.config.json`, you can run the command-line agent:

```powershell
python agent.py
```

For a one-time test:

```powershell
python agent.py --once
```

## Android prototype

The first Android prototype lives in:

```text
agent-android
```

It is a native Kotlin Android app with:

- activation by the same dashboard token.
- local config storage.
- heartbeat to `/api/heartbeat`.
- `Start Blocking` / `Stop Blocking`.
- Android `VPNService` DNS filtering.
- blocklist loading from `/api/blocklist`.
- blocked domain event logging to `/api/domain-event`.

For Android Emulator, the default server URL is:

```text
http://10.0.2.2:8000
```

For a real Android phone, run the server on `0.0.0.0` and enter the computer LAN IP in the app, for example:

```text
http://192.168.1.20:8000
```

Open the project folder in Android Studio and build the `agent-android` module.
