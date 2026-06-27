from __future__ import annotations

import sqlite3
import secrets
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request as UrlRequest
from urllib.request import urlopen

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR.parent / "data"
DB_PATH = DATA_DIR / "green.db"
SEED_BLOCKLIST_DIR = BASE_DIR.parent / "blocklists"

APP_VERSION = "0.1.0"
ACTIVE_SECONDS = 180
DELAYED_SECONDS = 600
BLOCKLIST_FETCH_TIMEOUT_SECONDS = 45
MAX_BLOCKLIST_DOWNLOAD_BYTES = 25 * 1024 * 1024

ALLOWED_BLOCK_CATEGORIES = {"adult", "social", "custom"}
DEFAULT_REMOTE_BLOCKLISTS = [
    {
        "name": "OISD NSFW",
        "url": "https://nsfw.oisd.nl/",
        "category": "adult",
    },
    {
        "name": "BlockListProject Porn",
        "url": "https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt",
        "category": "adult",
    },
]

app = FastAPI(title="Green Presence Monitor", version=APP_VERSION)
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


class HeartbeatPayload(BaseModel):
    device_id: str = Field(min_length=3, max_length=128)
    token: str = Field(min_length=8, max_length=256)
    device_name: str | None = Field(default=None, max_length=255)
    windows_user: str | None = Field(default=None, max_length=255)
    platform: str | None = Field(default=None, max_length=32)
    private_dns_mode: str | None = Field(default=None, max_length=64)
    private_dns_specifier: str | None = Field(default=None, max_length=255)
    vpn_active: bool | None = None
    battery_optimization_ignored: bool | None = None
    agent_version: str | None = Field(default=None, max_length=64)
    status: str = Field(default="running", max_length=32)


class ActivationPayload(BaseModel):
    enrollment_token: str = Field(min_length=8, max_length=256)
    device_name: str | None = Field(default=None, max_length=255)
    windows_user: str | None = Field(default=None, max_length=255)
    platform: str | None = Field(default=None, max_length=32)
    private_dns_mode: str | None = Field(default=None, max_length=64)
    private_dns_specifier: str | None = Field(default=None, max_length=255)
    vpn_active: bool | None = None
    battery_optimization_ignored: bool | None = None
    agent_version: str | None = Field(default=None, max_length=64)


class DomainEventPayload(BaseModel):
    device_id: str = Field(min_length=3, max_length=128)
    token: str = Field(min_length=8, max_length=256)
    domain: str = Field(min_length=1, max_length=255)
    category: str = Field(min_length=1, max_length=64)
    decision: str = Field(min_length=1, max_length=32)
    reason: str | None = Field(default=None, max_length=255)


class DomainCheckPayload(BaseModel):
    device_id: str = Field(min_length=3, max_length=128)
    token: str = Field(min_length=8, max_length=256)
    domain: str = Field(min_length=1, max_length=255)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


def utc_iso(value: datetime | None = None) -> str:
    return (value or now_utc()).isoformat(timespec="seconds")


def get_connection() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db() -> None:
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recovery_name TEXT NOT NULL,
                device_id TEXT NOT NULL UNIQUE,
                token TEXT NOT NULL,
                device_name TEXT,
                windows_user TEXT,
                agent_version TEXT,
                status TEXT NOT NULL DEFAULT 'registered',
                created_at TEXT NOT NULL,
                last_seen_at TEXT
            )
            """
        )
        ensure_column(conn, "devices", "platform", "TEXT")
        ensure_column(conn, "devices", "private_dns_mode", "TEXT")
        ensure_column(conn, "devices", "private_dns_specifier", "TEXT")
        ensure_column(conn, "devices", "vpn_active", "INTEGER")
        ensure_column(conn, "devices", "battery_optimization_ignored", "INTEGER")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS domain_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                domain TEXT NOT NULL,
                category TEXT NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(device_id) REFERENCES devices(device_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blocked_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                category TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_blocked_domains_domain
            ON blocked_domains(domain)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_blocked_domains_category
            ON blocked_domains(category)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blocked_keywords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                keyword TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_blocked_keywords_keyword
            ON blocked_keywords(keyword)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS remote_blocklists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                url TEXT NOT NULL UNIQUE,
                category TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                last_checked_at TEXT,
                last_success_at TEXT,
                last_error TEXT,
                last_domain_count INTEGER NOT NULL DEFAULT 0,
                last_import_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
        for source in DEFAULT_REMOTE_BLOCKLISTS:
            conn.execute(
                """
                INSERT OR IGNORE INTO remote_blocklists (name, url, category, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (source["name"], source["url"], source["category"], utc_iso()),
            )
        conn.commit()
    seed_blocklists_if_empty()


def seed_blocklists_if_empty() -> None:
    if not SEED_BLOCKLIST_DIR.exists():
        return

    with get_connection() as conn:
        existing_count = conn.execute("SELECT COUNT(*) AS total FROM blocked_domains").fetchone()["total"]
        if existing_count:
            return

        for category in sorted(ALLOWED_BLOCK_CATEGORIES):
            seed_path = SEED_BLOCKLIST_DIR / f"{category}.txt"
            if not seed_path.exists():
                continue

            created_at = utc_iso()
            batch: list[tuple[str, str, str]] = []
            with seed_path.open("r", encoding="utf-8") as seed_file:
                for line in seed_file:
                    domain = normalize_domain(line)
                    if not is_valid_domain(domain):
                        continue
                    batch.append((domain, category, created_at))
                    if len(batch) >= 1000:
                        conn.executemany(
                            """
                            INSERT OR IGNORE INTO blocked_domains (domain, category, created_at)
                            VALUES (?, ?, ?)
                            """,
                            batch,
                        )
                        batch.clear()

            if batch:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO blocked_domains (domain, category, created_at)
                    VALUES (?, ?, ?)
                    """,
                    batch,
                )

        conn.commit()


@app.on_event("startup")
def on_startup() -> None:
    init_db()


def status_for(last_seen_at: str | None, agent_status: str | None) -> dict[str, Any]:
    if last_seen_at is None:
        return {
            "key": "never",
            "label": "Waiting for Install",
            "class_name": "status-never",
            "minutes_ago": None,
        }

    last_seen = parse_utc(last_seen_at)
    if last_seen is None:
        return {
            "key": "unknown",
            "label": "Unknown",
            "class_name": "status-never",
            "minutes_ago": None,
        }

    age_seconds = max(0, int((now_utc() - last_seen).total_seconds()))
    minutes_ago = age_seconds // 60

    if agent_status == "exited":
        return {
            "key": "exited",
            "label": "Exited",
            "class_name": "status-exited",
            "minutes_ago": minutes_ago,
        }

    if age_seconds < ACTIVE_SECONDS:
        return {
            "key": "active",
            "label": "Active",
            "class_name": "status-active",
            "minutes_ago": minutes_ago,
        }
    if age_seconds < DELAYED_SECONDS:
        return {
            "key": "delayed",
            "label": "Delayed",
            "class_name": "status-delayed",
            "minutes_ago": minutes_ago,
        }
    return {
        "key": "no_signal",
        "label": "No Signal",
        "class_name": "status-no-signal",
        "minutes_ago": minutes_ago,
    }


def list_devices() -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM devices
            ORDER BY
                CASE WHEN last_seen_at IS NULL THEN 1 ELSE 0 END,
                last_seen_at DESC,
                recovery_name ASC
            """
        ).fetchall()

    devices = []
    for row in rows:
        device = dict(row)
        device["computed_status"] = status_for(device["last_seen_at"], device["status"])
        devices.append(device)
    return devices


def list_domain_events(limit: int = 80, device_id: str | None = None) -> list[dict[str, Any]]:
    where_clause = ""
    params: list[Any] = []
    if device_id:
        where_clause = "WHERE domain_events.device_id = ?"
        params.append(device_id)

    params.append(limit)

    with get_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT
                domain_events.*,
                devices.recovery_name,
                devices.device_name
            FROM domain_events
            LEFT JOIN devices ON devices.device_id = domain_events.device_id
            {where_clause}
            ORDER BY domain_events.id DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
    return [dict(row) for row in rows]


def get_device_by_id(device_id: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM devices WHERE device_id = ?",
            (device_id,),
        ).fetchone()

    if row is None:
        return None

    device = dict(row)
    device["computed_status"] = status_for(device["last_seen_at"], device["status"])
    return device


def normalize_domain(domain: str) -> str:
    normalized = domain.strip().lower().rstrip(".")
    for prefix in ("https://", "http://"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
    if "@" in normalized:
        normalized = normalized.rsplit("@", 1)[-1]
    normalized = normalized.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if normalized.startswith("www."):
        normalized = normalized[4:]
    if ":" in normalized:
        normalized = normalized.split(":", 1)[0]
    normalized = normalized.strip().lstrip(".")
    return normalized


def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253 or "." not in domain:
        return False
    if "*" in domain or "_" in domain:
        return False
    labels = domain.split(".")
    return all(
        label
        and len(label) <= 63
        and re.fullmatch(r"[a-z0-9-]+", label) is not None
        and not label.startswith("-")
        and not label.endswith("-")
        for label in labels
    )


def parse_domain_lines(raw_domains: str) -> list[str]:
    domains: list[str] = []
    for chunk in raw_domains.replace(",", "\n").replace(";", "\n").splitlines():
        normalized = normalize_domain(chunk)
        if is_valid_domain(normalized) and normalized not in domains:
            domains.append(normalized)
    return domains


def normalize_keyword(keyword: str) -> str:
    return keyword.strip().lower()


def is_valid_keyword(keyword: str) -> bool:
    return 2 <= len(keyword) <= 64 and re.fullmatch(r"[a-z0-9-]+", keyword) is not None


def domain_suffixes(domain: str) -> list[str]:
    labels = [label for label in domain.split(".") if label]
    return [".".join(labels[index:]) for index in range(len(labels))]


def check_domain_policy(domain: str) -> dict[str, str]:
    normalized = normalize_domain(domain)
    if not normalized:
        return {
            "domain": normalized,
            "category": "unknown",
            "decision": "allowed",
            "reason": "Invalid or empty domain",
        }

    with get_connection() as conn:
        for suffix in domain_suffixes(normalized):
            row = conn.execute(
                "SELECT category FROM blocked_domains WHERE domain = ?",
                (suffix,),
            ).fetchone()
            if row is not None:
                return {
                    "domain": normalized,
                    "category": row["category"],
                    "decision": "blocked",
                    "reason": f"Matched server list: {suffix}",
                }

        keyword_rows = conn.execute("SELECT keyword FROM blocked_keywords ORDER BY keyword ASC").fetchall()

    for row in keyword_rows:
        keyword = row["keyword"]
        if keyword and keyword in normalized:
            return {
                "domain": normalized,
                "category": "keyword",
                "decision": "blocked",
                "reason": f"Matched server keyword: {keyword}",
            }

    return {
        "domain": normalized,
        "category": "unknown",
        "decision": "allowed",
        "reason": "No server blocklist match",
    }


def extract_domains_from_blocklist(raw_text: str) -> list[str]:
    domains: list[str] = []
    seen: set[str] = set()

    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(("#", "!", "[", "@@")):
            continue

        candidates: list[str] = []

        if line.startswith("||"):
            candidate = line[2:].split("^", 1)[0].split("$", 1)[0]
            candidates.append(candidate)
        elif line.startswith("|"):
            candidate = line.lstrip("|").split("^", 1)[0].split("$", 1)[0]
            candidates.append(candidate)
        else:
            cleaned_line = line.replace("\t", " ")
            parts = [part for part in cleaned_line.split(" ") if part]
            if len(parts) >= 2 and parts[0] in {"0.0.0.0", "127.0.0.1", "::", "::1"}:
                candidates.append(parts[1])
            else:
                candidates.append(parts[0])

        for candidate in candidates:
            candidate = candidate.strip().strip("|").strip("^").strip()
            if candidate.startswith("*."):
                candidate = candidate[2:]
            normalized = normalize_domain(candidate)
            if is_valid_domain(normalized) and normalized not in seen:
                seen.add(normalized)
                domains.append(normalized)

    return domains


def list_blocked_domains(limit: int | None = None) -> list[dict[str, Any]]:
    limit_clause = ""
    params: list[Any] = []
    if limit is not None:
        limit_clause = "LIMIT ?"
        params.append(limit)

    with get_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT *
            FROM blocked_domains
            ORDER BY category ASC, domain ASC
            {limit_clause}
            """,
            params,
        ).fetchall()
    return [dict(row) for row in rows]


def list_blocked_domains_page(page: int, page_size: int, search: str = "") -> list[dict[str, Any]]:
    offset = (page - 1) * page_size
    where_clause = ""
    params: list[Any] = []
    if search:
        where_clause = "WHERE domain LIKE ?"
        params.append(f"%{search}%")

    with get_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT *
            FROM blocked_domains
            {where_clause}
            ORDER BY category ASC, domain ASC
            LIMIT ? OFFSET ?
            """,
            (*params, page_size, offset),
        ).fetchall()
    return [dict(row) for row in rows]


def count_blocked_domains(search: str = "") -> int:
    where_clause = ""
    params: list[Any] = []
    if search:
        where_clause = "WHERE domain LIKE ?"
        params.append(f"%{search}%")

    with get_connection() as conn:
        row = conn.execute(
            f"""
            SELECT COUNT(*) AS total
            FROM blocked_domains
            {where_clause}
            """
            ,
            params,
        ).fetchone()
    return int(row["total"])


def list_blocked_keywords() -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM blocked_keywords
            ORDER BY keyword ASC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def count_blocked_keywords() -> int:
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM blocked_keywords
            """
        ).fetchone()
    return int(row["total"])


def list_remote_blocklists() -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM remote_blocklists
            ORDER BY enabled DESC, name ASC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def fetch_remote_text(url: str) -> str:
    request = UrlRequest(
        url,
        headers={
            "User-Agent": "GreenBlocklistUpdater/0.1",
            "Accept": "text/plain,*/*;q=0.8",
        },
    )
    with urlopen(request, timeout=BLOCKLIST_FETCH_TIMEOUT_SECONDS) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        payload = response.read(MAX_BLOCKLIST_DOWNLOAD_BYTES + 1)
        if len(payload) > MAX_BLOCKLIST_DOWNLOAD_BYTES:
            raise ValueError("Remote list is larger than the configured safety limit")
        return payload.decode(charset, errors="replace")


def update_remote_blocklist(source_id: int) -> dict[str, Any]:
    checked_at = utc_iso()

    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM remote_blocklists WHERE id = ?",
            (source_id,),
        ).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Remote blocklist not found")

    source = dict(row)
    if not source["enabled"]:
        raise HTTPException(status_code=400, detail="Remote blocklist is disabled")

    try:
        raw_text = fetch_remote_text(source["url"])
        domains = extract_domains_from_blocklist(raw_text)
        if not domains:
            raise ValueError("No valid domains found in remote list")

        imported = 0
        with get_connection() as conn:
            for domain in domains:
                cursor = conn.execute(
                    """
                    INSERT OR IGNORE INTO blocked_domains (domain, category, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (domain, source["category"], checked_at),
                )
                imported += cursor.rowcount

            conn.execute(
                """
                UPDATE remote_blocklists
                SET last_checked_at = ?,
                    last_success_at = ?,
                    last_error = NULL,
                    last_domain_count = ?,
                    last_import_count = ?
                WHERE id = ?
                """,
                (checked_at, checked_at, len(domains), imported, source_id),
            )
            conn.commit()

        return {
            "source": source["name"],
            "domain_count": len(domains),
            "import_count": imported,
        }
    except (OSError, URLError, ValueError) as exc:
        error_message = str(exc)[:500]
        with get_connection() as conn:
            conn.execute(
                """
                UPDATE remote_blocklists
                SET last_checked_at = ?,
                    last_error = ?
                WHERE id = ?
                """,
                (checked_at, error_message, source_id),
            )
            conn.commit()
        raise HTTPException(status_code=502, detail=f"Could not update remote blocklist: {error_message}") from exc


def generate_device_id() -> str:
    return f"green-{secrets.token_hex(6)}"


def generate_token() -> str:
    return secrets.token_urlsafe(32)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    devices = list_devices()
    blocked_domain_total = count_blocked_domains()
    blocked_keywords = list_blocked_keywords()
    remote_blocklists = list_remote_blocklists()
    counts = {"active": 0, "delayed": 0, "no_signal": 0, "never": 0, "exited": 0}
    for device in devices:
        key = device["computed_status"]["key"]
        counts[key] = counts.get(key, 0) + 1

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "devices": devices,
            "blocked_domain_total": blocked_domain_total,
            "blocked_keywords": blocked_keywords,
            "blocked_keyword_total": len(blocked_keywords),
            "remote_blocklists": remote_blocklists,
            "counts": counts,
            "generated_at": utc_iso(),
        },
    )


@app.get("/blocked-domains", response_class=HTMLResponse)
def blocked_domains_page(
    request: Request,
    page: int = 1,
    page_size: int = 50,
    q: str = "",
) -> HTMLResponse:
    allowed_page_sizes = {25, 50, 100, 200}
    if page_size not in allowed_page_sizes:
        page_size = 50
    page = max(1, page)
    search = normalize_domain(q) if q.strip() else ""

    total = count_blocked_domains(search=search)
    total_pages = max(1, (total + page_size - 1) // page_size)
    if page > total_pages:
        page = total_pages

    domains = list_blocked_domains_page(page=page, page_size=page_size, search=search)

    return templates.TemplateResponse(
        "blocked_domains.html",
        {
            "request": request,
            "blocked_domains": domains,
            "blocked_domain_total": total,
            "page": page,
            "page_size": page_size,
            "page_sizes": sorted(allowed_page_sizes),
            "search": search,
            "total_pages": total_pages,
            "previous_page": page - 1 if page > 1 else None,
            "next_page": page + 1 if page < total_pages else None,
            "generated_at": utc_iso(),
        },
    )


@app.get("/devices/{device_id}/activity", response_class=HTMLResponse)
def device_activity(request: Request, device_id: str) -> HTMLResponse:
    device = get_device_by_id(device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")

    domain_events = list_domain_events(device_id=device_id, limit=200)
    return templates.TemplateResponse(
        "device_activity.html",
        {
            "request": request,
            "device": device,
            "domain_events": domain_events,
            "generated_at": utc_iso(),
        },
    )


@app.post("/devices")
def create_device(
    recovery_name: str = Form(...),
) -> RedirectResponse:
    recovery_name = recovery_name.strip()

    if not recovery_name:
        raise HTTPException(status_code=400, detail="Invalid device details")

    with get_connection() as conn:
        for _ in range(5):
            device_id = generate_device_id()
            token = generate_token()
            try:
                conn.execute(
                    """
                    INSERT INTO devices (recovery_name, device_id, token, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (recovery_name, device_id, token, utc_iso()),
                )
                conn.commit()
                return RedirectResponse("/", status_code=303)
            except sqlite3.IntegrityError:
                continue

    raise HTTPException(status_code=500, detail="Could not generate unique device credentials")


@app.post("/devices/{device_id}/delete")
def delete_device(device_id: str) -> RedirectResponse:
    with get_connection() as conn:
        conn.execute("DELETE FROM domain_events WHERE device_id = ?", (device_id,))
        conn.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
        conn.commit()

    return RedirectResponse("/", status_code=303)


@app.post("/devices/{device_id}/history/delete")
def delete_device_history(device_id: str) -> RedirectResponse:
    with get_connection() as conn:
        conn.execute("DELETE FROM domain_events WHERE device_id = ?", (device_id,))
        conn.commit()

    return RedirectResponse("/", status_code=303)


@app.post("/devices/{device_id}/rename")
def rename_device(device_id: str, recovery_name: str = Form(...)) -> RedirectResponse:
    recovery_name = recovery_name.strip()
    if not recovery_name:
        raise HTTPException(status_code=400, detail="Invalid recovery name")

    with get_connection() as conn:
        conn.execute(
            "UPDATE devices SET recovery_name = ? WHERE device_id = ?",
            (recovery_name, device_id),
        )
        conn.commit()

    return RedirectResponse("/", status_code=303)


@app.post("/blocked-domains")
def create_blocked_domain(
    domain: str = Form(...),
    category: str = Form(...),
) -> RedirectResponse:
    normalized = normalize_domain(domain)
    category = category.strip().lower()

    if not normalized or category not in ALLOWED_BLOCK_CATEGORIES:
        raise HTTPException(status_code=400, detail="Invalid blocked domain details")

    try:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO blocked_domains (domain, category, created_at)
                VALUES (?, ?, ?)
                """,
                (normalized, category, utc_iso()),
            )
            conn.commit()
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Domain already exists") from exc

    return RedirectResponse("/", status_code=303)


@app.post("/blocked-domains/import")
def import_blocked_domains(
    domains: str = Form(...),
    category: str = Form(...),
) -> RedirectResponse:
    category = category.strip().lower()

    if category not in ALLOWED_BLOCK_CATEGORIES:
        raise HTTPException(status_code=400, detail="Invalid blocked domain category")

    parsed_domains = parse_domain_lines(domains)
    if not parsed_domains:
        raise HTTPException(status_code=400, detail="No valid domains found")

    with get_connection() as conn:
        for domain in parsed_domains:
            conn.execute(
                """
                INSERT OR IGNORE INTO blocked_domains (domain, category, created_at)
                VALUES (?, ?, ?)
                """,
                (domain, category, utc_iso()),
            )
        conn.commit()

    return RedirectResponse("/", status_code=303)


@app.post("/blocked-keywords")
def create_blocked_keyword(
    keyword: str = Form(...),
) -> RedirectResponse:
    normalized = normalize_keyword(keyword)

    if not is_valid_keyword(normalized):
        raise HTTPException(status_code=400, detail="Invalid blocked keyword")

    try:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO blocked_keywords (keyword, created_at)
                VALUES (?, ?)
                """,
                (normalized, utc_iso()),
            )
            conn.commit()
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Keyword already exists") from exc

    return RedirectResponse("/", status_code=303)


@app.post("/blocked-keywords/{keyword_id}/delete")
def delete_blocked_keyword(keyword_id: int) -> RedirectResponse:
    with get_connection() as conn:
        conn.execute("DELETE FROM blocked_keywords WHERE id = ?", (keyword_id,))
        conn.commit()

    return RedirectResponse("/", status_code=303)


@app.post("/blocked-domains/{domain_id}/delete")
def delete_blocked_domain(domain_id: int) -> RedirectResponse:
    with get_connection() as conn:
        conn.execute("DELETE FROM blocked_domains WHERE id = ?", (domain_id,))
        conn.commit()

    return RedirectResponse("/", status_code=303)


@app.post("/remote-blocklists/{source_id}/update")
def update_remote_blocklist_route(source_id: int) -> RedirectResponse:
    update_remote_blocklist(source_id)
    return RedirectResponse("/", status_code=303)


@app.post("/remote-blocklists/update-all")
def update_all_remote_blocklists_route() -> RedirectResponse:
    sources = [source for source in list_remote_blocklists() if source["enabled"]]
    for source in sources:
        update_remote_blocklist(source["id"])
    return RedirectResponse("/", status_code=303)


@app.post("/devices/manual")
def create_device_manual(
    recovery_name: str = Form(...),
    device_id: str = Form(...),
    token: str = Form(...),
) -> RedirectResponse:
    recovery_name = recovery_name.strip()
    device_id = device_id.strip()
    token = token.strip()

    if not recovery_name or not device_id or len(token) < 8:
        raise HTTPException(status_code=400, detail="Invalid device details")

    try:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO devices (recovery_name, device_id, token, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (recovery_name, device_id, token, utc_iso()),
            )
            conn.commit()
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Device ID already exists") from exc

    return RedirectResponse("/", status_code=303)


@app.post("/api/heartbeat")
def heartbeat(payload: HeartbeatPayload) -> dict[str, str]:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT token FROM devices WHERE device_id = ?",
            (payload.device_id,),
        ).fetchone()

        if row is None or row["token"] != payload.token:
            raise HTTPException(status_code=401, detail="Invalid device credentials")

        conn.execute(
            """
            UPDATE devices
            SET device_name = ?,
                windows_user = ?,
                platform = COALESCE(?, platform),
                private_dns_mode = COALESCE(?, private_dns_mode),
                private_dns_specifier = COALESCE(?, private_dns_specifier),
                vpn_active = COALESCE(?, vpn_active),
                battery_optimization_ignored = COALESCE(?, battery_optimization_ignored),
                agent_version = ?,
                status = ?,
                last_seen_at = ?
            WHERE device_id = ?
            """,
            (
                payload.device_name,
                payload.windows_user,
                payload.platform,
                payload.private_dns_mode,
                payload.private_dns_specifier,
                payload.vpn_active,
                payload.battery_optimization_ignored,
                payload.agent_version,
                payload.status,
                utc_iso(),
                payload.device_id,
            ),
        )
        conn.commit()

    return {"ok": "true", "message": "heartbeat accepted"}


@app.post("/api/activate")
def activate(payload: ActivationPayload) -> dict[str, str]:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT device_id, recovery_name FROM devices WHERE token = ?",
            (payload.enrollment_token,),
        ).fetchone()

        if row is None:
            raise HTTPException(status_code=401, detail="Invalid activation token")

        conn.execute(
            """
            UPDATE devices
            SET device_name = ?,
                windows_user = ?,
                platform = COALESCE(?, platform),
                private_dns_mode = COALESCE(?, private_dns_mode),
                private_dns_specifier = COALESCE(?, private_dns_specifier),
                vpn_active = COALESCE(?, vpn_active),
                battery_optimization_ignored = COALESCE(?, battery_optimization_ignored),
                agent_version = ?,
                status = ?,
                last_seen_at = ?
            WHERE token = ?
            """,
            (
                payload.device_name,
                payload.windows_user,
                payload.platform,
                payload.private_dns_mode,
                payload.private_dns_specifier,
                payload.vpn_active,
                payload.battery_optimization_ignored,
                payload.agent_version,
                "running",
                utc_iso(),
                payload.enrollment_token,
            ),
        )
        conn.commit()

    return {
        "ok": "true",
        "message": "activated",
        "device_id": row["device_id"],
        "token": payload.enrollment_token,
        "recovery_name": row["recovery_name"],
    }


@app.post("/api/domain-event")
def domain_event(payload: DomainEventPayload) -> dict[str, str]:
    domain = payload.domain.strip().lower().rstrip(".")
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid domain")

    with get_connection() as conn:
        row = conn.execute(
            "SELECT token FROM devices WHERE device_id = ?",
            (payload.device_id,),
        ).fetchone()

        if row is None or row["token"] != payload.token:
            raise HTTPException(status_code=401, detail="Invalid device credentials")

        conn.execute(
            """
            INSERT INTO domain_events (
                device_id,
                domain,
                category,
                decision,
                reason,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                payload.device_id,
                domain,
                payload.category,
                payload.decision,
                payload.reason,
                utc_iso(),
            ),
        )
        conn.commit()

    return {"ok": "true", "message": "domain event recorded"}


@app.post("/api/domain-check")
def domain_check(payload: DomainCheckPayload) -> dict[str, str]:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT token FROM devices WHERE device_id = ?",
            (payload.device_id,),
        ).fetchone()

        if row is None or row["token"] != payload.token:
            raise HTTPException(status_code=401, detail="Invalid device credentials")

    return check_domain_policy(payload.domain)


@app.get("/api/blocklist")
def blocklist_api(device_id: str, token: str) -> dict[str, Any]:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT token FROM devices WHERE device_id = ?",
            (device_id,),
        ).fetchone()

        if row is None or row["token"] != token:
            raise HTTPException(status_code=401, detail="Invalid device credentials")

    return {
        "blocked_domains": list_blocked_domains(),
        "blocked_keywords": list_blocked_keywords(),
        "generated_at": utc_iso(),
    }


@app.get("/api/devices")
def devices_api() -> dict[str, Any]:
    return {"devices": list_devices(), "generated_at": utc_iso()}
