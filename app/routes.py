import datetime
import uuid
import qrcode
import os
import re
import subprocess
import threading
import time
import io
import zipfile
import shutil
import shlex
from pathlib import Path
from fastapi import APIRouter, Request, Form, Depends, HTTPException, status, UploadFile, File
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, JSONResponse, StreamingResponse
from app.database import get_db_connection, init_db
from app.audit import get_events, log_event
from app.cascade import (
    active_cascade_rules, apply_cascade, clear_cascade_rules, get_cascade_settings,
    set_cascade_setting, validate_port, validate_target_ip, create_remote_cascade_client,
    remote_client_action
)
from app.auth import (
    get_current_admin, check_password_change_required, verify_password,
    get_password_hash, create_access_token
)
from app.config import (
    BASE_DIR, CLIENTS_DIR, QR_DIR, SERVER_PUBLIC_IP, AWG_PORT, AWG_CONFIG_FILE,
    DATA_DIR, logger
)
from app.vpn_manager import (
    check_awg_interface_status, generate_keypair, get_next_free_ip,
    generate_client_config, generate_legacy_client_config, generate_preshared_key,
    format_bytes, get_client_connection_statuses, get_clients_traffic_usage, get_dashboard_stats,
    get_split_tunnel_routes, get_split_tunnel_routes_text, refresh_client_traffic_usage,
    rebuild_and_sync_vpn_config, set_split_tunnel_routes_text, enforce_expired_clients
)
from app.deeplink import generate_amnezia_deeplink, generate_amnezia_payload
from app.qr_series import render_qr_png, split_amnezia_qr_payload

router = APIRouter(tags=["Web UI"])
templates = Jinja2Templates(directory="app/templates")
LOGIN_FAILURES: dict[str, list[float]] = {}
LOGIN_LIMIT_WINDOW_SECONDS = 10 * 60
LOGIN_BLOCK_SECONDS = 10 * 60
LOGIN_MAX_FAILURES = 5

SPLIT_TUNNEL_PRESETS = {
    "Telegram": ["telegram.org", "t.me", "tdesktop.com"],
    "Discord": ["discord.com", "discordapp.com", "discord.gg"],
    "YouTube": ["youtube.com", "youtu.be", "googlevideo.com", "ytimg.com"],
    "OpenAI": ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"],
    "Cloudflare": ["1.1.1.1/32", "1.0.0.1/32", "cloudflare.com"],
}

# Вспомогательная функция для форматирования дат в шаблонах Jinja
def format_datetime(value: str) -> str:
    try:
        dt = datetime.datetime.fromisoformat(value)
        return dt.strftime("%d.%m.%Y %H:%M")
    except Exception:
        return value

templates.env.filters["datetime"] = format_datetime

def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"

def _is_login_blocked(ip: str) -> bool:
    now = time.time()
    failures = [ts for ts in LOGIN_FAILURES.get(ip, []) if now - ts <= LOGIN_BLOCK_SECONDS]
    LOGIN_FAILURES[ip] = failures
    return len(failures) >= LOGIN_MAX_FAILURES

def _record_login_failure(ip: str) -> None:
    now = time.time()
    failures = [ts for ts in LOGIN_FAILURES.get(ip, []) if now - ts <= LOGIN_LIMIT_WINDOW_SECONDS]
    failures.append(now)
    LOGIN_FAILURES[ip] = failures

def _clear_login_failures(ip: str) -> None:
    LOGIN_FAILURES.pop(ip, None)

def _validated_int_setting(name: str, value: str, min_value: int, max_value: int) -> str:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError(f"{name}: нужно целое число")
    if number < min_value or number > max_value:
        raise ValueError(f"{name}: значение должно быть от {min_value} до {max_value}")
    return str(number)

def _check_udp_port(port: str) -> dict:
    try:
        number = int(str(port).strip())
        if 1 <= number <= 65535:
            return {"ok": True, "message": f"UDP {number} настроен"}
        return {"ok": False, "message": f"UDP {port}: порт должен быть от 1 до 65535"}
    except Exception as exc:
        return {"ok": False, "message": f"UDP {port}: {exc}"}

def _diagnostic_checks() -> list[dict]:
    from app.vpn_manager import get_vpn_setting, LEGACY_CONFIG_FILE, LEGACY_INTERFACE

    public_ip = get_vpn_setting("public_ip", SERVER_PUBLIC_IP)
    web_path = os.getenv("PANEL_WEB_PATH", "")
    cert_path = Path(f"/etc/letsencrypt/live/{public_ip}/fullchain.pem")
    checks = [
        {"name": "Panel process", "ok": True, "message": "веб-панель отвечает"},
        {"name": "Amnezia 2.0 interface", "ok": os.path.exists("/sys/class/net/awg0"), "message": "awg0 найден" if os.path.exists("/sys/class/net/awg0") else "awg0 не найден"},
        {"name": "Amnezia 1 / Legacy interface", "ok": os.path.exists(f"/sys/class/net/{LEGACY_INTERFACE}"), "message": f"{LEGACY_INTERFACE} найден" if os.path.exists(f"/sys/class/net/{LEGACY_INTERFACE}") else f"{LEGACY_INTERFACE} не найден"},
        {"name": "Amnezia 2.0 config", "ok": AWG_CONFIG_FILE.exists(), "message": str(AWG_CONFIG_FILE)},
        {"name": "Amnezia 1 / Legacy config", "ok": LEGACY_CONFIG_FILE.exists(), "message": str(LEGACY_CONFIG_FILE)},
        {"name": "HTTPS certificate", "ok": cert_path.exists(), "message": str(cert_path) if cert_path.exists() else "сертификат для IP/домена не найден"},
        {"name": "Secret web path", "ok": bool(web_path), "message": web_path or "секретный путь не задан"},
    ]

    legacy_text = LEGACY_CONFIG_FILE.read_text(errors="ignore") if LEGACY_CONFIG_FILE.exists() else ""
    checks.append({
        "name": "Legacy without S3/S4",
        "ok": "S3 =" not in legacy_text and "S4 =" not in legacy_text,
        "message": "S3/S4 отсутствуют" if "S3 =" not in legacy_text and "S4 =" not in legacy_text else "S3/S4 найдены в Legacy",
    })

    return checks

def _vpn_config_checks() -> list[dict]:
    from app.vpn_manager import get_vpn_setting, LEGACY_CONFIG_FILE

    port = get_vpn_setting("port", str(AWG_PORT))
    legacy_port = get_vpn_setting("legacy_port", "43913")
    checks = [
        {"name": "Different UDP ports", "ok": port != legacy_port, "message": f"2.0: {port}, Legacy: {legacy_port}"},
        {"name": "Amnezia 2.0 UDP port", **_check_udp_port(port)},
        {"name": "Legacy UDP port", **_check_udp_port(legacy_port)},
    ]
    legacy_text = LEGACY_CONFIG_FILE.read_text(errors="ignore") if LEGACY_CONFIG_FILE.exists() else ""
    checks.append({
        "name": "Legacy excludes S3/S4",
        "ok": "S3 =" not in legacy_text and "S4 =" not in legacy_text,
        "message": "OK" if "S3 =" not in legacy_text and "S4 =" not in legacy_text else "Legacy config contains S3/S4",
    })
    return checks

def _bool_check(name: str, ok: bool, good: str, bad: str) -> dict:
    return {"name": name, "ok": bool(ok), "message": good if ok else bad}

def _client_health_checks(client: dict) -> list[dict]:
    connection_statuses = get_client_connection_statuses()
    traffic_usage = get_clients_traffic_usage()
    connection = connection_statuses.get(client["public_key"], {})
    usage = traffic_usage.get(client["public_key"], {})
    preshared_key = client.get("preshared_key") or ""
    legacy_config = generate_legacy_client_config(
        client["ip_address"], client["private_key"], preshared_key=preshared_key
    )
    v2_config = generate_client_config(
        client["ip_address"], client["private_key"], preshared_key=preshared_key
    )
    split_config = generate_client_config(
        client["ip_address"], client["private_key"], split_tunnel=True, preshared_key=preshared_key
    )
    checks = [
        _bool_check("Клиент найден в базе", True, client["name"], "Клиент не найден"),
        _bool_check(
            "Peer есть на сервере",
            bool(connection),
            f"интерфейс: {connection.get('interface', 'неизвестно')}",
            "peer пока не найден в awg show",
        ),
        _bool_check(
            "Amnezia 1 без S3/S4",
            "S3 =" not in legacy_config and "S4 =" not in legacy_config,
            "Legacy-конфиг совместим с Amnezia 1",
            "Legacy-конфиг содержит S3/S4",
        ),
        _bool_check(
            "Amnezia 2.0 содержит S3/S4",
            "S3 =" in v2_config and "S4 =" in v2_config,
            "Amnezia 2.0-конфиг полный",
            "В Amnezia 2.0-конфиге не хватает S3/S4",
        ),
        _bool_check(
            "Split-конфиг отличается от full",
            "AllowedIPs = 0.0.0.0/0, ::/0" not in split_config,
            "AllowedIPs ограничены split-маршрутами",
            "Split сейчас выглядит как полный туннель",
        ),
    ]
    if connection.get("latest_handshake"):
        checks.append({
            "name": "Последний handshake",
            "ok": True,
            "message": _last_seen_text(connection.get("seconds_ago")),
        })
    else:
        checks.append({"name": "Последний handshake", "ok": False, "message": "подключений еще не было"})
    checks.append({
        "name": "Трафик на сервере",
        "ok": True,
        "message": f"{format_bytes(int(usage.get('rx', 0)))} received / {format_bytes(int(usage.get('tx', 0)))} sent",
    })
    return checks

def _security_checks(user: dict) -> list[dict]:
    from app.auth import verify_password
    from app.vpn_manager import get_vpn_setting

    panel_domain = get_panel_setting("panel_domain", os.getenv("PANEL_DOMAIN", ""))
    panel_port = get_panel_setting("panel_port", os.getenv("PANEL_PORT", "80"))
    web_path = os.getenv("PANEL_WEB_PATH", "")
    https_enabled = os.getenv("PANEL_HTTPS", "") == "1"
    api_token = os.getenv("TELEGRAM_API_TOKEN") or os.getenv("API_TOKEN") or ""
    public_ip = get_vpn_setting("public_ip", SERVER_PUBLIC_IP)
    cert_name = os.getenv("PANEL_CERT_NAME", panel_domain or public_ip)
    cert_candidates = [
        Path(f"/etc/letsencrypt/live/{cert_name}/fullchain.pem"),
        Path(f"/etc/letsencrypt/live/{public_ip}/fullchain.pem"),
    ]
    if panel_domain:
        cert_candidates.append(Path(f"/etc/letsencrypt/live/{panel_domain}/fullchain.pem"))
    cert_exists = any(path.exists() for path in cert_candidates)
    default_password = verify_password("admin", user.get("password_hash", ""))
    https_message = "HTTPS включен через nginx-proxy"
    if cert_exists:
        https_message = "сертификат найден и HTTPS включен"
    return [
        _bool_check("HTTPS", https_enabled, https_message, "HTTPS выключен"),
        _bool_check("Секретный web path", bool(web_path and web_path != "/"), web_path or "не задан", "секретный путь не задан"),
        _bool_check("Пароль администратора", not default_password and not user.get("must_change_password"), "пароль не стандартный", "нужно сменить admin/admin"),
        _bool_check("API token", len(api_token) >= 24, "токен задан", "токен пустой или слишком короткий"),
        _bool_check("Порт панели", str(panel_port) not in {"80", "8080"}, f"порт {panel_port}", "лучше использовать нестандартный порт за HTTPS/proxy"),
        _bool_check("Домен панели", bool(panel_domain), panel_domain or "домен не задан", "домен не задан, используется IP"),
    ]

def _panel_update_info() -> dict:
    default_project_dir = "/root/Blits-Amnezia.WG" if str(BASE_DIR) == "/app" else str(BASE_DIR)
    project_dir = os.getenv("BLITZ_PROJECT_DIR", default_project_dir)
    command = f"cd {shlex.quote(project_dir)} && git pull origin main && docker compose --profile ssl up -d --build"
    enabled = os.getenv("BLITZ_ENABLE_WEB_UPDATE", "0") == "1"
    current = "unknown"
    try:
        proc = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=BASE_DIR, capture_output=True, text=True, timeout=5)
        if proc.returncode == 0:
            current = proc.stdout.strip()
    except Exception:
        pass
    return {
        "enabled": enabled,
        "current": current,
        "project_dir": project_dir,
        "command": command,
        "note": "Web-обновление выключено по умолчанию. Включается только env BLITZ_ENABLE_WEB_UPDATE=1.",
    }

PANEL_ENV_FILE = DATA_DIR / "panel.env"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")

def get_panel_setting(key: str, default: str) -> str:
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        if row:
            return row["value"]
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, default))
        conn.commit()
        return default
    finally:
        conn.close()

def set_panel_setting(key: str, value: str):
    conn = get_db_connection()
    try:
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
        conn.commit()
    finally:
        conn.close()

def _read_panel_env() -> dict[str, str]:
    values = {}
    if PANEL_ENV_FILE.exists():
        for line in PANEL_ENV_FILE.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def _write_panel_env(values: dict[str, str]):
    PANEL_ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    env = _read_panel_env()
    env.update({key: value for key, value in values.items() if value is not None})
    lines = [f"{key}={env[key]}" for key in sorted(env)]
    PANEL_ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(PANEL_ENV_FILE, 0o600)
    except Exception:
        pass


def write_panel_env(port: str):
    _write_panel_env({"PANEL_PORT": port})

def restart_panel_service_later(delay_seconds: float = 1.0):
    def _restart():
        time.sleep(delay_seconds)
        try:
            subprocess.run(["systemctl", "daemon-reload"], check=False)
            subprocess.run(["systemctl", "restart", "amnezia-panel"], check=False)
        except Exception as exc:
            logger.error(f"Не удалось перезапустить сервис панели: {exc}")
    threading.Thread(target=_restart, daemon=True).start()

# --- СТАТИЧЕСКИЙ ДОСТУП ДЛЯ КЛИЕНТОВ (Скачивание файлов без авторизации по UUID) ---

def _last_seen_text(seconds_ago):
    if seconds_ago is None:
        return "еще не подключался"
    if seconds_ago < 60:
        return "только что"
    if seconds_ago < 3600:
        return f"{seconds_ago // 60} мин назад"
    if seconds_ago < 86400:
        return f"{seconds_ago // 3600} ч назад"
    return f"{seconds_ago // 86400} дн назад"


def _client_view(row: dict, connection_statuses: dict, traffic_usage: dict) -> dict:
    c = dict(row)
    c["display_ip_address"] = c.get("remote_ip_address") or c.get("ip_address")
    now = datetime.datetime.utcnow()
    try:
        expire_dt = datetime.datetime.fromisoformat(c["expires_at"])
        c["is_expired"] = expire_dt < now
    except Exception:
        c["is_expired"] = False

    is_cascade = c.get("route_type") == "cascade"
    connection = {} if is_cascade else connection_statuses.get(c["public_key"], {})
    c["is_online"] = bool(connection.get("online"))
    c["last_seen_text"] = _last_seen_text(connection.get("seconds_ago"))
    c["connected_interface"] = connection.get("interface", "")
    c["transfer_rx_text"] = format_bytes(int(connection.get("transfer_rx", 0)))
    c["transfer_tx_text"] = format_bytes(int(connection.get("transfer_tx", 0)))

    live_usage = traffic_usage.get(c["public_key"], {})
    used_bytes = max(int(c.get("traffic_used_bytes") or 0), int(live_usage.get("total", 0)))
    limit_gb = float(c.get("traffic_limit_gb") or 0)
    limit_bytes = int(limit_gb * 1024 * 1024 * 1024) if limit_gb > 0 else 0
    c["traffic_used_bytes_current"] = used_bytes
    c["traffic_used_text"] = format_bytes(used_bytes)
    c["traffic_limit_text"] = f"{limit_gb:g} GB" if limit_gb > 0 else "Безлимит"
    c["traffic_percent"] = min(100, round(used_bytes / limit_bytes * 100)) if limit_bytes else 0
    c["traffic_limit_exceeded"] = bool(limit_bytes and used_bytes >= limit_bytes)

    if is_cascade:
        c["config_text"] = c.get("config_text_v2") or ""
        c["config_text_legacy"] = c.get("config_text_legacy") or c["config_text"]
        c["config_text_split"] = c.get("config_text_split_v2") or c["config_text"]
        c["config_text_split_legacy"] = c.get("config_text_split_legacy") or c["config_text_legacy"]
        c["deep_link"] = generate_amnezia_deeplink(c["config_text_legacy"], version="1.0", client_public_key=c["public_key"], client_name=c["name"])
        c["deep_link_v2"] = generate_amnezia_deeplink(c["config_text"], version="2.0", client_public_key=c["public_key"], client_name=c["name"])
        c["deep_link_split"] = generate_amnezia_deeplink(c["config_text_split_legacy"], version="1.0", client_public_key=c["public_key"], split_tunnel=True, client_name=c["name"])
        c["deep_link_split_v2"] = generate_amnezia_deeplink(c["config_text_split"], version="2.0", client_public_key=c["public_key"], split_tunnel=True, client_name=c["name"])
        return c

    c["config_text"] = generate_client_config(c["ip_address"], c["private_key"], preshared_key=c["preshared_key"])
    c["config_text_legacy"] = generate_legacy_client_config(c["ip_address"], c["private_key"], preshared_key=c["preshared_key"])
    c["deep_link"] = generate_amnezia_deeplink(c["config_text_legacy"], version="1.0", client_public_key=c["public_key"], client_name=c["name"])
    c["deep_link_v2"] = generate_amnezia_deeplink(c["config_text"], version="2.0", client_public_key=c["public_key"], client_name=c["name"])
    c["config_text_split"] = generate_client_config(c["ip_address"], c["private_key"], split_tunnel=True, preshared_key=c["preshared_key"])
    c["config_text_split_legacy"] = generate_legacy_client_config(c["ip_address"], c["private_key"], split_tunnel=True, preshared_key=c["preshared_key"])
    c["deep_link_split"] = generate_amnezia_deeplink(c["config_text_split_legacy"], version="1.0", client_public_key=c["public_key"], split_tunnel=True, client_name=c["name"])
    c["deep_link_split_v2"] = generate_amnezia_deeplink(c["config_text_split"], version="2.0", client_public_key=c["public_key"], split_tunnel=True, client_name=c["name"])
    return c


@router.get("/clients/{client_id}/download")
async def download_client_conf(client_id: str, split: bool = False, version: str = "2.0"):
    """
    Отдает файл .conf по UUID клиента. Доступно без авторизации.
    """
    conn = get_db_connection()
    client = conn.execute("SELECT * FROM clients WHERE id = ? AND deleted_at IS NULL", (client_id,)).fetchone()
    conn.close()
    
    if not client:
        raise HTTPException(status_code=404, detail="Клиент не найден")
        
    version_suffix = "_legacy" if version == "1.0" else "_v2"
    filename = f"{client['name']}{'_split' if split else ''}{version_suffix}.conf"
    if client["route_type"] == "cascade":
        filename = f"{client['name']}{'_split' if split else ''}_cascade{version_suffix}.conf"
        if split and version == "1.0":
            config_text = client["config_text_split_legacy"] or client["config_text_legacy"] or client["config_text_v2"]
        elif split:
            config_text = client["config_text_split_v2"] or client["config_text_v2"]
        elif version == "1.0":
            config_text = client["config_text_legacy"] or client["config_text_v2"]
        else:
            config_text = client["config_text_v2"]
    elif version == "1.0":
        config_text = generate_legacy_client_config(client['ip_address'], client['private_key'], split_tunnel=split, preshared_key=client['preshared_key'])
    else:
        config_text = generate_client_config(client['ip_address'], client['private_key'], split_tunnel=split, preshared_key=client['preshared_key'])
    
    import urllib.parse
    from fastapi import Response
    
    content_disposition_filename = urllib.parse.quote(filename)
    if content_disposition_filename != filename:
        disposition = f"attachment; filename*=utf-8''{content_disposition_filename}"
    else:
        disposition = f'attachment; filename="{filename}"'
        
    return Response(
        content=config_text,
        media_type="application/octet-stream",
        headers={"Content-Disposition": disposition}
    )

def _get_client_config_for_export(client: dict, split: bool, version: str) -> str:
    if client["route_type"] == "cascade":
        if split and version == "1.0":
            return client["config_text_split_legacy"] or client["config_text_legacy"] or client["config_text_v2"]
        if split:
            return client["config_text_split_v2"] or client["config_text_v2"]
        if version == "1.0":
            return client["config_text_legacy"] or client["config_text_v2"]
        return client["config_text_v2"]
    if version == "1.0":
        return generate_legacy_client_config(
            client["ip_address"],
            client["private_key"],
            split_tunnel=split,
            preshared_key=client["preshared_key"],
        )
    return generate_client_config(
        client["ip_address"],
        client["private_key"],
        split_tunnel=split,
        preshared_key=client["preshared_key"],
    )


def _get_amnezia_qr_parts(client: dict, split: bool, version: str) -> list[str]:
    config_text = _get_client_config_for_export(client, split=split, version=version)
    payload = generate_amnezia_payload(
        config_text,
        version=version,
        client_public_key=client["public_key"],
        split_tunnel=split,
        client_name=client["name"],
    )
    if payload:
        return split_amnezia_qr_payload(payload)
    return [config_text]


@router.get("/clients/{client_id}/qr-series")
async def get_client_qr_series(client_id: str, split: bool = False, version: str = "1.0"):
    conn = get_db_connection()
    client = conn.execute("SELECT * FROM clients WHERE id = ? AND deleted_at IS NULL", (client_id,)).fetchone()
    conn.close()

    if not client:
        raise HTTPException(status_code=404, detail="QR code not found")

    parts = _get_amnezia_qr_parts(dict(client), split=split, version=version)
    query_base = f"version={version}&split={'true' if split else 'false'}"
    return JSONResponse({
        "version": version,
        "split": split,
        "count": len(parts),
        "urls": [
            f"/clients/{client_id}/qr?{query_base}&part={index}"
            for index in range(len(parts))
        ],
    })


@router.get("/clients/{client_id}/qr")
async def download_client_qr(client_id: str, split: bool = False, version: str = "1.0", part: int = 0):
    """
    Отдает изображение QR-кода PNG по UUID клиента. Доступно без авторизации.
    """
    conn = get_db_connection()
    client = conn.execute("SELECT * FROM clients WHERE id = ? AND deleted_at IS NULL", (client_id,)).fetchone()
    conn.close()
    
    if not client:
        raise HTTPException(status_code=404, detail="QR-код не найден")
        
    parts = _get_amnezia_qr_parts(dict(client), split=split, version=version)
    if part < 0 or part >= len(parts):
        raise HTTPException(status_code=404, detail="QR part not found")

    from fastapi import Response
    return Response(
        content=render_qr_png(parts[part]),
        media_type="image/png",
        headers={
            "X-Amnezia-QR-Part": str(part + 1),
            "X-Amnezia-QR-Count": str(len(parts)),
        },
    )

# --- СТРАНИЦЫ АВТОРИЗАЦИИ ---

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = None):
    # Если уже авторизован, отправляем на главную
    token = request.cookies.get("access_token")
    if token:
        payload = jwt_decode = {}
        try:
            from app.auth import decode_access_token
            payload = decode_access_token(token)
        except Exception:
            pass
        if payload.get("sub"):
            return RedirectResponse(url="/", status_code=303)
            
    return templates.TemplateResponse(request=request, name="login.html", context={"error": error})

@router.post("/login")
async def login_action(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = _client_ip(request)
    if _is_login_blocked(ip):
        log_event("login_blocked", f"Слишком много ошибок входа с IP {ip}.", meta={"ip": ip, "username": username})
        return templates.TemplateResponse(request=request, name="login.html", context={"error": "Слишком много попыток входа. Подождите 10 минут."}, status_code=429)

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    
    if not user or not verify_password(password, user["password_hash"]):
        _record_login_failure(ip)
        log_event("login_failed", f"Ошибка входа для пользователя {username} с IP {ip}.", meta={"ip": ip, "username": username})
        return templates.TemplateResponse(request=request, name="login.html", context={"error": "Неверное имя пользователя или пароль"})
        
    # Создаем токен
    _clear_login_failures(ip)
    log_event("login_success", f"Успешный вход пользователя {username} с IP {ip}.", meta={"ip": ip, "username": username})
    token = create_access_token(data={"sub": username})
    
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        max_age=86400,
        expires=86400,
        samesite="lax"
    )
    return response

@router.get("/logout")
async def logout_action():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(key="access_token")
    return response

# --- СТРАНИЦЫ АДМИН-ПАНЕЛИ (Защищены авторизацией) ---

@router.get("/diagnostics", response_class=HTMLResponse)
async def diagnostics_page(
    request: Request,
    user: dict = Depends(check_password_change_required)
):
    return templates.TemplateResponse(
        request=request,
        name="diagnostics.html",
        context={
            "user": user,
            "checks": _diagnostic_checks(),
            "current_page": "diagnostics",
        },
    )

@router.get("/settings/vpn/check")
async def check_vpn_config(
    user: dict = Depends(check_password_change_required)
):
    checks = _vpn_config_checks()
    return JSONResponse({"ok": all(item["ok"] for item in checks), "checks": checks})

@router.get("/settings/security/check")
async def check_security_status(
    user: dict = Depends(check_password_change_required)
):
    checks = _security_checks(user)
    return JSONResponse({"ok": all(item["ok"] for item in checks), "checks": checks})

@router.get("/panel/update/status")
async def panel_update_status(
    user: dict = Depends(check_password_change_required)
):
    return JSONResponse(_panel_update_info())

@router.post("/panel/update/run")
async def panel_update_run(
    user: dict = Depends(check_password_change_required)
):
    info = _panel_update_info()
    if not info["enabled"]:
        return JSONResponse({"ok": False, **info}, status_code=403)
    try:
        proc = subprocess.run(
            ["bash", "-lc", info["command"]],
            cwd=info["project_dir"],
            capture_output=True,
            text=True,
            timeout=180,
        )
        log_event("panel_update_requested", "Запущено обновление панели из web UI.", meta={"returncode": proc.returncode})
        return JSONResponse({
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-4000:],
        })
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)

@router.get("/", response_class=HTMLResponse)
@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(
    request: Request,
    user: dict = Depends(check_password_change_required)
):
    enforce_expired_clients()
    conn = get_db_connection()
    # Статистика
    client_count = conn.execute("SELECT COUNT(*) FROM clients WHERE deleted_at IS NULL").fetchone()[0]
    active_count = conn.execute("SELECT COUNT(*) FROM clients WHERE disabled_at IS NULL AND deleted_at IS NULL").fetchone()[0]
    expired_count = 0 # В будущем можно проверять по дате
    
    # Считаем просроченных
    now = datetime.datetime.utcnow().isoformat()
    expired_rows = conn.execute("SELECT COUNT(*) FROM clients WHERE expires_at < ? AND deleted_at IS NULL", (now,)).fetchone()[0]
    expired_count = expired_rows
    
    conn.close()
    
    # Статус AmneziaWG
    awg_status = check_awg_interface_status()
    dashboard_stats = get_dashboard_stats()
    
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "user": user,
            "client_count": client_count,
            "active_count": active_count,
            "expired_count": expired_count,
            "awg_status": awg_status,
            "public_ip": SERVER_PUBLIC_IP,
            "awg_port": AWG_PORT,
            "config_path": str(AWG_CONFIG_FILE),
            "stats": dashboard_stats,
            "security_checks": _security_checks(user),
            "panel_update": _panel_update_info(),
            "current_page": "dashboard"
        }
    )

@router.get("/dashboard/stats")
async def dashboard_stats_api(user: dict = Depends(check_password_change_required)):
    enforce_expired_clients()
    refresh_client_traffic_usage(enforce_limits=True)
    conn = get_db_connection()
    client_count = conn.execute("SELECT COUNT(*) FROM clients WHERE deleted_at IS NULL").fetchone()[0]
    active_count = conn.execute("SELECT COUNT(*) FROM clients WHERE disabled_at IS NULL AND deleted_at IS NULL").fetchone()[0]
    now = datetime.datetime.utcnow().isoformat()
    expired_count = conn.execute("SELECT COUNT(*) FROM clients WHERE expires_at < ? AND deleted_at IS NULL", (now,)).fetchone()[0]
    conn.close()

    return JSONResponse({
        "client_count": client_count,
        "active_count": active_count,
        "expired_count": expired_count,
        "awg_status": check_awg_interface_status(),
        "stats": get_dashboard_stats(),
    })

@router.get("/clients", response_class=HTMLResponse)
async def clients_page(
    request: Request,
    user: dict = Depends(check_password_change_required),
    search: str = ""
):
    enforce_expired_clients()
    refresh_client_traffic_usage(enforce_limits=True)
    conn = get_db_connection()
    if search:
        query = "%" + search + "%"
        clients_rows = conn.execute(
            "SELECT * FROM clients WHERE deleted_at IS NULL AND (name LIKE ? OR ip_address LIKE ?) ORDER BY created_at DESC",
            (query, query)
        ).fetchall()
    else:
        clients_rows = conn.execute(
            "SELECT * FROM clients WHERE deleted_at IS NULL ORDER BY created_at DESC"
        ).fetchall()
    conn.close()
    
    clients = []
    connection_statuses = get_client_connection_statuses()
    traffic_usage = get_clients_traffic_usage()

    for row in clients_rows:
        clients.append(_client_view(dict(row), connection_statuses, traffic_usage))
    return templates.TemplateResponse(
        request=request,
        name="clients.html",
        context={
            "user": user,
            "clients": clients,
            "search": search,
            "cascade": get_cascade_settings(),
            "current_page": "clients"
        }
    )


@router.get("/clients/{client_id}", response_class=HTMLResponse)
async def client_detail_page(
    request: Request,
    client_id: str,
    user: dict = Depends(check_password_change_required),
):
    enforce_expired_clients()
    refresh_client_traffic_usage(enforce_limits=True)
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM clients WHERE id = ? AND deleted_at IS NULL", (client_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Клиент не найден")

    client = _client_view(dict(row), get_client_connection_statuses(), get_clients_traffic_usage())
    return templates.TemplateResponse(
        request=request,
        name="client_detail.html",
        context={
            "user": user,
            "client": client,
            "checks": _client_health_checks(dict(row)) if dict(row).get("route_type", "local") != "cascade" else [],
            "events": get_events(50),
            "current_page": "clients",
        },
    )

@router.get("/clients/{client_id}/check")
async def check_client_status(
    client_id: str,
    user: dict = Depends(check_password_change_required),
):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM clients WHERE id = ? AND deleted_at IS NULL", (client_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Клиент не найден")
    client = dict(row)
    if client.get("route_type") == "cascade":
        checks = [_bool_check("Каскадный клиент", True, "проверяется на целевой панели", "")]
    else:
        checks = _client_health_checks(client)
    return JSONResponse({"ok": all(item["ok"] for item in checks), "checks": checks})


@router.post("/clients/bulk")
async def bulk_clients_action(
    client_ids: list[str] = Form([]),
    action: str = Form(...),
    days: int = Form(30),
    user: dict = Depends(check_password_change_required),
):
    if not client_ids:
        return RedirectResponse(url="/clients", status_code=303)

    now = datetime.datetime.utcnow()
    conn = get_db_connection()
    try:
        rows = conn.execute(
            f"SELECT id, name, expires_at FROM clients WHERE deleted_at IS NULL AND id IN ({','.join(['?'] * len(client_ids))})",
            client_ids,
        ).fetchall()
        for row in rows:
            if action == "extend":
                val_days = days
                if val_days < 1:
                    val_days = 1
                elif val_days > 36500:
                    val_days = 36500
                try:
                    current_expire = datetime.datetime.fromisoformat(row["expires_at"])
                except Exception:
                    current_expire = now
                base_date = current_expire if current_expire > now else now
                new_expire = (base_date + datetime.timedelta(days=val_days)).isoformat()
                conn.execute("UPDATE clients SET expires_at = ?, disabled_at = NULL WHERE id = ?", (new_expire, row["id"]))
                log_event("client_extended", f"Клиент {row['name']} продлен на {val_days} дн.", row["id"], row["name"])
            elif action == "disable":
                conn.execute("UPDATE clients SET disabled_at = ? WHERE id = ?", (now.isoformat(), row["id"]))
                log_event("client_disabled", f"Клиент {row['name']} отключен массовым действием.", row["id"], row["name"], notify=True)
            elif action == "delete":
                conn.execute("UPDATE clients SET deleted_at = ? WHERE id = ?", (now.isoformat(), row["id"]))
                log_event("client_deleted", f"Клиент {row['name']} удален массовым действием.", row["id"], row["name"], notify=True)
        conn.commit()
    finally:
        conn.close()

    rebuild_and_sync_vpn_config()
    return RedirectResponse(url="/clients", status_code=303)


@router.get("/events", response_class=HTMLResponse)
async def events_page(
    request: Request,
    user: dict = Depends(check_password_change_required),
):
    return templates.TemplateResponse(
        request=request,
        name="events.html",
        context={
            "user": user,
            "events": get_events(300),
            "current_page": "events",
        },
    )


@router.get("/backup/download")
async def download_backup(user: dict = Depends(check_password_change_required)):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        db_path = DATA_DIR / "panel.db"
        if db_path.exists():
            archive.write(db_path, "data/panel.db")
        env_path = DATA_DIR / "panel.env"
        if env_path.exists():
            archive.write(env_path, "data/panel.env")
        for path in (AWG_CONFIG_FILE, Path("/etc/amnezia/amneziawg/awg_legacy.conf")):
            if path.exists():
                archive.write(path, f"vpn/{path.name}")
    buffer.seek(0)
    filename = datetime.datetime.utcnow().strftime("blitz-panel-backup-%Y%m%d-%H%M%S.zip")
    log_event("backup", "Скачан резервный архив панели.")
    return StreamingResponse(
        buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )

@router.get("/backup/download/db")
async def download_database_backup(user: dict = Depends(check_password_change_required)):
    db_path = DATA_DIR / "panel.db"
    if not db_path.exists():
        raise HTTPException(status_code=404, detail="Database not found")
    filename = datetime.datetime.utcnow().strftime("blitz-panel-db-%Y%m%d-%H%M%S.db")
    log_event("backup_db", "Скачана резервная копия базы клиентов.")
    return FileResponse(db_path, media_type="application/octet-stream", filename=filename)

@router.get("/backup/download/settings")
async def download_settings_backup(user: dict = Depends(check_password_change_required)):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in (DATA_DIR / "panel.env", AWG_CONFIG_FILE, Path("/etc/amnezia/amneziawg/awg_legacy.conf")):
            if path.exists():
                archive.write(path, f"settings/{path.name}")
    buffer.seek(0)
    filename = datetime.datetime.utcnow().strftime("blitz-panel-settings-%Y%m%d-%H%M%S.zip")
    log_event("backup_settings", "Скачана резервная копия настроек панели и VPN.")
    return StreamingResponse(
        buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.post("/backup/restore")
async def restore_backup(
    backup_file: UploadFile = File(...),
    user: dict = Depends(check_password_change_required),
):
    try:
        content = await backup_file.read()
        with zipfile.ZipFile(io.BytesIO(content), "r") as archive:
            names = set(archive.namelist())
            if "data/panel.db" not in names:
                return RedirectResponse(url="/dashboard?backup_error=invalid", status_code=303)

            timestamp = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
            current_db = DATA_DIR / "panel.db"
            if current_db.exists():
                shutil.copy2(current_db, DATA_DIR / f"panel.before-restore-{timestamp}.db")

            DATA_DIR.mkdir(parents=True, exist_ok=True)
            current_db.write_bytes(archive.read("data/panel.db"))

            if "data/panel.env" in names:
                env_path = DATA_DIR / "panel.env"
                env_path.write_bytes(archive.read("data/panel.env"))
                try:
                    os.chmod(env_path, 0o600)
                except Exception:
                    pass

            config_targets = {
                "vpn/awg0.conf": AWG_CONFIG_FILE,
                "vpn/awg_legacy.conf": Path("/etc/amnezia/amneziawg/awg_legacy.conf"),
            }
            for archive_name, target in config_targets.items():
                if archive_name in names:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.read(archive_name))

        init_db()
        rebuild_and_sync_vpn_config()
        log_event("backup_restore", "Восстановлен резервный архив панели.", notify=True)
        return RedirectResponse(url="/dashboard?backup_restored=1", status_code=303)
    except zipfile.BadZipFile:
        return RedirectResponse(url="/dashboard?backup_error=zip", status_code=303)
    except Exception as exc:
        logger.error(f"Backup restore failed: {exc}")
        return RedirectResponse(url="/dashboard?backup_error=failed", status_code=303)

@router.post("/clients/create")
async def web_create_client(
    name: str = Form(...),
    days: int = Form(30),
    traffic_limit_gb: float = Form(0.0),
    route_type: str = Form("local"),
    user: dict = Depends(check_password_change_required)
):
    # Санация имени клиента
    name = re.sub(r'[\r\n]', ' ', name).strip()
    name = re.sub(r'[\\\'"`;|&<>$]', '', name)
    if not name:
        name = "client"

    # Валидация дней
    if days < 1:
        days = 1
    elif days > 36500:
        days = 36500

    client_id = str(uuid.uuid4())
    logger.info(f"Создание клиента через UI: '{name}' (id: {client_id})")
    
    try:
        if route_type == "cascade":
            cascade_client = create_remote_cascade_client(name, days, traffic_limit_gb)
            remote = cascade_client["remote"]
            now = datetime.datetime.utcnow()
            conn = get_db_connection()
            conn.execute(
                """
                INSERT INTO clients (
                    id, name, telegram_id, ip_address, public_key, private_key, preshared_key,
                    traffic_limit_gb, traffic_used_bytes, expires_at, created_at, route_type,
                    remote_client_id, remote_ip_address, config_text_v2, config_text_legacy,
                    config_text_split_v2, config_text_split_legacy
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    client_id, name, None, f"cascade:{remote['client_id']}", remote["public_key"], "", "",
                    traffic_limit_gb, 0, remote["expires_at"], now.isoformat(), "cascade",
                    remote["client_id"], cascade_client["remote_ip_address"],
                    cascade_client["config_text_v2"], cascade_client["config_text_legacy"],
                    cascade_client["config_text_split_v2"], cascade_client["config_text_split_legacy"],
                ),
            )
            conn.commit()
            conn.close()
            log_event("client_created", f"Создан каскадный клиент {name}.", client_id, name, notify=True)
            return RedirectResponse(url="/clients", status_code=303)
        # Генерируем ключи и IP
        client_private_key, client_public_key = generate_keypair()
        preshared_key = generate_preshared_key()
        client_ip = get_next_free_ip()
        
        now = datetime.datetime.utcnow()
        created_at = now.isoformat()
        expires_at = (now + datetime.timedelta(days=days)).isoformat()
        
        conn = get_db_connection()
        conn.execute(
            """
            INSERT INTO clients (
                id, name, telegram_id, ip_address, public_key, private_key, preshared_key,
                traffic_limit_gb, traffic_used_bytes, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                client_id, name, None, client_ip,
                client_public_key, client_private_key, preshared_key, traffic_limit_gb,
                0, expires_at, created_at
            )
        )
        conn.commit()
        conn.close()
        
        # Запись файлов
        config_text = generate_client_config(client_ip, client_private_key, preshared_key=preshared_key)
        with open(CLIENTS_DIR / f"{client_id}.conf", "w") as f:
            f.write(config_text)
            
        # Генерация QR
        qr = qrcode.QRCode(version=1, box_size=10, border=3)
        qr.add_data(config_text)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_img.save(QR_DIR / f"{client_id}.png")
        
        # Пересборка
        rebuild_and_sync_vpn_config()
        log_event("client_created", f"Создан клиент {name}.", client_id, name, notify=True)
        
    except Exception as e:
        logger.error(f"Ошибка создания клиента через Web UI: {e}")
        
    return RedirectResponse(url="/clients", status_code=303)

@router.post("/clients/{client_id}/disable")
async def web_disable_client(
    client_id: str,
    user: dict = Depends(check_password_change_required)
):
    conn = get_db_connection()
    client = conn.execute("SELECT name, route_type, remote_client_id FROM clients WHERE id = ?", (client_id,)).fetchone()
    if client and client["route_type"] == "cascade" and client["remote_client_id"]:
        remote_client_action(client["remote_client_id"], "disable")
    now = datetime.datetime.utcnow().isoformat()
    conn.execute("UPDATE clients SET disabled_at = ? WHERE id = ?", (now, client_id))
    conn.commit()
    conn.close()
    
    if not client or client["route_type"] != "cascade":
        rebuild_and_sync_vpn_config()
    if client:
        log_event("client_disabled", f"Клиент {client['name']} отключен.", client_id, client["name"], notify=True)
    return RedirectResponse(url="/clients", status_code=303)

@router.post("/clients/{client_id}/enable")
async def web_enable_client(
    client_id: str,
    user: dict = Depends(check_password_change_required)
):
    conn = get_db_connection()
    client = conn.execute("SELECT name, route_type, remote_client_id FROM clients WHERE id = ?", (client_id,)).fetchone()
    if client and client["route_type"] == "cascade" and client["remote_client_id"]:
        remote_client_action(client["remote_client_id"], "enable")
    conn.execute("UPDATE clients SET disabled_at = NULL WHERE id = ?", (client_id,))
    conn.commit()
    conn.close()
    
    if not client or client["route_type"] != "cascade":
        rebuild_and_sync_vpn_config()
    if client:
        log_event("client_enabled", f"Клиент {client['name']} включен.", client_id, client["name"])
    return RedirectResponse(url="/clients", status_code=303)

@router.post("/clients/{client_id}/extend")
async def web_extend_client(
    client_id: str,
    days: int = Form(30),
    user: dict = Depends(check_password_change_required)
):
    if days < 1:
        days = 1
    elif days > 36500:
        days = 36500
    conn = get_db_connection()
    client = conn.execute("SELECT name, expires_at, route_type, remote_client_id FROM clients WHERE id = ?", (client_id,)).fetchone()
    if client:
        if client["route_type"] == "cascade" and client["remote_client_id"]:
            remote_client_action(client["remote_client_id"], "extend", days)
        try:
            current_expire = datetime.datetime.fromisoformat(client['expires_at'])
        except Exception:
            current_expire = datetime.datetime.utcnow()
            
        now = datetime.datetime.utcnow()
        base_date = current_expire if current_expire > now else now
        new_expire = (base_date + datetime.timedelta(days=days)).isoformat()
        
        conn.execute("UPDATE clients SET expires_at = ?, disabled_at = NULL WHERE id = ?", (new_expire, client_id))
        conn.commit()
        
    conn.close()
    if not client or client["route_type"] != "cascade":
        rebuild_and_sync_vpn_config()
    if client:
        log_event("client_extended", f"Клиент {client['name']} продлен на {days} дн.", client_id, client["name"])
    return RedirectResponse(url="/clients", status_code=303)

@router.post("/clients/{client_id}/delete")
async def web_delete_client(
    client_id: str,
    user: dict = Depends(check_password_change_required)
):
    conn = get_db_connection()
    client = conn.execute("SELECT name, route_type, remote_client_id FROM clients WHERE id = ?", (client_id,)).fetchone()
    if client and client["route_type"] == "cascade" and client["remote_client_id"]:
        remote_client_action(client["remote_client_id"], "delete")
    now = datetime.datetime.utcnow().isoformat()
    conn.execute("UPDATE clients SET deleted_at = ? WHERE id = ?", (now, client_id))
    conn.commit()
    conn.close()
    
    if not client or client["route_type"] != "cascade":
        rebuild_and_sync_vpn_config()
    if client:
        log_event("client_deleted", f"Клиент {client['name']} удален.", client_id, client["name"], notify=True)
    return RedirectResponse(url="/clients", status_code=303)

# --- СТРАНИЦА СМЕНЫ ПАРОЛЯ ---

@router.get("/settings/password", response_class=HTMLResponse)
async def change_password_page(
    request: Request,
    user: dict = Depends(get_current_admin)
):
    return templates.TemplateResponse(
        request=request,
        name="password.html",
        context={
            "user": user,
            "current_page": "password",
            "must_change": user.get("must_change_password") == 1
        }
    )

@router.post("/settings/password")
async def change_password_action(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: dict = Depends(get_current_admin)
):
    # Валидация
    if new_password != confirm_password:
        return templates.TemplateResponse(
            request=request,
            name="password.html",
            context={
                "user": user,
                "error": "Новые пароли не совпадают",
                "must_change": user.get("must_change_password") == 1
            }
        )
        
    if not verify_password(current_password, user["password_hash"]):
        return templates.TemplateResponse(
            request=request,
            name="password.html",
            context={
                "user": user,
                "error": "Неверный текущий пароль",
                "must_change": user.get("must_change_password") == 1
            }
        )
        
    # Обновление пароля
    hashed_password = get_password_hash(new_password)
    conn = get_db_connection()
    conn.execute(
        "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
        (hashed_password, user["id"])
    )
    conn.commit()
    conn.close()
    
    logger.info("Администратор успешно сменил пароль.")
    
    # После успешной смены перенаправляем на дашборд с уведомлением
    return templates.TemplateResponse(
        request=request,
        name="password.html",
        context={
            "user": {**user, "must_change_password": 0},
            "success": "Пароль успешно изменен!",
            "must_change": False
        }
    )

# --- СТРАНИЦА НАСТРОЕК VPN ---

@router.get("/settings/vpn", response_class=HTMLResponse)
async def vpn_settings_page(
    request: Request,
    user: dict = Depends(check_password_change_required)
):
    from app.vpn_manager import get_vpn_setting
    
    # Загружаем настройки из БД
    settings = {
        "public_ip": get_vpn_setting("public_ip", SERVER_PUBLIC_IP),
        "port": get_vpn_setting("port", str(AWG_PORT)),
        "legacy_port": get_vpn_setting("legacy_port", "43913"),
        "dns": get_vpn_setting("dns", "1.1.1.1, 1.0.0.1"),
        "jc": get_vpn_setting("jc", "4"),
        "jmin": get_vpn_setting("jmin", "10"),
        "jmax": get_vpn_setting("jmax", "50"),
        "s1": get_vpn_setting("s1", "61"),
        "s2": get_vpn_setting("s2", "34"),
        "s3": get_vpn_setting("s3", "21"),
        "s4": get_vpn_setting("s4", "2"),
        "h1": get_vpn_setting("h1", "906396796-1598714541"),
        "h2": get_vpn_setting("h2", "2056848576-2126223526"),
        "h3": get_vpn_setting("h3", "2141047196-2144456894"),
        "h4": get_vpn_setting("h4", "2146243463-2147170402"),
        "legacy_jc": get_vpn_setting("legacy_jc", get_vpn_setting("jc", "4")),
        "legacy_jmin": get_vpn_setting("legacy_jmin", get_vpn_setting("jmin", "10")),
        "legacy_jmax": get_vpn_setting("legacy_jmax", get_vpn_setting("jmax", "50")),
        "legacy_s1": get_vpn_setting("legacy_s1", get_vpn_setting("s1", "61")),
        "legacy_s2": get_vpn_setting("legacy_s2", get_vpn_setting("s2", "34")),
        "legacy_h1": get_vpn_setting("legacy_h1", get_vpn_setting("h1", "906396796-1598714541")),
        "legacy_h2": get_vpn_setting("legacy_h2", get_vpn_setting("h2", "2056848576-2126223526")),
        "legacy_h3": get_vpn_setting("legacy_h3", get_vpn_setting("h3", "2141047196-2144456894")),
        "legacy_h4": get_vpn_setting("legacy_h4", get_vpn_setting("h4", "2146243463-2147170402")),
        "split_tunnel_routes": get_split_tunnel_routes_text(),
        "split_tunnel_route_count": len(get_split_tunnel_routes())
    }
    
    return templates.TemplateResponse(
        request=request,
        name="vpn_settings.html",
        context={
            "user": user,
            "settings": settings,
            "split_presets": SPLIT_TUNNEL_PRESETS,
            "current_page": "vpn_settings"
        }
    )

@router.post("/settings/vpn", response_class=HTMLResponse)
async def save_vpn_settings(
    request: Request,
    public_ip: str = Form(...),
    port: str = Form(...),
    legacy_port: str = Form("43913"),
    dns: str = Form(...),
    jc: str = Form(...),
    jmin: str = Form(...),
    jmax: str = Form(...),
    s1: str = Form(...),
    s2: str = Form(...),
    s3: str = Form("21"),
    s4: str = Form("2"),
    h1: str = Form(...),
    h2: str = Form(...),
    h3: str = Form(...),
    h4: str = Form(...),
    legacy_jc: str = Form(...),
    legacy_jmin: str = Form(...),
    legacy_jmax: str = Form(...),
    legacy_s1: str = Form(...),
    legacy_s2: str = Form(...),
    legacy_h1: str = Form(...),
    legacy_h2: str = Form(...),
    legacy_h3: str = Form(...),
    legacy_h4: str = Form(...),
    split_tunnel_routes: str = Form(""),
    user: dict = Depends(check_password_change_required)
):
    from app.vpn_manager import set_vpn_setting, rebuild_and_sync_vpn_config
    
    try:
        # Валидация и сохранение настроек
        port_value = _validated_int_setting("UDP-порт Amnezia 2.0", port, 1, 65535)
        legacy_port_value = _validated_int_setting("UDP-порт Legacy", legacy_port, 1, 65535)
        jc_value = _validated_int_setting("Jc", jc, 0, 100)
        jmin_value = _validated_int_setting("Jmin", jmin, 0, 1200)
        jmax_value = _validated_int_setting("Jmax", jmax, 0, 1200)
        s1_value = _validated_int_setting("S1", s1, 0, 1000)
        s2_value = _validated_int_setting("S2", s2, 0, 1000)
        s3_value = _validated_int_setting("S3", s3, 0, 1000)
        s4_value = _validated_int_setting("S4", s4, 0, 1000)
        legacy_jc_value = _validated_int_setting("Legacy Jc", legacy_jc, 0, 100)
        legacy_jmin_value = _validated_int_setting("Legacy Jmin", legacy_jmin, 0, 1200)
        legacy_jmax_value = _validated_int_setting("Legacy Jmax", legacy_jmax, 0, 1200)
        legacy_s1_value = _validated_int_setting("Legacy S1", legacy_s1, 0, 1000)
        legacy_s2_value = _validated_int_setting("Legacy S2", legacy_s2, 0, 1000)
        if int(jmin_value) > int(jmax_value):
            raise ValueError("Jmin не может быть больше Jmax")
        if int(legacy_jmin_value) > int(legacy_jmax_value):
            raise ValueError("Legacy Jmin не может быть больше Legacy Jmax")
        if port_value == legacy_port_value:
            raise ValueError("Порты Amnezia 2.0 и Legacy должны быть разными")

        set_vpn_setting("public_ip", public_ip.strip())
        set_vpn_setting("port", port_value)
        set_vpn_setting("legacy_port", legacy_port_value)
        set_vpn_setting("dns", dns.strip())
        set_vpn_setting("jc", jc_value)
        set_vpn_setting("jmin", jmin_value)
        set_vpn_setting("jmax", jmax_value)
        set_vpn_setting("s1", s1_value)
        set_vpn_setting("s2", s2_value)
        set_vpn_setting("s3", s3_value)
        set_vpn_setting("s4", s4_value)
        set_vpn_setting("h1", h1.strip())
        set_vpn_setting("h2", h2.strip())
        set_vpn_setting("h3", h3.strip())
        set_vpn_setting("h4", h4.strip())
        set_vpn_setting("legacy_jc", legacy_jc_value)
        set_vpn_setting("legacy_jmin", legacy_jmin_value)
        set_vpn_setting("legacy_jmax", legacy_jmax_value)
        set_vpn_setting("legacy_s1", legacy_s1_value)
        set_vpn_setting("legacy_s2", legacy_s2_value)
        set_vpn_setting("legacy_h1", legacy_h1.strip())
        set_vpn_setting("legacy_h2", legacy_h2.strip())
        set_vpn_setting("legacy_h3", legacy_h3.strip())
        set_vpn_setting("legacy_h4", legacy_h4.strip())
        set_split_tunnel_routes_text(split_tunnel_routes)
        
        # Пересборка конфигов сервера и перезапуск интерфейса VPN
        rebuild_and_sync_vpn_config()
        log_event("settings_vpn_updated", "Настройки VPN и AmneziaWG обновлены.", meta={"port": port_value, "legacy_port": legacy_port_value})
        success_msg = "Настройки успешно сохранены!"
        error_msg = None
    except Exception as e:
        logger.error(f"Не удалось сохранить настройки VPN: {e}")
        success_msg = None
        error_msg = f"Ошибка применения настроек: {str(e)}"
        
    settings = {
        "public_ip": public_ip,
        "port": port,
        "legacy_port": legacy_port,
        "dns": dns,
        "jc": jc,
        "jmin": jmin,
        "jmax": jmax,
        "s1": s1,
        "s2": s2,
        "s3": s3,
        "s4": s4,
        "h1": h1,
        "h2": h2,
        "h3": h3,
        "h4": h4,
        "legacy_jc": legacy_jc,
        "legacy_jmin": legacy_jmin,
        "legacy_jmax": legacy_jmax,
        "legacy_s1": legacy_s1,
        "legacy_s2": legacy_s2,
        "legacy_h1": legacy_h1,
        "legacy_h2": legacy_h2,
        "legacy_h3": legacy_h3,
        "legacy_h4": legacy_h4,
        "split_tunnel_routes": split_tunnel_routes,
        "split_tunnel_route_count": len(get_split_tunnel_routes())
    }
    
    return templates.TemplateResponse(
        request=request,
        name="vpn_settings.html",
        context={
            "user": user,
            "settings": settings,
            "success": success_msg,
            "error": error_msg,
            "split_presets": SPLIT_TUNNEL_PRESETS,
            "current_page": "vpn_settings"
        }
    )

# --- СТРАНИЦА API ДОКУМЕНТАЦИИ ---

# --- НАСТРОЙКИ ВЕБ-ПАНЕЛИ ---

# --- КАСКАД AMNEZIA ---

@router.get("/settings/cascade", response_class=HTMLResponse)
async def cascade_settings_page(
    request: Request,
    user: dict = Depends(check_password_change_required),
):
    return templates.TemplateResponse(
        request=request,
        name="cascade_settings.html",
        context={
            "user": user,
            "settings": get_cascade_settings(),
            "active_rules": active_cascade_rules(),
            "current_page": "cascade_settings",
        },
    )


@router.post("/settings/cascade", response_class=HTMLResponse)
async def save_cascade_settings(
    request: Request,
    action: str = Form("apply"),
    target_ip: str = Form(""),
    v2_local_port: str = Form("54912"),
    v2_target_port: str = Form("43912"),
    legacy_enabled: str = Form("0"),
    legacy_local_port: str = Form("54913"),
    legacy_target_port: str = Form("43913"),
    target_panel_url: str = Form(""),
    target_api_token: str = Form(""),
    user: dict = Depends(check_password_change_required),
):
    success_msg = None
    error_msg = None
    settings = {
        "enabled": "0",
        "target_ip": target_ip.strip(),
        "v2_local_port": v2_local_port.strip(),
        "v2_target_port": v2_target_port.strip(),
        "legacy_enabled": "1" if legacy_enabled == "1" else "0",
        "legacy_local_port": legacy_local_port.strip(),
        "legacy_target_port": legacy_target_port.strip(),
        "target_panel_url": target_panel_url.strip().rstrip("/"),
        "target_api_token": target_api_token.strip(),
    }

    try:
        if action == "disable":
            clear_cascade_rules()
            set_cascade_setting("cascade_enabled", "0")
            success_msg = "Каскад отключен, правила проброса удалены."
            log_event("cascade_disabled", "Каскад Amnezia отключен.", notify=True)
        else:
            settings["target_ip"] = validate_target_ip(settings["target_ip"])
            settings["v2_local_port"] = validate_port(settings["v2_local_port"], "Входящий порт Amnezia 2.0")
            settings["v2_target_port"] = validate_port(settings["v2_target_port"], "Порт Amnezia 2.0 на целевом сервере")
            settings["legacy_local_port"] = validate_port(settings["legacy_local_port"], "Входящий порт Legacy")
            settings["legacy_target_port"] = validate_port(settings["legacy_target_port"], "Порт Legacy на целевом сервере")
            for key, value in {
                "cascade_target_ip": settings["target_ip"],
                "cascade_v2_local_port": settings["v2_local_port"],
                "cascade_v2_target_port": settings["v2_target_port"],
                "cascade_legacy_enabled": settings["legacy_enabled"],
                "cascade_legacy_local_port": settings["legacy_local_port"],
                "cascade_legacy_target_port": settings["legacy_target_port"],
                "cascade_target_panel_url": settings["target_panel_url"],
                "cascade_target_api_token": settings["target_api_token"],
            }.items():
                set_cascade_setting(key, value)
            apply_cascade(settings)
            set_cascade_setting("cascade_enabled", "1")
            settings["enabled"] = "1"
            success_msg = "Каскад включен, UDP-порты Amnezia проброшены на целевой сервер."
            log_event("cascade_enabled", f"Каскад Amnezia включен на {settings['target_ip']}.", notify=True)
    except Exception as exc:
        logger.error(f"Cascade settings failed: {exc}")
        error_msg = str(exc)
        settings["enabled"] = get_cascade_settings().get("enabled", "0")

    return templates.TemplateResponse(
        request=request,
        name="cascade_settings.html",
        context={
            "user": user,
            "settings": settings if error_msg else get_cascade_settings(),
            "active_rules": active_cascade_rules(),
            "success": success_msg,
            "error": error_msg,
            "current_page": "cascade_settings",
        },
    )


@router.get("/settings/panel", response_class=HTMLResponse)
async def panel_settings_page(
    request: Request,
    user: dict = Depends(check_password_change_required)
):
    settings = {
        "panel_port": get_panel_setting("panel_port", os.getenv("PANEL_PORT", "8080")),
        "panel_domain": get_panel_setting("panel_domain", ""),
        "panel_theme": get_panel_setting("panel_theme", request.cookies.get("panel_theme", "light")),
        "panel_language": get_panel_setting("panel_language", request.cookies.get("panel_lang", "ru")),
        "telegram_notifications_enabled": get_panel_setting("telegram_notifications_enabled", "0"),
        "telegram_admin_bot_token": get_panel_setting("telegram_admin_bot_token", ""),
        "telegram_admin_chat_id": get_panel_setting("telegram_admin_chat_id", ""),
        "public_ip": SERVER_PUBLIC_IP,
    }
    return templates.TemplateResponse(
        request=request,
        name="panel_settings.html",
        context={
            "user": user,
            "settings": settings,
            "current_page": "panel_settings"
        }
    )

@router.post("/settings/panel", response_class=HTMLResponse)
async def save_panel_settings(
    request: Request,
    telegram_notifications_enabled: str = Form("0"),
    telegram_admin_bot_token: str = Form(""),
    telegram_admin_chat_id: str = Form(""),
    user: dict = Depends(check_password_change_required)
):
    success_msg = None
    error_msg = None
    port_value = get_panel_setting("panel_port", os.getenv("PANEL_PORT", "8080"))
    domain_value = get_panel_setting("panel_domain", "")
    theme_value = get_panel_setting("panel_theme", request.cookies.get("panel_theme", "light"))
    language_value = get_panel_setting("panel_language", request.cookies.get("panel_lang", "ru"))
    telegram_enabled_value = "1" if telegram_notifications_enabled == "1" else "0"
    telegram_token_value = telegram_admin_bot_token.strip()
    telegram_chat_id_value = telegram_admin_chat_id.strip()

    try:
        set_panel_setting("telegram_notifications_enabled", telegram_enabled_value)
        set_panel_setting("telegram_admin_bot_token", telegram_token_value)
        set_panel_setting("telegram_admin_chat_id", telegram_chat_id_value)
        log_event("settings_telegram_updated", "Настройки Telegram уведомлений обновлены.", meta={"enabled": telegram_enabled_value})
        success_msg = "Настройки Telegram сохранены."
    except Exception as e:
        logger.error(f"Не удалось сохранить настройки Telegram: {e}")
        error_msg = str(e)

    settings = {
        "panel_port": port_value,
        "panel_domain": domain_value,
        "panel_theme": theme_value,
        "panel_language": language_value,
        "telegram_notifications_enabled": telegram_enabled_value,
        "telegram_admin_bot_token": telegram_token_value,
        "telegram_admin_chat_id": telegram_chat_id_value,
        "public_ip": SERVER_PUBLIC_IP,
    }
    response = templates.TemplateResponse(
        request=request,
        name="panel_settings.html",
        context={
            "user": user,
            "settings": settings,
            "success": success_msg,
            "error": error_msg,
            "current_page": "panel_settings"
        }
    )
    response.set_cookie("panel_theme", theme_value, max_age=60 * 60 * 24 * 365, samesite="lax")
    response.set_cookie("panel_lang", language_value, max_age=60 * 60 * 24 * 365, samesite="lax")
    return response


@router.post("/settings/panel/theme")
async def save_panel_theme(
    panel_theme: str = Form(...),
    user: dict = Depends(check_password_change_required)
):
    theme_value = panel_theme.strip().lower()
    if theme_value not in {"light", "dark"}:
        raise HTTPException(status_code=400, detail="Тема панели должна быть light или dark")

    set_panel_setting("panel_theme", theme_value)
    log_event("settings_theme_updated", f"Тема панели изменена на {theme_value}.", meta={"theme": theme_value})
    response = JSONResponse({"status": "ok", "theme": theme_value})
    response.set_cookie("panel_theme", theme_value, max_age=60 * 60 * 24 * 365, samesite="lax")
    return response

@router.post("/settings/panel/language")
async def save_panel_language(
    panel_language: str = Form(...),
    user: dict = Depends(check_password_change_required)
):
    language_value = panel_language.strip().lower()
    if language_value not in {"ru", "en"}:
        raise HTTPException(status_code=400, detail="Panel language must be ru or en")

    set_panel_setting("panel_language", language_value)
    log_event("settings_language_updated", f"Язык панели изменен на {language_value}.", meta={"language": language_value})
    response = JSONResponse({"status": "ok", "language": language_value})
    response.set_cookie("panel_lang", language_value, max_age=60 * 60 * 24 * 365, samesite="lax")
    return response

@router.get("/settings/api", response_class=HTMLResponse)
async def api_docs_page(
    request: Request,
    user: dict = Depends(check_password_change_required)
):
    from app.config import TELEGRAM_API_TOKEN
    
    return templates.TemplateResponse(
        request=request,
        name="api_docs.html",
        context={
            "user": user,
            "telegram_token": TELEGRAM_API_TOKEN,
            "public_ip": SERVER_PUBLIC_IP,
            "panel_port": get_panel_setting("panel_port", os.getenv("PANEL_PORT", "8080")),
            "current_page": "api_docs"
        }
    )
