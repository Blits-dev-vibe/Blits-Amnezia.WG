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
    CLIENTS_DIR, QR_DIR, SERVER_PUBLIC_IP, AWG_PORT, AWG_CONFIG_FILE,
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

# Вспомогательная функция для форматирования дат в шаблонах Jinja
def format_datetime(value: str) -> str:
    try:
        dt = datetime.datetime.fromisoformat(value)
        return dt.strftime("%d.%m.%Y %H:%M")
    except Exception:
        return value

templates.env.filters["datetime"] = format_datetime

def _validated_int_setting(name: str, value: str, min_value: int, max_value: int) -> str:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError(f"{name}: нужно целое число")
    if number < min_value or number > max_value:
        raise ValueError(f"{name}: значение должно быть от {min_value} до {max_value}")
    return str(number)

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

def write_panel_env(port: str):
    PANEL_ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    PANEL_ENV_FILE.write_text(f"PANEL_PORT={port}\n", encoding="utf-8")
    try:
        os.chmod(PANEL_ENV_FILE, 0o600)
    except Exception:
        pass

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
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    
    if not user or not verify_password(password, user["password_hash"]):
        return templates.TemplateResponse(request=request, name="login.html", context={"error": "Неверное имя пользователя или пароль"})
        
    # Создаем токен
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
            "events": get_events(50),
            "current_page": "clients",
        },
    )


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
                try:
                    current_expire = datetime.datetime.fromisoformat(row["expires_at"])
                except Exception:
                    current_expire = now
                base_date = current_expire if current_expire > now else now
                new_expire = (base_date + datetime.timedelta(days=days)).isoformat()
                conn.execute("UPDATE clients SET expires_at = ?, disabled_at = NULL WHERE id = ?", (new_expire, row["id"]))
                log_event("client_extended", f"Клиент {row['name']} продлен на {days} дн.", row["id"], row["name"])
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
        "split_tunnel_routes": get_split_tunnel_routes_text(),
        "split_tunnel_route_count": len(get_split_tunnel_routes())
    }
    
    return templates.TemplateResponse(
        request=request,
        name="vpn_settings.html",
        context={
            "user": user,
            "settings": settings,
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
        if int(jmin_value) > int(jmax_value):
            raise ValueError("Jmin не может быть больше Jmax")
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
        set_split_tunnel_routes_text(split_tunnel_routes)
        
        # Пересборка конфигов сервера и перезапуск интерфейса VPN
        rebuild_and_sync_vpn_config()
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
    panel_port: str = Form(...),
    panel_domain: str = Form(""),
    panel_theme: str = Form("light"),
    panel_language: str = Form("ru"),
    telegram_notifications_enabled: str = Form("0"),
    telegram_admin_bot_token: str = Form(""),
    telegram_admin_chat_id: str = Form(""),
    user: dict = Depends(check_password_change_required)
):
    from app.vpn_manager import get_vpn_setting

    success_msg = None
    error_msg = None
    port_value = panel_port.strip()
    domain_value = panel_domain.strip().lower()
    theme_value = panel_theme.strip().lower()
    language_value = panel_language.strip().lower()
    telegram_enabled_value = "1" if telegram_notifications_enabled == "1" else "0"
    telegram_token_value = telegram_admin_bot_token.strip()
    telegram_chat_id_value = telegram_admin_chat_id.strip()

    try:
        port_value = _validated_int_setting("Порт панели", port_value, 1, 65535)
        if theme_value not in {"light", "dark"}:
            raise ValueError("Тема панели должна быть light или dark")
        if language_value not in {"ru", "en"}:
            raise ValueError("Panel language must be ru or en")
        reserved_ports = {
            "22": "SSH",
            get_vpn_setting("port", str(AWG_PORT)): "Amnezia 2.0",
            get_vpn_setting("legacy_port", "43913"): "Amnezia Legacy",
        }
        if port_value in reserved_ports:
            raise ValueError(f"Порт {port_value} уже используется для {reserved_ports[port_value]}")
        if domain_value and not DOMAIN_RE.match(domain_value):
            raise ValueError("Домен должен быть в формате example.com без http:// и пути")

        old_port = get_panel_setting("panel_port", os.getenv("PANEL_PORT", "8080"))
        set_panel_setting("panel_port", port_value)
        set_panel_setting("panel_domain", domain_value)
        set_panel_setting("panel_theme", theme_value)
        set_panel_setting("panel_language", language_value)
        set_panel_setting("telegram_notifications_enabled", telegram_enabled_value)
        set_panel_setting("telegram_admin_bot_token", telegram_token_value)
        set_panel_setting("telegram_admin_chat_id", telegram_chat_id_value)
        write_panel_env(port_value)

        if port_value != old_port and os.name != "nt":
            restart_panel_service_later()
            success_msg = f"Настройки сохранены. Панель перезапустится на порту {port_value} через пару секунд."
        else:
            success_msg = "Настройки панели сохранены."
    except Exception as e:
        logger.error(f"Не удалось сохранить настройки панели: {e}")
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
    response = JSONResponse({"status": "ok", "theme": theme_value})
    response.set_cookie("panel_theme", theme_value, max_age=60 * 60 * 24 * 365, samesite="lax")
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
