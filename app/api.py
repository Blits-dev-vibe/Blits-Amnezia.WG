import uuid
import datetime
import qrcode
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from app.models import ClientCreate, ClientExtend, ClientResponse, TokenRequest
from app.auth import verify_api_token, verify_password, create_access_token
from app.database import get_db_connection
from app.audit import log_event
from app.config import CLIENTS_DIR, QR_DIR, SERVER_PUBLIC_IP, AWG_PORT, logger
from app.vpn_manager import (
    generate_keypair, generate_preshared_key, get_next_free_ip, generate_client_config, generate_legacy_client_config,
    rebuild_and_sync_vpn_config
)
from app.deeplink import generate_amnezia_deeplink

router = APIRouter(prefix="/api/v1", tags=["Telegram Bot API"])

@router.post("/clients", response_model=ClientResponse)
async def create_client(payload: ClientCreate, api_token: str = Depends(verify_api_token)):
    """
    Создает нового пира AmneziaWG. Добавляет в БД, генерирует .conf и QR-код,
    пересобирает и синхронизирует конфигурационный файл сервера.
    """
    client_id = str(uuid.uuid4())
    logger.info(f"API запрос на создание клиента '{payload.name}' (id: {client_id})")
    
    try:
        # Генерируем ключи
        client_private_key, client_public_key = generate_keypair()
        preshared_key = generate_preshared_key()
        
        # Получаем свободный IP
        client_ip = get_next_free_ip()
        
        # Временные метки
        now = datetime.datetime.utcnow()
        created_at = now.isoformat()
        expires_at = (now + datetime.timedelta(days=payload.days)).isoformat()
        
        # Сохранение в базу данных
        conn = get_db_connection()
        conn.execute(
            """
            INSERT INTO clients (
                id, name, telegram_id, ip_address, public_key, private_key, preshared_key,
                traffic_limit_gb, traffic_used_bytes, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                client_id, payload.name, payload.telegram_id, client_ip,
                client_public_key, client_private_key, preshared_key, payload.traffic_limit_gb,
                0, expires_at, created_at
            )
        )
        conn.commit()
        conn.close()
        
        # Генерация файла .conf
        config_text = generate_client_config(client_ip, client_private_key, preshared_key=preshared_key)
        conf_file_path = CLIENTS_DIR / f"{client_id}.conf"
        with open(conf_file_path, "w") as f:
            f.write(config_text)
            
        # Генерация QR-кода
        qr = qrcode.QRCode(version=1, box_size=10, border=3)
        qr.add_data(config_text)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_file_path = QR_DIR / f"{client_id}.png"
        qr_img.save(qr_file_path)
        
        # Пересборка и синхронизация конфига сервера AmneziaWG
        rebuild_and_sync_vpn_config()
        
        # Ссылки на скачивание (используем относительные, чтобы не зависеть от хоста)
        conf_download_url = f"/clients/{client_id}/download"
        qr_url = f"/clients/{client_id}/qr"
        qr_url_v2 = f"/clients/{client_id}/qr?version=2.0"
        qr_url_split = f"/clients/{client_id}/qr?split=true"
        qr_url_split_v2 = f"/clients/{client_id}/qr?split=true&version=2.0"
        qr_series_url = f"/clients/{client_id}/qr-series"
        qr_series_url_v2 = f"/clients/{client_id}/qr-series?version=2.0"
        qr_series_url_split = f"/clients/{client_id}/qr-series?split=true"
        qr_series_url_split_v2 = f"/clients/{client_id}/qr-series?split=true&version=2.0"
        
        # Deep link
        config_text_legacy = generate_legacy_client_config(client_ip, client_private_key, preshared_key=preshared_key)
        deep_link = generate_amnezia_deeplink(config_text_legacy, version="1.0", client_public_key=client_public_key, client_name=payload.name)
        deep_link_v2 = generate_amnezia_deeplink(config_text, version="2.0", client_public_key=client_public_key, client_name=payload.name)
        
        # Раздельный конфиг и ссылки (избирательный туннель)
        config_text_split = generate_client_config(client_ip, client_private_key, split_tunnel=True, preshared_key=preshared_key)
        config_text_split_legacy = generate_legacy_client_config(client_ip, client_private_key, split_tunnel=True, preshared_key=preshared_key)
        deep_link_split = generate_amnezia_deeplink(config_text_split_legacy, version="1.0", client_public_key=client_public_key, split_tunnel=True, client_name=payload.name)
        deep_link_split_v2 = generate_amnezia_deeplink(config_text_split, version="2.0", client_public_key=client_public_key, split_tunnel=True, client_name=payload.name)
        
        return ClientResponse(
            client_id=client_id,
            name=payload.name,
            telegram_id=payload.telegram_id,
            ip_address=client_ip,
            public_key=client_public_key,
            traffic_limit_gb=payload.traffic_limit_gb,
            traffic_used_bytes=0,
            expires_at=expires_at,
            created_at=created_at,
            disabled_at=None,
            config_text=config_text,
            conf_download_url=conf_download_url,
            qr_url=qr_url,
            qr_url_v2=qr_url_v2,
            qr_url_split=qr_url_split,
            qr_url_split_v2=qr_url_split_v2,
            qr_series_url=qr_series_url,
            qr_series_url_v2=qr_series_url_v2,
            qr_series_url_split=qr_series_url_split,
            qr_series_url_split_v2=qr_series_url_split_v2,
            deep_link=deep_link,
            deep_link_v2=deep_link_v2,
            config_text_split=config_text_split,
            deep_link_split=deep_link_split,
            deep_link_split_v2=deep_link_split_v2
        )
        
    except Exception as e:
        logger.error(f"Ошибка при создании клиента через API: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Внутренняя ошибка сервера: {str(e)}"
        )

@router.get("/clients/{client_id}", response_model=ClientResponse)
async def get_client_api(client_id: str, api_token: str = Depends(verify_api_token)):
    """
    Возвращает детальную информацию о клиенте по его ID.
    """
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM clients WHERE id = ? AND deleted_at IS NULL", (client_id,)).fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Клиент не найден")
        
    client = dict(row)
    
    # Генерация конфига для ответа
    config_text = generate_client_config(client['ip_address'], client['private_key'], preshared_key=client['preshared_key'])
    conf_download_url = f"/clients/{client_id}/download"
    qr_url = f"/clients/{client_id}/qr"
    qr_url_v2 = f"/clients/{client_id}/qr?version=2.0"
    qr_url_split = f"/clients/{client_id}/qr?split=true"
    qr_url_split_v2 = f"/clients/{client_id}/qr?split=true&version=2.0"
    qr_series_url = f"/clients/{client_id}/qr-series"
    qr_series_url_v2 = f"/clients/{client_id}/qr-series?version=2.0"
    qr_series_url_split = f"/clients/{client_id}/qr-series?split=true"
    qr_series_url_split_v2 = f"/clients/{client_id}/qr-series?split=true&version=2.0"
    config_text_legacy = generate_legacy_client_config(client['ip_address'], client['private_key'], preshared_key=client['preshared_key'])
    deep_link = generate_amnezia_deeplink(config_text_legacy, version="1.0", client_public_key=client['public_key'], client_name=client['name'])
    deep_link_v2 = generate_amnezia_deeplink(config_text, version="2.0", client_public_key=client['public_key'], client_name=client['name'])
    
    # Раздельный конфиг и ссылки (избирательный туннель)
    config_text_split = generate_client_config(client['ip_address'], client['private_key'], split_tunnel=True, preshared_key=client['preshared_key'])
    config_text_split_legacy = generate_legacy_client_config(client['ip_address'], client['private_key'], split_tunnel=True, preshared_key=client['preshared_key'])
    deep_link_split = generate_amnezia_deeplink(config_text_split_legacy, version="1.0", client_public_key=client['public_key'], split_tunnel=True, client_name=client['name'])
    deep_link_split_v2 = generate_amnezia_deeplink(config_text_split, version="2.0", client_public_key=client['public_key'], split_tunnel=True, client_name=client['name'])
    
    return ClientResponse(
        client_id=client['id'],
        name=client['name'],
        telegram_id=client['telegram_id'],
        ip_address=client['ip_address'],
        public_key=client['public_key'],
        traffic_limit_gb=client['traffic_limit_gb'],
        traffic_used_bytes=client['traffic_used_bytes'],
        expires_at=client['expires_at'],
        created_at=client['created_at'],
        disabled_at=client['disabled_at'],
        config_text=config_text,
        conf_download_url=conf_download_url,
        qr_url=qr_url,
        qr_url_v2=qr_url_v2,
        qr_url_split=qr_url_split,
        qr_url_split_v2=qr_url_split_v2,
        qr_series_url=qr_series_url,
        qr_series_url_v2=qr_series_url_v2,
        qr_series_url_split=qr_series_url_split,
        qr_series_url_split_v2=qr_series_url_split_v2,
        deep_link=deep_link,
        deep_link_v2=deep_link_v2,
        config_text_split=config_text_split,
        deep_link_split=deep_link_split,
        deep_link_split_v2=deep_link_split_v2
    )

@router.post("/clients/{client_id}/disable")
async def disable_client_api(client_id: str, api_token: str = Depends(verify_api_token)):
    """
    Отключает клиента (peer удаляется из активного конфига сервера, но остается в БД).
    """
    conn = get_db_connection()
    client = conn.execute("SELECT * FROM clients WHERE id = ? AND deleted_at IS NULL", (client_id,)).fetchone()
    if not client:
        conn.close()
        raise HTTPException(status_code=404, detail="Клиент не найден")
        
    now = datetime.datetime.utcnow().isoformat()
    conn.execute("UPDATE clients SET disabled_at = ? WHERE id = ?", (now, client_id))
    conn.commit()
    conn.close()
    
    # Синхронизация VPN сервера
    rebuild_and_sync_vpn_config()
    logger.info(f"Клиент {client_id} успешно отключен через API.")
    
    return {"status": "disabled", "client_id": client_id}

@router.post("/clients/{client_id}/enable")
async def enable_client_api(client_id: str, api_token: str = Depends(verify_api_token)):
    """
    Включает ранее отключенного клиента.
    """
    conn = get_db_connection()
    client = conn.execute("SELECT * FROM clients WHERE id = ? AND deleted_at IS NULL", (client_id,)).fetchone()
    if not client:
        conn.close()
        raise HTTPException(status_code=404, detail="Клиент не найден")
        
    conn.execute("UPDATE clients SET disabled_at = NULL WHERE id = ?", (client_id,))
    conn.commit()
    conn.close()
    
    # Синхронизация VPN сервера
    rebuild_and_sync_vpn_config()
    logger.info(f"Клиент {client_id} успешно включен через API.")
    
    return {"status": "enabled", "client_id": client_id}

@router.post("/clients/{client_id}/extend")
async def extend_client_api(client_id: str, payload: ClientExtend, api_token: str = Depends(verify_api_token)):
    """
    Продлевает действие ключа клиента на указанное число дней.
    """
    conn = get_db_connection()
    client = conn.execute("SELECT * FROM clients WHERE id = ? AND deleted_at IS NULL", (client_id,)).fetchone()
    if not client:
        conn.close()
        raise HTTPException(status_code=404, detail="Клиент не найден")
        
    # Парсим текущую дату истечения или берем текущее время, если срок уже истек
    try:
        current_expire = datetime.datetime.fromisoformat(client['expires_at'])
    except Exception:
        current_expire = datetime.datetime.utcnow()
        
    now = datetime.datetime.utcnow()
    base_date = current_expire if current_expire > now else now
    new_expire = (base_date + datetime.timedelta(days=payload.days)).isoformat()
    
    conn.execute("UPDATE clients SET expires_at = ?, disabled_at = NULL WHERE id = ?", (new_expire, client_id))
    conn.commit()
    conn.close()
    
    # Если клиент был отключен (например, закончился срок), возвращаем его на сервер
    rebuild_and_sync_vpn_config()
    logger.info(f"Клиент {client_id} успешно продлен на {payload.days} дн. Новая дата истечения: {new_expire}")
    
    return {"status": "extended", "client_id": client_id, "expires_at": new_expire}

@router.delete("/clients/{client_id}")
async def delete_client_api(client_id: str, api_token: str = Depends(verify_api_token)):
    """
    Удаляет клиента (мягкое удаление из БД, удаление из конфига сервера).
    """
    conn = get_db_connection()
    client = conn.execute("SELECT * FROM clients WHERE id = ? AND deleted_at IS NULL", (client_id,)).fetchone()
    if not client:
        conn.close()
        raise HTTPException(status_code=404, detail="Клиент не найден")
        
    now = datetime.datetime.utcnow().isoformat()
    conn.execute("UPDATE clients SET deleted_at = ? WHERE id = ?", (now, client_id))
    conn.commit()
    conn.close()
    
    # Синхронизация VPN сервера
    rebuild_and_sync_vpn_config()
    logger.info(f"Клиент {client_id} мягко удален через API.")
    
    return {"status": "deleted", "client_id": client_id}

@router.post("/auth/token")
async def login_for_bot_token(payload: TokenRequest):
    """
    Авторизует бота/клиента по логину и паролю администратора.
    Возвращает access_token (JWT), который можно использовать как Bearer-токен.
    """
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (payload.username,)).fetchone()
    conn.close()
    
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверное имя пользователя или пароль"
        )
        
    # Создаем токен (срок действия по умолчанию 24 часа)
    token = create_access_token(data={"sub": payload.username})
    return {"access_token": token, "token_type": "bearer"}
