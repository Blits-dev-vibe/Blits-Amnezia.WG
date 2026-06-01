import os
import secrets
from pathlib import Path
import urllib.request
import logging

# Логгер
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent

# Загрузка .env вручную, чтобы не тащить pydantic-settings
if os.path.exists(BASE_DIR / ".env"):
    from dotenv import load_dotenv
    load_dotenv(BASE_DIR / ".env")

# Папка данных панели
DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Папки для конфигов и QR-кодов
CLIENTS_DIR = DATA_DIR / "clients"
QR_DIR = DATA_DIR / "qr"
CLIENTS_DIR.mkdir(parents=True, exist_ok=True)
QR_DIR.mkdir(parents=True, exist_ok=True)

# Секретный ключ для JWT
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_urlsafe(32)
    logger.warning("SECRET_KEY is not set; generated a temporary key for this process.")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 часа

# Токен авторизации для API Telegram-бота
TELEGRAM_API_TOKEN = os.getenv(
    "TELEGRAM_API_TOKEN",
    os.getenv("API_TOKEN", ""),
)

# Параметры AmneziaWG
AWG_INTERFACE = os.getenv("AWG_INTERFACE", "awg0")
AWG_PORT = int(os.getenv("AWG_PORT", "51820"))
AWG_SUBNET = os.getenv("AWG_SUBNET", "10.66.66.0/24")
AWG_SERVER_IP = os.getenv("AWG_SERVER_IP", "10.66.66.1")

# Конфигурационные пути AmneziaWG в системе
AWG_CONFIG_DIR = Path(os.getenv("AWG_CONFIG_DIR", "/etc/amnezia/amneziawg"))
AWG_CONFIG_FILE = AWG_CONFIG_DIR / f"{AWG_INTERFACE}.conf"

# Автоопределение внешнего IP
def get_public_ip() -> str:
    env_ip = os.getenv("SERVER_PUBLIC_IP")
    if env_ip:
        return env_ip
    
    # Список надежных текстовых API для получения внешнего IP
    endpoints = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://ipinfo.io/ip",
        "http://icanhazip.com"
    ]
    
    for url in endpoints:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'curl/7.81.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                ip = response.read().decode('utf-8').strip()
                # Простая валидация: строка должна содержать точки и быть короткой (не HTML)
                if ip and "." in ip and len(ip) < 20:
                    logger.info(f"Внешний IP сервера успешно получен из {url}: {ip}")
                    return ip
        except Exception as e:
            logger.warning(f"Не удалось получить IP с {url}: {e}")
            
    return "127.0.0.1"

SERVER_PUBLIC_IP = get_public_ip()
logger.info(f"Внешний IP сервера определен как: {SERVER_PUBLIC_IP}")
