from pydantic import BaseModel, Field
from typing import Optional, List

class ClientCreate(BaseModel):
    name: str = Field(..., description="Имя клиента, например telegram_123456")
    telegram_id: Optional[int] = Field(None, description="Telegram ID клиента")
    days: int = Field(default=30, ge=1, description="Количество дней действия ключа")
    traffic_limit_gb: float = Field(default=0.0, ge=0, description="Лимит трафика в ГБ (0 = безлимит)")

class ClientExtend(BaseModel):
    days: int = Field(..., ge=1, description="На сколько дней продлить ключ")

class ClientResponse(BaseModel):
    client_id: str
    name: str
    telegram_id: Optional[int]
    ip_address: str
    public_key: str
    traffic_limit_gb: float
    traffic_used_bytes: int
    expires_at: str
    created_at: str
    disabled_at: Optional[str]
    config_text: str
    conf_download_url: str
    qr_url: str
    qr_url_v2: Optional[str] = None
    qr_url_split: Optional[str] = None
    qr_url_split_v2: Optional[str] = None
    qr_series_url: Optional[str] = None
    qr_series_url_v2: Optional[str] = None
    qr_series_url_split: Optional[str] = None
    qr_series_url_split_v2: Optional[str] = None
    deep_link: Optional[str]
    deep_link_v2: Optional[str]
    config_text_split: Optional[str] = None
    deep_link_split: Optional[str] = None
    deep_link_split_v2: Optional[str] = None

class TokenRequest(BaseModel):
    username: str
    password: str

class SystemStatusResponse(BaseModel):
    panel_status: str
    amnezia_status: str
    public_ip: str
    amnezia_port: int
    client_count: int
    config_path: str
