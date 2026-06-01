import base64
import json
import logging
import re
import struct
import zlib

logger = logging.getLogger(__name__)


def _get_config_value(config_text: str, key: str, default: str = "") -> str:
    match = re.search(
        rf"(?im)^[^\S\r\n]*{re.escape(key)}[^\S\r\n]*=[^\S\r\n]*([^\r\n#]*)",
        config_text,
    )
    return match.group(1).strip() if match else default


def _split_dns(dns_value: str) -> tuple[str, str]:
    parts = [part.strip() for part in dns_value.split(",") if part.strip()]
    dns1 = parts[0] if parts else "1.1.1.1"
    dns2 = parts[1] if len(parts) > 1 else "1.0.0.1"
    return dns1, dns2


def _split_endpoint(endpoint: str) -> tuple[str, int]:
    host, port = endpoint.strip(), 51820
    if endpoint and ":" in endpoint:
        host, port_text = endpoint.rsplit(":", 1)
        port = int(port_text.strip())
    return host.strip(), port


def build_amnezia_server_json(
    config_text: str,
    version: str = "1.0",
    client_public_key: str = "",
    split_tunnel: bool = False,
    client_name: str = "Client",
) -> dict | None:
    """
    Generate a native Amnezia import key.

    This mirrors Amnezia's own extractWireGuardConfig() result: the app receives
    an Amnezia server JSON with an AWG container and last_config, so parameters
    are shown in separate UI fields instead of as one raw config blob.
    """
    try:
        dns1, dns2 = _split_dns(_get_config_value(config_text, "DNS"))
        host_name, port = _split_endpoint(_get_config_value(config_text, "Endpoint"))
        allowed_ips = [
            ip.strip()
            for ip in _get_config_value(config_text, "AllowedIPs", "0.0.0.0/0, ::/0").split(",")
            if ip.strip()
        ]

        last_config = {
            "config": config_text.strip(),
            "hostName": host_name,
            "port": port,
            "client_priv_key": _get_config_value(config_text, "PrivateKey"),
            "client_ip": _get_config_value(config_text, "Address"),
            "server_pub_key": _get_config_value(config_text, "PublicKey"),
            "allowed_ips": allowed_ips,
            "mtu": _get_config_value(config_text, "MTU", "1280"),
            "persistent_keep_alive": _get_config_value(config_text, "PersistentKeepalive", "25"),
        }

        preshared_key = _get_config_value(config_text, "PresharedKey") or _get_config_value(config_text, "PreSharedKey")
        if preshared_key:
            last_config["psk_key"] = preshared_key

        required_awg_keys = ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4")
        optional_awg_keys = ("S3", "S4", "I1", "I2", "I3", "I4", "I5")
        has_awg = all(_get_config_value(config_text, key) for key in required_awg_keys)

        awg_config = {
            "isObfuscationEnabled": has_awg,
            "isThirdPartyConfig": True,
            "last_config": json.dumps(last_config, ensure_ascii=False, indent=4),
            "port": str(port),
            "transport_proto": "udp",
        }
        if has_awg:
            last_config["isObfuscationEnabled"] = True

        container_name = "amnezia-wireguard"
        protocol_name = "wireguard"
        if has_awg:
            container_name = "amnezia-awg"
            protocol_name = "awg"
            for key in required_awg_keys + optional_awg_keys:
                value = _get_config_value(config_text, key)
                if value:
                    last_config[key] = value
                    awg_config[key] = value

            if _get_config_value(config_text, "S3") and _get_config_value(config_text, "S4"):
                awg_config["protocol_version"] = "2"
            elif any(_get_config_value(config_text, key) for key in ("I1", "I2", "I3", "I4", "I5")):
                awg_config["protocol_version"] = "1.5"

            awg_config["last_config"] = json.dumps(last_config, ensure_ascii=False, indent=4)

        display_name = f"{client_name} | VPN ({version})".strip()

        server_json = {
            "containers": [
                {
                    "container": container_name,
                    protocol_name: awg_config,
                }
            ],
            "defaultContainer": container_name,
            "description": display_name,
            "dns1": dns1,
            "dns2": dns2,
            "hostName": host_name,
            "nameOverriddenByUser": True,
            "splitTunnelSites": allowed_ips if split_tunnel else [],
            "splitTunnelType": 1 if split_tunnel else 0,
        }

        return server_json
    except Exception as exc:
        logger.error("Failed to build Amnezia config v%s: %s", version, exc)
        return None


def generate_amnezia_payload(
    config_text: str,
    version: str = "1.0",
    client_public_key: str = "",
    split_tunnel: bool = False,
    client_name: str = "Client",
) -> bytes | None:
    server_json = build_amnezia_server_json(
        config_text,
        version=version,
        client_public_key=client_public_key,
        split_tunnel=split_tunnel,
        client_name=client_name,
    )
    if not server_json:
        return None
    json_bytes = json.dumps(server_json, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return struct.pack(">I", len(json_bytes)) + zlib.compress(json_bytes)


def generate_amnezia_deeplink(
    config_text: str,
    version: str = "1.0",
    client_public_key: str = "",
    split_tunnel: bool = False,
    client_name: str = "Client",
) -> str | None:
    """
    Generate a native Amnezia import key.

    The payload is the same qCompress-compatible byte format that AmneziaVPN
    exports and expects when it scans multi-part QR codes.
    """
    payload = generate_amnezia_payload(
        config_text,
        version=version,
        client_public_key=client_public_key,
        split_tunnel=split_tunnel,
        client_name=client_name,
    )
    if not payload:
        return None
    encoded = base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")
    return f"vpn://{encoded}"
