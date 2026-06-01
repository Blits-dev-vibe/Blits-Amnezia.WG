import base64
import io
import math
import struct

import qrcode


AMNEZIA_QR_MAGIC = 1984
AMNEZIA_QR_CHUNK_SIZE = 850


def split_amnezia_qr_payload(payload: bytes) -> list[str]:
    chunks_count = max(2, math.ceil(len(payload) / AMNEZIA_QR_CHUNK_SIZE))
    chunk_size = math.ceil(len(payload) / chunks_count)
    chunks = []
    for index in range(chunks_count):
        part = payload[index * chunk_size:(index + 1) * chunk_size]
        framed = (
            struct.pack(">hBBI", AMNEZIA_QR_MAGIC, chunks_count, index, len(part))
            + part
        )
        chunks.append(base64.urlsafe_b64encode(framed).decode("utf-8").rstrip("="))
    return chunks


def render_qr_png(data: str) -> bytes:
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=7,
        border=3,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
