import hashlib
import hmac
import json
import math
import time

from fastapi import HTTPException, Request, status

from app.core.config import settings


_SIGNATURE_HEADER = "X-SOC-Signature"
_TIMESTAMP_HEADER = "X-SOC-Timestamp"


def sign_payload(secret: str, timestamp: str, body: bytes) -> str:
    """Return the HMAC signature for the exact request body and timestamp."""
    message = timestamp.encode("utf-8") + b"." + body
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


async def verify_wazuh_signature(request: Request) -> bytes:
    return await _verify_signature(request, settings.app_secret_key)


async def verify_hub_signature(request: Request) -> bytes:
    keys = settings.hub_keys()
    if not keys:
        return await verify_wazuh_signature(request)
    body = await request.body()
    if len(body) > settings.ingest_max_body_bytes:
        raise HTTPException(413, "Payload is too large")
    try:
        source = json.loads(body).get("source")
        secret = keys.get(source)
    except (ValueError, AttributeError, TypeError):
        secret = None
    if secret is None:
        raise HTTPException(401, "Unknown Hub source")
    return await _verify_signature(request, secret)


async def _verify_signature(request: Request, secret: str) -> bytes:
    timestamp = request.headers.get(_TIMESTAMP_HEADER)
    signature = request.headers.get(_SIGNATURE_HEADER)

    if not timestamp or not signature:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing signature headers")

    try:
        timestamp_value = float(timestamp)
    except ValueError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid timestamp") from None

    if not math.isfinite(timestamp_value):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid timestamp")

    if (
        not signature.isascii()
        or len(signature) != hashlib.sha256().digest_size * 2
        or any(character not in "0123456789abcdefABCDEF" for character in signature)
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid signature")

    if abs(time.time() - timestamp_value) > settings.ingest_signature_max_skew_seconds:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Timestamp outside allowed skew")

    body = await request.body()
    if len(body) > settings.ingest_max_body_bytes:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Alert payload is too large")

    expected = sign_payload(secret, timestamp, body)
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid signature")

    return body
