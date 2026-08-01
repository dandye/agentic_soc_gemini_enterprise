import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path

from dotenv import load_dotenv


def _get_secret():
    """Retrieves the ChatOps secret from environment variables."""
    # Try to load .env from the root directory if it's not already loaded
    env_path = Path(__file__).parent.parent.parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)

    secret = os.getenv("CHRONICLE_CHATOPS_SECRET")
    if not secret:
        # Fail closed on Cloud Run (K_SERVICE set): signing with the public
        # fallback would let anyone mint valid approval tokens. An unset
        # shell var in a deploy script must not silently weaken HMAC.
        if os.getenv("K_SERVICE"):
            raise ValueError(
                "CHRONICLE_CHATOPS_SECRET is not set; refusing to sign or "
                "verify ChatOps tokens with the development fallback secret "
                "in a deployed service."
            )
        # Fallback for local development only
        return "development_fallback_secret_not_for_production"
    return secret


def generate_signed_payload(payload: dict, ttl: int = 3600) -> str:
    """
    Generates a secure, signed URL-friendly token containing a payload.

    Args:
        payload: The dictionary to encode and sign.
        ttl: Time to live in seconds (default 1 hour).

    Returns:
        A base64URL encoded string containing the signed payload.
    """
    secret = _get_secret()

    # Add expiration timestamp
    data = payload.copy()
    data["exp"] = int(time.time()) + ttl

    # Encode payload to JSON -> Bytes -> Base64
    json_payload = json.dumps(data, sort_keys=True).encode("utf-8")
    encoded_payload = base64.urlsafe_b64encode(json_payload).decode("utf-8").strip("=")

    # Generate signature
    signature = hmac.new(
        secret.encode("utf-8"), encoded_payload.encode("utf-8"), hashlib.sha256
    ).digest()

    encoded_signature = base64.urlsafe_b64encode(signature).decode("utf-8").strip("=")

    # Return formatted token: <payload>.<signature>
    return f"{encoded_payload}.{encoded_signature}"


def verify_signed_payload(token: str) -> dict:
    """
    Verifies a signed token and returns the payload if valid.

    Args:
        token: The <payload>.<signature> string to verify.

    Returns:
        The original payload dictionary.

    Raises:
        ValueError: If signature is invalid or payload has expired.
    """
    secret = _get_secret()

    try:
        encoded_payload, encoded_signature = token.split(".")
    except ValueError:
        raise ValueError("Invalid token format")

    # Re-calculate signature
    expected_signature = hmac.new(
        secret.encode("utf-8"), encoded_payload.encode("utf-8"), hashlib.sha256
    ).digest()

    recalculated_encoded_signature = (
        base64.urlsafe_b64encode(expected_signature).decode("utf-8").strip("=")
    )

    # Use constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(encoded_signature, recalculated_encoded_signature):
        raise ValueError("Invalid signature: payload may have been tampered with")

    # Decode and parse payload
    # Add back padding if necessary
    padding = (
        "=" * (4 - len(encoded_payload) % 4) if len(encoded_payload) % 4 != 0 else ""
    )
    json_payload = base64.urlsafe_b64decode(encoded_payload + padding).decode("utf-8")
    data = json.loads(json_payload)

    # Check expiration
    if "exp" in data and time.time() > data["exp"]:
        raise ValueError("Token has expired")

    return data
