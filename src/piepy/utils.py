from base64 import urlsafe_b64decode, urlsafe_b64encode


def bytes_to_base64url(b: bytes) -> str:
    """Encode bytes as base64url (RFC 4648) without padding."""
    return urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def base64url_to_bytes(s: str) -> bytes:
    """Decode base64url (RFC 4648) string to bytes."""
    padding = (4 - len(s) % 4) % 4
    return urlsafe_b64decode(f"{s}{"=" * padding}")
