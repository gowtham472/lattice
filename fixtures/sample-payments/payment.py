import hashlib


def legacy_receipt(value: bytes) -> str:
    """Deliberately weak hash used as a scanner regression fixture."""
    return hashlib.sha1(value).hexdigest()
