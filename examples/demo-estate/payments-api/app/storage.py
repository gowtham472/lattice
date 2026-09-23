import hashlib


def statement_checksum(statement_bytes):
    """Integrity check for archived bank statements."""
    return hashlib.md5(statement_bytes).hexdigest()
