import hashlib
import hmac

WEBHOOK_SECRET = b"rotate-me"


def verify_webhook(body, signature):
    expected = hmac.new(WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
