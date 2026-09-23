from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from .webhooks import verify_webhook

app = Flask(__name__)
_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)


@app.route("/v1/payments", methods=["POST"])
def create_payment():
    payload = request.get_json()
    token = tokenize_card(payload["card_number"], payload["cvv"])
    return jsonify({"token": token.hex()})


@app.route("/v1/webhooks/bank", methods=["POST"])
def bank_webhook():
    if not verify_webhook(request.data, request.headers["X-Signature"]):
        return "", 401
    return "", 204


def tokenize_card(card_number, cvv):
    public_key = _key.public_key()
    return public_key.encrypt(
        f"{card_number}:{cvv}".encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
