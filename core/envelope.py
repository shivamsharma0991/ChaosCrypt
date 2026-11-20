import base64
import hashlib
import hmac
import json
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

MAGIC = b"IWC1"


def generate_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return pub, priv


def _oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def wrap_seed(seed: bytes, public_pem: str) -> bytes:
    pub = serialization.load_pem_public_key(public_pem.encode())
    return pub.encrypt(seed, _oaep())


def unwrap_seed(wrapped: bytes, private_pem: str) -> bytes:
    priv = serialization.load_pem_private_key(private_pem.encode(), password=None)
    return priv.decrypt(wrapped, _oaep())


def _mac_key(seed: bytes) -> bytes:
    return hashlib.sha256(b"IWC-mac" + seed).digest()


def pack(header: dict, payload: bytes, seed: bytes) -> bytes:
    hj = json.dumps(header, separators=(",", ":")).encode()
    body = MAGIC + struct.pack(">I", len(hj)) + hj + payload
    return body + hmac.new(_mac_key(seed), body, hashlib.sha256).digest()


def parse(blob: bytes):
    """Return (header, payload, body, tag). Raises ValueError on bad format."""
    if len(blob) < 40 or blob[:4] != MAGIC:
        raise ValueError("Not a valid .enc package.")
    (hl,) = struct.unpack(">I", blob[4:8])
    if 8 + hl + 32 > len(blob):
        raise ValueError("Package is truncated.")
    header = json.loads(blob[8:8 + hl])
    payload = blob[8 + hl:-32]
    return header, payload, blob[:-32], blob[-32:]


def verify(body: bytes, tag: bytes, seed: bytes) -> bool:
    return hmac.compare_digest(hmac.new(_mac_key(seed), body, hashlib.sha256).digest(), tag)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s)
