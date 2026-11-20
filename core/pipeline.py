import hashlib
import json
import os
import time

import numpy as np

from . import chaos, envelope, inn, iwt

LEVELS = 2
M = 0xFFFF


def _to_words(coef):
    return (coef.ravel() & M).astype(np.int64)


def _from_words(words, shape):
    v = words.reshape(shape).astype(np.int64)
    return np.where(v >= 32768, v - 65536, v)


def encrypt_array(img: np.ndarray, seed: bytes):
    """Return ciphertext int64 array (Hp, Wp, C) with values in [0, 65535]."""
    padded = iwt.pad_to_multiple(img, LEVELS)
    coef = iwt.forward(padded, LEVELS)
    flat = _to_words(coef)
    perm, ks1, ks2 = chaos.keystreams(seed, flat.size)
    flat = flat[perm]
    flat = inn.forward(flat, seed)
    a = (flat + ks1) & M
    b = np.cumsum(a) & M                       # forward diffusion
    c = (b + ks2) & M
    d = np.cumsum(c[::-1])[::-1] & M           # backward diffusion
    return d.reshape(padded.shape)


def decrypt_array(cipher: np.ndarray, seed: bytes):
    shape = cipher.shape
    d = cipher.ravel().astype(np.int64)
    perm, ks1, ks2 = chaos.keystreams(seed, d.size)
    c = d.copy()
    c[:-1] = (d[:-1] - d[1:]) & M
    b = (c - ks2) & M
    a = b.copy()
    a[1:] = (b[1:] - b[:-1]) & M
    flat = (a - ks1) & M
    flat = inn.inverse(flat, seed)
    plain = np.empty_like(flat)
    plain[perm] = flat
    coef = _from_words(plain, shape)
    return iwt.inverse(coef, LEVELS)


def cipher_preview(cipher: np.ndarray) -> np.ndarray:
    """8-bit view of the 16-bit ciphertext (low byte) for display."""
    return (cipher & 0xFF).astype(np.uint8)


def encrypt_image(img: np.ndarray, public_pem: str):
    """Full pipeline incl. RSA envelope. Returns (package_bytes, cipher, seed, timing_ms)."""
    t0 = time.perf_counter()
    h, w, c = img.shape
    seed = os.urandom(32)
    cipher = encrypt_array(img, seed)
    wrapped = envelope.wrap_seed(seed, public_pem)
    header = {
        "v": 1, "h": h, "w": w, "c": c, "levels": LEVELS,
        "hp": cipher.shape[0], "wp": cipher.shape[1],
        "key": envelope.b64e(wrapped),
        "sha256": hashlib.sha256(img.tobytes()).hexdigest(),
    }
    payload = cipher.astype("<u2").tobytes()
    pkg = envelope.pack(header, payload, seed)
    return pkg, cipher, seed, (time.perf_counter() - t0) * 1000


def decrypt_package(blob: bytes, private_pem: str, allow_corrupt=False):
    """Returns (img uint8 (H,W,C), info dict). Raises ValueError with a user-safe message."""
    t0 = time.perf_counter()
    header, payload, body, tag = envelope.parse(blob)
    try:
        seed = envelope.unwrap_seed(envelope.b64d(header["key"]), private_pem)
    except Exception:
        raise ValueError("Wrong private key for this package (RSA unwrap failed).")
    integrity = envelope.verify(body, tag, seed)
    if not integrity and not allow_corrupt:
        raise ValueError("Integrity check failed: the package was modified or damaged.")
    hp, wp, c = header["hp"], header["wp"], header["c"]
    if len(payload) != hp * wp * c * 2:
        raise ValueError("Payload size does not match the header.")
    cipher = np.frombuffer(payload, dtype="<u2").astype(np.int64).reshape(hp, wp, c)
    plain = decrypt_array(cipher, seed)
    img = np.clip(plain[:header["h"], :header["w"]], 0, 255).astype(np.uint8)
    exact = hashlib.sha256(img.tobytes()).hexdigest() == header["sha256"]
    return img, {
        "integrity_ok": integrity,
        "bit_exact": exact,
        "width": header["w"], "height": header["h"], "channels": c,
        "time_ms": round((time.perf_counter() - t0) * 1000, 1),
    }
