import numpy as np

from .chaos import hash_bytes

MOD = 1 << 16
HIDDEN = 8
ROUNDS = 3


def _weights(seed: bytes, label: bytes):
    raw = np.frombuffer(hash_bytes(seed, b"IWC-inn" + label, HIDDEN * 3 + HIDDEN + HIDDEN + 1), dtype=np.uint8).astype(np.int64)
    w1 = (raw[:HIDDEN * 3] % 17 - 8).reshape(HIDDEN, 3)
    b1 = (raw[HIDDEN * 3:HIDDEN * 4] % 64 - 32) * 256
    w2 = (raw[HIDDEN * 4:HIDDEN * 5] % 17 - 8).reshape(1, HIDDEN)
    return w1, b1, w2


def _F(b, w):
    w1, b1, w2 = w
    b = b.astype(np.int64)
    feats = np.stack([b, np.roll(b, 1), np.roll(b, -1)])      # (3, n)
    hid = np.maximum(w1 @ feats + b1[:, None], 0) >> 10       # ReLU + floor
    return ((w2 @ hid) >> 2)[0] & (MOD - 1)


def forward(flat, seed: bytes):
    """flat: int64 array of even length, values in [0, 65535]."""
    n = flat.size // 2
    a, b = flat[:n].copy(), flat[n:].copy()
    for r in range(ROUNDS):
        a = (a + _F(b, _weights(seed, b"F%d" % r))) & (MOD - 1)
        b = (b + _F(a, _weights(seed, b"G%d" % r))) & (MOD - 1)
    return np.concatenate([a, b])


def inverse(flat, seed: bytes):
    n = flat.size // 2
    a, b = flat[:n].copy(), flat[n:].copy()
    for r in range(ROUNDS - 1, -1, -1):
        b = (b - _F(a, _weights(seed, b"G%d" % r))) & (MOD - 1)
        a = (a - _F(b, _weights(seed, b"F%d" % r))) & (MOD - 1)
    return np.concatenate([a, b])
