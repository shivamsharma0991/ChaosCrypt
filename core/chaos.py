import hashlib
import math

import numpy as np

WARMUP = 2000


def hash_bytes(seed: bytes, label: bytes, n: int) -> bytes:
    """Deterministic SHA-256 counter-mode byte stream."""
    out, ctr = b"", 0
    while len(out) < n:
        out += hashlib.sha256(seed + label + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return out[:n]


def _params(seed: bytes):
    h = hash_bytes(seed, b"IWC-chaos", 80)

    def f(i, lo, hi):
        v = int.from_bytes(h[8 * i:8 * i + 8], "big") / 2.0 ** 64
        return lo + (hi - lo) * v

    return dict(
        x=f(0, 0.05, 0.95), y=f(1, 0.05, 0.95), z=f(2, 0.05, 0.95),
        mu=f(3, 1.90, 1.99), b1=f(4, 2.6, 3.6), b2=f(5, 2.6, 3.6),
        b3=f(6, 2.6, 3.6), phi=f(7, 0.30, 0.70), kick=f(8, 0.10, 0.45),
    )


def generate(seed: bytes, n: int):
    """Return three float64 arrays X, Y, Z of length n in [0, 1]."""
    p = _params(seed)
    x, y, z = p["x"], p["y"], p["z"]
    mu, b1, b2, b3, phi, kick = p["mu"], p["b1"], p["b2"], p["b3"], p["phi"], p["kick"]
    sin, cos, pi = math.sin, math.cos, math.pi
    total = n + WARMUP
    X, Y, Z = [0.0] * total, [0.0] * total, [0.0] * total
    for i in range(total):
        t = mu * x if x < 0.5 else mu * (1.0 - x)          # tent term
        ph = (i * phi) % 1.0                                 # dynamic phase
        x = abs(sin(pi * (b1 * t + y + ph)))                 # sine
        y = abs(cos(pi * (b2 * y + z + kick * x)))           # cosine
        z = abs(sin(pi * (b3 * z + x * y + kick * ph)))      # sine-cross
        X[i], Y[i], Z[i] = x, y, z
    return (np.array(X[WARMUP:]), np.array(Y[WARMUP:]), np.array(Z[WARMUP:]))


def _low16(v):
    return ((v * 2.0 ** 40).astype(np.uint64) & 0xFFFF).astype(np.int64)


def keystreams(seed: bytes, n: int):
    """Return (permutation, ks1, ks2) for n 16-bit elements."""
    X, Y, Z = generate(seed, n)
    perm = np.argsort(X, kind="stable")
    return perm, _low16(Y), _low16(Z)
