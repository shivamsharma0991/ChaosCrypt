"""Lossless 2D Integer Haar (S-transform) lifting wavelet, Z -> Z.

Layout is Mallat style: after each level the LL band sits in the top-left
corner and is decomposed again.  Everything is exact integer arithmetic, so
inverse(forward(x)) == x bit for bit.
"""
import numpy as np


def _fwd_1d(a, axis):
    a = np.moveaxis(a, axis, 0)
    x, y = a[0::2], a[1::2]
    d = x - y
    s = y + (d >> 1)  # floor(d / 2), arithmetic shift on signed ints
    return np.moveaxis(np.concatenate([s, d], axis=0), 0, axis)


def _inv_1d(c, axis):
    c = np.moveaxis(c, axis, 0)
    n = c.shape[0] // 2
    s, d = c[:n], c[n:]
    y = s - (d >> 1)
    x = y + d
    out = np.empty_like(c)
    out[0::2], out[1::2] = x, y
    return np.moveaxis(out, 0, axis)


def pad_to_multiple(img, levels):
    """Edge-pad an (H, W, C) array so H and W are divisible by 2**levels."""
    m = 1 << levels
    h, w = img.shape[:2]
    ph, pw = (-h) % m, (-w) % m
    if ph or pw:
        img = np.pad(img, ((0, ph), (0, pw), (0, 0)), mode="edge")
    return img


def forward(img, levels=2):
    """(H, W, C) integer array -> int64 coefficient array of the same shape."""
    coef = img.astype(np.int64).copy()
    h, w = coef.shape[:2]
    if h % (1 << levels) or w % (1 << levels):
        raise ValueError("dimensions must be divisible by 2**levels")
    for _ in range(levels):
        sub = _fwd_1d(coef[:h, :w], 0)
        sub = _fwd_1d(sub, 1)
        coef[:h, :w] = sub
        h //= 2
        w //= 2
    return coef


def inverse(coef, levels=2):
    out = coef.astype(np.int64).copy()
    H, W = out.shape[:2]
    for lvl in range(levels - 1, -1, -1):
        h, w = H >> lvl, W >> lvl
        sub = _inv_1d(out[:h, :w], 1)
        sub = _inv_1d(sub, 0)
        out[:h, :w] = sub
    return out
