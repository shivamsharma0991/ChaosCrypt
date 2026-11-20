import numpy as np

from . import pipeline


def entropy(arr8: np.ndarray) -> float:
    counts = np.bincount(arr8.ravel(), minlength=256).astype(np.float64)
    p = counts[counts > 0] / counts.sum()
    return float(-(p * np.log2(p)).sum())


def _gray(a):
    return a.astype(np.float64).mean(axis=2) if a.ndim == 3 else a.astype(np.float64)


def correlation(arr8: np.ndarray, samples=5000, seed=0):
    """Horizontal / vertical / diagonal adjacent-pixel correlation."""
    g = _gray(arr8)
    h, w = g.shape
    rng = np.random.default_rng(seed)
    ys = rng.integers(0, h - 1, samples)
    xs = rng.integers(0, w - 1, samples)

    def r(a, b):
        if a.std() == 0 or b.std() == 0:
            return 0.0
        return float(np.corrcoef(a, b)[0, 1])

    base = g[ys, xs]
    return {
        "horizontal": r(base, g[ys, xs + 1]),
        "vertical": r(base, g[ys + 1, xs]),
        "diagonal": r(base, g[ys + 1, xs + 1]),
    }


def npcr_uaci(img: np.ndarray, seed: bytes, cipher: np.ndarray):
    """Flip one pixel of the plaintext, re-encrypt with the same seed, compare."""
    img2 = img.copy()
    img2[0, 0, 0] = (int(img2[0, 0, 0]) + 1) % 256
    c2 = pipeline.encrypt_array(img2, seed)
    npcr = float((cipher != c2).mean() * 100)
    uaci = float((np.abs(cipher - c2) / 65535.0).mean() * 100)
    return npcr, uaci


def analyze(img, cipher, seed, with_diffusion=True):
    prev = pipeline.cipher_preview(cipher)
    out = {
        "entropy_plain": entropy(img),
        "entropy_cipher": entropy(prev),
        "corr_plain": correlation(img),
        "corr_cipher": correlation(prev),
    }
    if with_diffusion:
        out["npcr"], out["uaci"] = npcr_uaci(img, seed, cipher)
    return out
