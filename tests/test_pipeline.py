import io
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import numpy as np
import pytest
from PIL import Image

from core import envelope, iwt, metrics, pipeline
from app import app


def sample(h=64, w=48, c=3, seed=0):
    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:h, 0:w]
    base = ((x * 3 + y * 2) % 256).astype(np.uint8)
    img = np.stack([base] * c, axis=2)
    img[::7] = rng.integers(0, 256, img[::7].shape, dtype=np.uint8)
    return img


@pytest.fixture(scope="module")
def keys():
    return envelope.generate_keypair()


def test_iwt_lossless_extremes():
    rng = np.random.default_rng(1)
    for arr in (rng.integers(0, 256, (16, 16, 3)), np.zeros((8, 8, 1), int), np.full((8, 8, 1), 255)):
        assert np.array_equal(iwt.inverse(iwt.forward(arr, 2), 2), arr)


@pytest.mark.parametrize("shape", [(64, 48, 3), (33, 17, 3), (20, 20, 1), (2, 2, 3)])
def test_roundtrip_bit_exact(keys, shape):
    img = sample(*shape)
    pkg, _, _, _ = pipeline.encrypt_image(img, keys[0])
    out, info = pipeline.decrypt_package(pkg, keys[1])
    assert np.array_equal(out, img) and info["bit_exact"] and info["integrity_ok"]


def test_wrong_key_and_tamper(keys):
    img = sample()
    pkg, _, _, _ = pipeline.encrypt_image(img, keys[0])
    other_priv = envelope.generate_keypair()[1]
    with pytest.raises(ValueError):
        pipeline.decrypt_package(pkg, other_priv)
    bad = bytearray(pkg); bad[-100] ^= 1
    with pytest.raises(ValueError):
        pipeline.decrypt_package(bytes(bad), keys[1])
    out, info = pipeline.decrypt_package(bytes(bad), keys[1], allow_corrupt=True)
    assert not info["integrity_ok"] and not info["bit_exact"]


def test_security_metrics(keys):
    img = sample(96, 96)
    pkg, cipher, seed, _ = pipeline.encrypt_image(img, keys[0])
    m = metrics.analyze(img, cipher, seed)
    assert m["entropy_cipher"] > 7.99
    assert abs(m["corr_cipher"]["horizontal"]) < 0.05
    assert m["npcr"] > 99.5


def test_api_end_to_end():
    c = app.test_client()
    k = c.post("/api/keys").get_json()
    buf = io.BytesIO(); Image.fromarray(sample(40, 30)).save(buf, "PNG"); buf.seek(0)
    r = c.post("/api/encrypt", data={"image": (buf, "a.png"), "public_key": k["public_key"], "analyze": "false"})
    assert r.status_code == 200
    import base64
    pkg = base64.b64decode(r.get_json()["package"])
    r2 = c.post("/api/decrypt", data={"package": (io.BytesIO(pkg), "a.enc"), "private_key": k["private_key"]})
    j = r2.get_json()
    assert r2.status_code == 200 and j["bit_exact"]
    # errors
    assert c.post("/api/encrypt", data={}).status_code == 400
    bad = c.post("/api/encrypt", data={"image": (io.BytesIO(b"nope"), "x.png"), "public_key": k["public_key"]})
    assert bad.status_code == 400
