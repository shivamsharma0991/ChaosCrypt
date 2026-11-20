import base64
import io

import numpy as np
from flask import Flask, jsonify, request, send_from_directory
from PIL import Image, UnidentifiedImageError

from core import envelope, metrics, pipeline

MAX_PIXELS = 1024 * 1024         
Image.MAX_IMAGE_PIXELS = 50_000_000

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 30 * 1024 * 1024


def _err(msg, code=400):
    return jsonify({"error": msg}), code


def _png_b64(arr: np.ndarray) -> str:
    buf = io.BytesIO()
    Image.fromarray(arr.squeeze() if arr.shape[2] == 1 else arr).save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "pipeline": "Int-WINN-Chaos", "max_pixels": MAX_PIXELS})


@app.post("/api/keys")
def keys():
    pub, priv = envelope.generate_keypair()
    return jsonify({"public_key": pub, "private_key": priv})


@app.post("/api/encrypt")
def encrypt():
    f = request.files.get("image")
    pub = (request.form.get("public_key") or "").strip()
    if not f:
        return _err("Please choose an image.")
    if not pub:
        return _err("A public key is required. Generate or paste one.")
    try:
        im = Image.open(f.stream)
        im = im.convert("L") if im.mode in ("L", "1") else im.convert("RGB")
    except (UnidentifiedImageError, OSError):
        return _err("That file is not a readable image.")
    img = np.asarray(im, dtype=np.uint8)
    if img.ndim == 2:
        img = img[:, :, None]
    h, w = img.shape[:2]
    if h < 2 or w < 2:
        return _err("Image is too small.")
    if h * w > MAX_PIXELS:
        return _err(f"Image is {w}x{h}; the limit is {MAX_PIXELS} pixels (about 1024x1024).", 413)
    try:
        pkg, cipher, seed, ms = pipeline.encrypt_image(img, pub)
    except ValueError:
        return _err("The public key could not be read. Use a PEM public key.")
    analyze = request.form.get("analyze", "true") == "true"
    res = {
        "encrypted_preview": _png_b64(pipeline.cipher_preview(cipher)),
        "package": base64.b64encode(pkg).decode(),
        "package_bytes": len(pkg),
        "original_bytes": h * w * img.shape[2],
        "width": w, "height": h, "channels": img.shape[2],
        "time_ms": round(ms, 1),
    }
    if analyze:
        res["metrics"] = metrics.analyze(img, cipher, seed)
    return jsonify(res)


@app.post("/api/decrypt")
def decrypt():
    f = request.files.get("package")
    priv = (request.form.get("private_key") or "").strip()
    if not f:
        return _err("Please provide the .enc package.")
    if not priv:
        return _err("A private key is required.")
    allow = request.form.get("allow_corrupt", "false") == "true"
    try:
        img, info = pipeline.decrypt_package(f.read(), priv, allow_corrupt=allow)
    except ValueError as e:
        return _err(str(e))
    info["image"] = _png_b64(img)
    return jsonify(info)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
