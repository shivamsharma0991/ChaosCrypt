# Int-WINN-Chaos Image Encryption (backend + frontend)

Lossless image encryption with a Flask backend and a browser frontend.
The frontend talks to the backend over a local JSON API. All cryptography
runs locally in Python; no external or AI API is used.

## Run

```bash
pip install -r requirements.txt
python app.py          # then open http://127.0.0.1:5000
python -m pytest -q    # tests
```

## How it works

1. **Integer Haar wavelet** (lifting, Z to Z, 2 levels) per channel, exactly invertible.
2. Coefficients become 16-bit words, shuffled by a **3D Sine-Tent-Cosine hyperchaotic** permutation (phase-perturbed each step).
3. **INN additive coupling layers** (integer MLP, ReLU, floor rounding, mod 2^16).
4. Chaotic keystream add + forward and backward cumulative **diffusion**, so one changed pixel changes the whole ciphertext.
5. A random 32-byte session seed drives steps 2 to 4. It is wrapped with **RSA-2048 OAEP (SHA-256)** and stored in the `.enc` package with an **HMAC-SHA256** integrity tag.

Decryption inverts every step: result is bit-exact (PSNR = infinity). The package stores a SHA-256 of the original pixels, so the UI can confirm an exact match.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | status |
| POST | `/api/keys` | generate RSA key pair |
| POST | `/api/encrypt` | form: `image`, `public_key`, `analyze` -> preview, `.enc` (base64), metrics |
| POST | `/api/decrypt` | form: `package`, `private_key`, `allow_corrupt` -> PNG, integrity flags |

## Notes and limits

- Images up to about 1024x1024 (1M pixels); alpha is dropped, grayscale stays 1 channel. About 1.8 s to encrypt, 0.9 s to decrypt at 512x512.
- Encrypt and decrypt must run on the same platform (the chaos stream uses float64 sin/cos).
- Because of the cumulative diffusion, damage to the ciphertext spreads; this version does not claim the noise tolerance in the earlier benchmark table.
- The server keeps no keys or images. Private keys are only in the browser page unless you download them.
- Research prototype, not independently audited.

## Layout

```
app.py            Flask server + API
core/             iwt.py, chaos.py, inn.py, envelope.py, pipeline.py, metrics.py
static/           index.html, style.css, app.js
tests/            test_pipeline.py
```
