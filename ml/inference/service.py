"""HTTP inference service consumed by the MailSherlock API.

The service receives the *raw* message so it parses it with exactly the code
used during training. It binds to loopback only; the Node API is the single
public entry point.

Run: ``python3 -m ml.inference.service`` (or ``npm run ml:serve``).
"""

from __future__ import annotations

import logging
import os

import uvicorn
from fastapi import FastAPI, HTTPException, Request

from ml.config import MAX_EMAIL_BYTES
from ml.inference.predictor import Predictor

log = logging.getLogger("mailsherlock.ml")
app = FastAPI(title="MailSherlock ML inference", docs_url=None, redoc_url=None)
_predictor: Predictor | None = None
_load_error: str | None = None


def predictor() -> Predictor:
    global _predictor, _load_error
    if _predictor is None and _load_error is None:
        try:
            _predictor = Predictor.load()
        except Exception as exc:  # model missing or incompatible
            _load_error = f"{type(exc).__name__}: {exc}"
            log.error("model load failed: %s", _load_error)
    if _predictor is None:
        raise HTTPException(status_code=503, detail=_load_error or "model unavailable")
    return _predictor


@app.get("/health")
def health() -> dict:
    model = predictor()
    return {"status": "ok", "model_version": model.metadata["model_version"]}


@app.get("/model")
def model_info() -> dict:
    model = predictor()
    return {"metadata": model.metadata, "metrics": model.metrics}


@app.post("/predict")
async def predict(request: Request) -> dict:
    model = predictor()
    raw = await request.body()
    if not raw:
        raise HTTPException(status_code=400, detail="empty message")
    if len(raw) > MAX_EMAIL_BYTES * 6:
        raise HTTPException(status_code=413, detail="message too large")
    prediction = model.predict_raw(raw)
    return {
        "model_name": model.metadata["model_name"],
        "model_version": model.metadata["model_version"],
        **prediction.as_dict(),
    }


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    predictor()  # load eagerly so the first request is fast and failures are visible at startup
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("ML_PORT", "8001")), log_level="warning")


if __name__ == "__main__":
    main()
