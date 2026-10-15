from __future__ import annotations

import io
import json
import logging
import os
import secrets
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "model"
MODEL_PATH = MODEL_DIR / "ddos_model.joblib"
FEATURES_PATH = MODEL_DIR / "model_features.json"
LOG_DIR = BASE_DIR / "logs"
LOG_PATH = LOG_DIR / "security.log"

load_dotenv(BASE_DIR / ".env")

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_CSV_ROWS = 100_000
MAX_CSV_COLUMNS = 250
ALLOWED_EXTENSIONS = {".csv"}

app = Flask(__name__, static_folder=None)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY") or secrets.token_hex(32),
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=60 * 60,
    JSON_SORT_KEYS=False,
)

# For local/student use. Use Redis or another shared backend for multi-worker production.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
)

LOG_DIR.mkdir(parents=True, exist_ok=True)
logger = logging.getLogger("ddos_security")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = RotatingFileHandler(LOG_PATH, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)

model = None
features: list[str] = []
model_load_error = None
try:
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(f"Model file not found: {MODEL_PATH}")
    if not FEATURES_PATH.is_file():
        raise FileNotFoundError(f"Feature list not found: {FEATURES_PATH}")
    model = joblib.load(MODEL_PATH)
    with FEATURES_PATH.open("r", encoding="utf-8") as f:
        loaded_features = json.load(f)
    if not isinstance(loaded_features, list) or not loaded_features:
        raise ValueError("model/model_features.json must contain a non-empty JSON list.")
    if not all(isinstance(item, str) and item.strip() for item in loaded_features):
        raise ValueError("Every model feature must be a non-empty string.")
    if len(set(loaded_features)) != len(loaded_features):
        raise ValueError("model_features.json contains duplicate feature names.")
    features = loaded_features
except Exception as exc:
    model_load_error = str(exc)
    logger.exception("Model initialization failed")

def audit(event: str, details: str = "") -> None:
    """Write short audit events; never log uploaded CSV contents or passwords."""
    safe_details = str(details).replace("\n", " ").replace("\r", " ")[:300]
    logger.info("event=%s ip=%s details=%s", event, get_remote_address(), safe_details)

def is_authenticated() -> bool:
    return bool(session.get("authenticated"))

def require_login():
    if not is_authenticated():
        return jsonify({"error": "Please log in to use this feature."}), 401
    return None

def normalise_label(value):
    text = str(value).strip().upper()
    if text in {"0", "0.0", "BENIGN", "NORMAL", "LEGITIMATE"}:
        return 0
    if text in {"1", "1.0", "DDOS", "DOS", "ATTACK", "DDOS/ATTACK"}:
        return 1
    return None

def label_name(value):
    return "DDoS / Attack" if int(value) == 1 else "Benign"

def read_uploaded_csv(require_label: bool = False):
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        raise ValueError("Choose a CSV file first.")
    filename = Path(upload.filename).name
    if Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError("Only .csv files are allowed.")
    raw = upload.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise ValueError("File exceeds the 25 MB upload limit.")
    if not raw:
        raise ValueError("The uploaded file is empty.")
    try:
        df = pd.read_csv(io.BytesIO(raw), encoding="utf-8-sig", nrows=MAX_CSV_ROWS + 1, low_memory=False)
    except UnicodeDecodeError:
        raise ValueError("CSV must be saved as UTF-8 or UTF-8 with BOM.")
    except Exception as exc:
        raise ValueError(f"Could not parse this CSV file: {exc}")
    if df.empty:
        raise ValueError("The CSV has a header but no data rows.")
    if len(df) > MAX_CSV_ROWS:
        raise ValueError(f"CSV has too many rows. Maximum allowed: {MAX_CSV_ROWS:,}.")
    if len(df.columns) > MAX_CSV_COLUMNS:
        raise ValueError(f"CSV has too many columns. Maximum allowed: {MAX_CSV_COLUMNS}.")
    df.columns = [str(col).strip().lstrip("\ufeff") for col in df.columns]
    if any(not col for col in df.columns):
        raise ValueError("CSV contains an empty column name.")
    if len(set(df.columns)) != len(df.columns):
        raise ValueError("CSV contains duplicate column names.")
    if require_label and "label" not in [c.lower() for c in df.columns]:
        raise ValueError("Evaluation requires a label column named 'label'.")
    return filename, df

def prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    if model is None:
        raise RuntimeError("The model could not be loaded. Check the model folder and restart the app.")
    missing = [col for col in features if col not in df.columns]
    if missing:
        raise ValueError(
            "This CSV does not match the trained model. Missing required feature columns: "
            + ", ".join(missing)
            + ". Upload data with the exact column names from model/model_features.json. "
              "Do not rename unrelated columns or invent missing features."
        )
    X = df.loc[:, features].copy()
    for col in features:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    invalid_rows = X.isna().any(axis=1)
    if invalid_rows.any():
        examples = [int(i) + 2 for i in X.index[invalid_rows][:5]]
        raise ValueError(
            f"{int(invalid_rows.sum())} row(s) contain missing, non-numeric, or infinite values "
            f"in required model features. Example CSV line(s): {examples}. Clean these values and retry."
        )
    return X

def predict_with_confidence(X: pd.DataFrame):
    if model is None:
        raise RuntimeError("Model is not loaded.")
    raw_predictions = model.predict(X)
    mapped = []
    for value in raw_predictions:
        label = normalise_label(value)
        if label is None:
            raise RuntimeError(
                f"The loaded model returned an unsupported class {value!r}. "
                "This dashboard expects model classes 0=Benign and 1=DDoS/Attack."
            )
        mapped.append(label)
    confidence = [None] * len(mapped)
    if hasattr(model, "predict_proba"):
        try:
            probabilities = model.predict_proba(X)
            classes = list(getattr(model, "classes_", []))
            if not classes and hasattr(model, "named_steps"):
                final_estimator = list(model.named_steps.values())[-1]
                classes = list(getattr(final_estimator, "classes_", []))
            for i, pred in enumerate(mapped):
                match = next((j for j, cls in enumerate(classes) if normalise_label(cls) == pred), None)
                if match is not None:
                    confidence[i] = round(float(probabilities[i][match]) * 100, 2)
        except Exception:
            confidence = [None] * len(mapped)
    return mapped, confidence

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'"
    )
    return response

@app.errorhandler(413)
def too_large(_error):
    audit("upload_rejected", "reason=request_too_large")
    return jsonify({"error": "Upload exceeds the 25 MB limit."}), 413

@app.errorhandler(429)
def rate_limited(_error):
    audit("rate_limited", request.path)
    return jsonify({"error": "Too many requests. Wait a moment and try again."}), 429

@app.get("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")

@app.get("/style.css")
def style():
    return send_from_directory(BASE_DIR, "style.css")

@app.get("/script.js")
def script():
    return send_from_directory(BASE_DIR, "script.js")

@app.get("/api/session")
def session_status():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return jsonify({
        "authenticated": is_authenticated(),
        "username": session.get("username"),
        "csrf_token": token,
        "model_loaded": model is not None,
        "model_error": model_load_error if model is None else None,
        "features": features,
    })

def check_csrf():
    expected = session.get("csrf_token")
    supplied = request.headers.get("X-CSRF-Token", "")
    return bool(expected and supplied and secrets.compare_digest(expected, supplied))

@app.post("/api/login")
@limiter.limit("5 per minute")
def login():
    if not request.is_json:
        return jsonify({"error": "Send login details as JSON."}), 415
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", ""))[:100]
    password = str(body.get("password", ""))[:1024]
    if not check_csrf():
        audit("login_failed", "reason=csrf")
        return jsonify({"error": "Session expired. Refresh the page and try again."}), 400
    expected_username = os.getenv("ADMIN_USERNAME", "admin")
    password_hash = os.getenv("ADMIN_PASSWORD_HASH", "")
    if not password_hash:
        audit("login_failed", "reason=admin_password_not_configured")
        return jsonify({"error": "Admin password is not configured. Run python setup_security.py and restart."}), 503
    if not secrets.compare_digest(username, expected_username) or not check_password_hash(password_hash, password):
        audit("login_failed", "reason=invalid_credentials")
        return jsonify({"error": "Invalid username or password."}), 401
    session.clear()
    session["authenticated"] = True
    session["username"] = username
    session["csrf_token"] = secrets.token_urlsafe(32)
    session.permanent = True
    audit("login_success", f"user={username}")
    return jsonify({"ok": True, "username": username, "csrf_token": session["csrf_token"]})

@app.post("/api/logout")
def logout():
    if not is_authenticated():
        return jsonify({"ok": True})
    if not check_csrf():
        return jsonify({"error": "Session expired. Refresh the page and try again."}), 400
    audit("logout", f"user={session.get('username', 'unknown')}")
    session.clear()
    return jsonify({"ok": True})

@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok" if model is not None else "model_error",
        "model_loaded": model is not None,
        "features": features,
        "authentication_configured": bool(os.getenv("ADMIN_PASSWORD_HASH")),
    })

@app.post("/api/analyze")
@limiter.limit("10 per minute")
def analyze():
    denied = require_login()
    if denied:
        return denied
    if not check_csrf():
        return jsonify({"error": "Invalid or expired security token. Refresh the page and retry."}), 400
    try:
        filename, df = read_uploaded_csv()
        X = prepare_features(df)
        predictions, confidence = predict_with_confidence(X)
        benign_count = predictions.count(0)
        ddos_count = predictions.count(1)
        total = len(predictions)
        results = []
        for i, pred in enumerate(predictions):
            row = df.iloc[i]
            source_ip = str(row.get("src_ip", row.get("Source IP", row.get("source_ip", "—"))))
            destination_ip = str(row.get("dst_ip", row.get("Destination IP", row.get("destination_ip", "—"))))
            if source_ip == "nan": source_ip = "—"
            if destination_ip == "nan": destination_ip = "—"
            results.append({
                "record": i + 1,
                "prediction": label_name(pred),
                "source_ip": source_ip[:80],
                "destination_ip": destination_ip[:80],
                "confidence": confidence[i],
                "severity": "HIGH" if pred == 1 else "INFO",
            })
        audit("analysis_success", f"file={Path(filename).name} rows={total} ddos={ddos_count}")
        return jsonify({
            "total": total,
            "benign": benign_count,
            "ddos": ddos_count,
            "detection_rate": round(ddos_count / total * 100, 2) if total else 0,
            "results": results,
        })
    except (ValueError, RuntimeError) as exc:
        audit("analysis_rejected", str(exc))
        return jsonify({"error": str(exc)}), 400
    except Exception:
        logger.exception("Unexpected analysis failure")
        audit("analysis_error", "unexpected_exception")
        return jsonify({"error": "Analysis failed unexpectedly. Check logs/security.log for details."}), 500

@app.post("/api/evaluate")
@limiter.limit("5 per minute")
def evaluate():
    denied = require_login()
    if denied:
        return denied
    if not check_csrf():
        return jsonify({"error": "Invalid or expired security token. Refresh the page and retry."}), 400
    try:
        filename, df = read_uploaded_csv(require_label=True)
        label_col = next(c for c in df.columns if c.lower() == "label")
        actual = [normalise_label(v) for v in df[label_col].tolist()]
        if any(v is None for v in actual):
            examples = sorted({str(v) for v in df.loc[[v is None for v in actual], label_col].head(5).tolist()})
            raise ValueError(
                "Evaluation supports only BENIGN/0 and DDoS/ATTACK/1 labels. "
                f"Unsupported label example(s): {examples}. This model is binary; it does not evaluate PORT_SCAN or BRUTE_FORCE."
            )
        X = prepare_features(df)
        predicted, _confidence = predict_with_confidence(X)
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
        matrix = confusion_matrix(actual, predicted, labels=[0, 1]).tolist()
        report = classification_report(
            actual, predicted, labels=[0, 1], target_names=["Benign", "DDoS / Attack"],
            output_dict=True, zero_division=0
        )
        metrics = {
            "accuracy": round(float(accuracy_score(actual, predicted)) * 100, 2),
            "precision": round(float(precision_score(actual, predicted, zero_division=0)) * 100, 2),
            "recall": round(float(recall_score(actual, predicted, zero_division=0)) * 100, 2),
            "f1_score": round(float(f1_score(actual, predicted, zero_division=0)) * 100, 2),
            "confusion_matrix": matrix,
            "class_report": {
                "benign": {
                    "precision": round(float(report["Benign"]["precision"]) * 100, 2),
                    "recall": round(float(report["Benign"]["recall"]) * 100, 2),
                    "f1_score": round(float(report["Benign"]["f1-score"]) * 100, 2),
                    "support": int(report["Benign"]["support"]),
                },
                "ddos": {
                    "precision": round(float(report["DDoS / Attack"]["precision"]) * 100, 2),
                    "recall": round(float(report["DDoS / Attack"]["recall"]) * 100, 2),
                    "f1_score": round(float(report["DDoS / Attack"]["f1-score"]) * 100, 2),
                    "support": int(report["DDoS / Attack"]["support"]),
                },
            },
            "records": len(actual),
        }
        audit("evaluation_success", f"file={Path(filename).name} rows={len(actual)} accuracy={metrics['accuracy']}")
        return jsonify(metrics)
    except (ValueError, RuntimeError, StopIteration) as exc:
        audit("evaluation_rejected", str(exc))
        return jsonify({"error": str(exc)}), 400
    except Exception:
        logger.exception("Unexpected evaluation failure")
        audit("evaluation_error", "unexpected_exception")
        return jsonify({"error": "Evaluation failed unexpectedly. Check logs/security.log for details."}), 500

if __name__ == "__main__":
    if not os.getenv("ADMIN_PASSWORD_HASH"):
        print("Admin credentials are not configured. First run: python setup_security.py")
    if os.getenv("SECRET_KEY") is None:
        print("WARNING: SECRET_KEY is not set. Run setup_security.py to create a persistent key.")
    print(f"Model loaded: {model is not None}")
    if model is None:
        print(f"Model load error: {model_load_error}")
    print("Open http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)
