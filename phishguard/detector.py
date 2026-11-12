import ipaddress
import re
from urllib.parse import urlparse
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

SUSPICIOUS_WORDS = ["login", "verify", "update", "secure", "account", "banking",
                    "password", "signin", "confirm", "wallet", "support"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "ow.ly", "buff.ly"}

def normalize_url(raw):
    raw = raw.strip()
    if not raw:
        raise ValueError("Enter a URL.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "http://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc:
        raise ValueError("That does not look like a valid URL. Try example.com.")
    return raw, parsed

def extract_features(raw):
    normalized, p = normalize_url(raw)
    host = (p.hostname or "").lower()
    try:
        ipaddress.ip_address(host)
        is_ip = 1
    except ValueError:
        is_ip = 0
    labels = host.split(".")
    path_query = (p.path + "?" + p.query).lower()
    return {
        "url_length": len(normalized),
        "hostname_length": len(host),
        "dot_count": host.count("."),
        "hyphen_count": normalized.count("-"),
        "at_symbol": int("@" in normalized),
        "https": int(p.scheme.lower() == "https"),
        "ip_address_host": is_ip,
        "subdomain_count": max(0, len(labels) - 2),
        "digit_count": sum(ch.isdigit() for ch in normalized),
        "suspicious_word_count": sum(word in path_query or word in host for word in SUSPICIOUS_WORDS),
        "shortener_domain": int(host in SHORTENERS),
        "has_port": int(p.port is not None) if p.port else 0,
        "double_slash_in_path": int("//" in p.path),
    }

def _synthetic_dataset(seed=17, n=2400):
    """Create reproducible teaching examples; labels are generated from simulated patterns."""
    rng = np.random.default_rng(seed)
    X, y = [], []
    for _ in range(n):
        label = int(rng.random() < 0.5)
        if label:
            row = [int(rng.integers(55, 190)), int(rng.integers(18, 65)),
                   int(rng.integers(2, 7)), int(rng.integers(1, 7)),
                   int(rng.random() < .22), int(rng.random() < .25),
                   int(rng.random() < .18), int(rng.integers(1, 5)),
                   int(rng.integers(3, 24)), int(rng.integers(1, 5)),
                   int(rng.random() < .13), int(rng.random() < .12),
                   int(rng.random() < .15)]
        else:
            row = [int(rng.integers(12, 95)), int(rng.integers(6, 32)),
                   int(rng.integers(1, 4)), int(rng.integers(0, 3)),
                   int(rng.random() < .01), int(rng.random() < .82),
                   int(rng.random() < .005), int(rng.integers(0, 3)),
                   int(rng.integers(0, 12)), int(rng.integers(0, 2)),
                   int(rng.random() < .005), int(rng.random() < .02),
                   int(rng.random() < .01)]
        X.append(row); y.append(label)
    return np.asarray(X), np.asarray(y)

FEATURE_NAMES = ["url_length", "hostname_length", "dot_count", "hyphen_count",
                 "at_symbol", "https", "ip_address_host", "subdomain_count",
                 "digit_count", "suspicious_word_count", "shortener_domain",
                 "has_port", "double_slash_in_path"]

def train_model():
    X, y = _synthetic_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=.2, random_state=42, stratify=y)
    model = RandomForestClassifier(n_estimators=160, max_depth=9,
                                   min_samples_leaf=2, class_weight="balanced",
                                   random_state=42)
    model.fit(X_train, y_train)
    model.demo_accuracy_ = accuracy_score(y_test, model.predict(X_test))
    model.demo_samples_ = len(y)
    return model

def get_model_metrics(model):
    return {"accuracy": model.demo_accuracy_, "samples": model.demo_samples_}

def analyze_url(raw, model):
    features = extract_features(raw)
    vector = np.array([[features[name] for name in FEATURE_NAMES]])
    probability = float(model.predict_proba(vector)[0][1])
    indicators = []
    _, p = normalize_url(raw)
    host = (p.hostname or "").lower()
    try:
        ipaddress.ip_address(host); indicators.append("The hostname is an IP address instead of a typical domain name.")
    except ValueError:
        pass
    if "@" in raw: indicators.append("The URL contains an @ symbol, which can obscure the actual destination.")
    if p.scheme.lower() != "https": indicators.append("The URL does not use HTTPS.")
    if len(raw) > 100: indicators.append("The URL is unusually long.")
    if host in SHORTENERS: indicators.append("The hostname is a known URL-shortening domain; the final destination is hidden.")
    if features["subdomain_count"] >= 3: indicators.append("The hostname contains several subdomain levels.")
    if features["suspicious_word_count"] >= 2: indicators.append("The URL contains multiple words commonly used in credential or account lures.")
    if features["hyphen_count"] >= 3: indicators.append("The URL contains several hyphens.")
    if features["digit_count"] >= 8: indicators.append("The URL contains many digits.")
    heuristic = min(100, len(indicators) * 13 + (10 if features["ip_address_host"] else 0))
    score = int(round(0.55 * probability * 100 + 0.45 * heuristic))
    return {"risk_score": score, "ml_probability": probability,
            "indicators": indicators, "features": features}
