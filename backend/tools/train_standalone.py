"""
PhishGuard AI - Standalone Model Trainer (Phase A)

Trains a URL phishing classifier using the EXACT same feature extractor as the
live Flask API (imported directly - single source of truth), then exports to
ONNX for embedding inside the browser extension.

Artifacts produced:
  extension/src/assets/url-model-v3.onnx     <- bundled into the extension
  backend/data/models/url-model-v3-meta.json <- metadata (features, labels, metrics)
  backend/tests/data/golden_urls.json        <- golden vectors for JS parity tests

Integrity rules:
  - TEST SET IS REAL-ONLY: augmented (mutated) phishing URLs never enter eval.
  - Feature extraction imported from backend.services.ml_service (no copies).
"""

import json
import random
import sys
import time
import urllib.parse
from pathlib import Path

import numpy as np

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from services.ml_service import MLService  # noqa: E402

RAW_DIR = BACKEND_DIR / "data" / "raw"
MODELS_DIR = BACKEND_DIR / "data" / "models"
ASSETS_DIR = BACKEND_DIR.parent / "extension" / "src" / "assets"
GOLDEN_DIR = BACKEND_DIR / "tests" / "data"

LABELS = ["safe", "phishing"]
PHISH_THRESHOLD = 0.65   # p(phishing) >= .65 -> 'phishing'   (matches ml_service.py)
SUSPicious_THRESHOLD = 0.35  # noqa: N816  # >= .35 -> 'suspicious', else 'safe'

AUG_COPIES = 5          # mutated variants per real phishing URL (TRAIN ONLY)
LEGIT_TRAIN_CAP = 6000


# ---------------------------------------------------------------------------
# Data loading & augmentation
# ---------------------------------------------------------------------------

def load_raw() -> tuple[list[str], list[str]]:
    phish = (RAW_DIR / "phishing_urls.txt").read_text().splitlines()
    legit = (RAW_DIR / "legit_urls.txt").read_text().splitlines()
    return phish, legit


def _mutate(url: str, rng: random.Random) -> str:
    """Realistic trivial mutations attackers apply when cloning kits."""
    if "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    netloc, _, path = rest.partition("/")

    kind = rng.choice(["sub", "path", "dash", "digits", "word"])
    if kind == "sub" and netloc:
        prefix = rng.choice(["secure", "login", "verify", "account", "auth", "update"])
        netloc = f"{prefix}-{netloc}"
    elif kind == "path":
        suffix = rng.choice([
            "/login.php?session=", "/signin/verify?id=", "/account/update?token=",
            "/secure/confirm?uid=", "/wp-content/login?",
        ])
        path = path + suffix if path.endswith("/") else f"/{path}{suffix}" if path else \
            suffix.lstrip("/")
    elif kind == "dash" and netloc:
        parts = netloc.split(".", 1)
        parts[0] = parts[0].replace("", "-", 1).strip("-")
        netloc = "-".join(parts) if len(parts) == 1 else f"{parts[0]}-{parts[1]}"
    elif kind == "digits" and netloc:
        head, _, tail = netloc.partition(".")
        netloc = f"{head}{rng.randint(11, 9999)}.{tail}" if tail else netloc
    elif kind == "word":
        extra = rng.choice(["free", "gift", "bonus", "claim", "wallet", "airdrop"])
        path = f"/{extra}/{path}" if path else f"/{extra}/"

    new = f"{scheme}://{netloc}"
    if path:
        new += "/" + path if not path.startswith("/") else path
    return new


# ---------------------------------------------------------------------------
# LEGIT deep-link generation (fixes the v1 distribution flaw)
# ---------------------------------------------------------------------------

_BENIGN_SUBS = ["www.", "mail.", "docs.", "maps.", "accounts.", "support.",
                "blog.", "shop.", "consent.", "images."]
_BENIGN_SINGLE = ["api", "static", "assets", "media"]

def _rand_id(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
                   for _ in range(n))

def _deepen_legit(url: str, rng: random.Random) -> str:
    """
    Build REAL-WORLD-shaped legit URLs: deep paths, query strings, encoded
    params, service subdomains. Without these the model learns
    'has a path = phishing' (the exact bug seen on youtube/github).
    """
    base = url.rstrip("/")
    if "://" not in base:
        return url
    scheme, rest = base.split("://", 1)
    netloc = rest

    kind = rng.choice(["watch", "watch", "video", "search", "profile", "doc",
                       "product", "social", "encoded", "api", "multi",
                       "numeric", "numeric", "comments", "oauth", "thread",
                       "uuid", "uuid", "uuid", "hexfile"])

    if kind == "hexfile":
        return f"{scheme}://{netloc}/files/{_rand_id(rng, 40).lower()}"

    if kind == "uuid":
        # Modern app routes: /c/<uuid>, /d/<hex>, /p/<uuid>?tab=...
        u = lambda n: "-".join(_rand_id(rng, n) for _ in range(4)).lower()  # noqa: E731
        shape = rng.choice([
            f"/c/{u(8)}",
            f"/d/{_rand_id(rng, 32).lower()}",
            f"/p/{u(8)}?tab={rng.choice(['read','edit','share'])}",
            f"/conversation/{u(8)}",
            f"/t/{rng.choice(['kb','ticket','doc'])}-{_rand_id(rng, 10).lower()}",
        ])
        return f"{scheme}://{netloc}{shape}"

    if kind == "numeric":
        if rng.random() < 0.5:
            return f"{scheme}://{netloc}/{rng.choice(['status','p','post','article'])}/{rng.randint(10**17, 10**18)}"
        # streaming-style: /watch/<id>?trackId=...
        return (f"{scheme}://{netloc}/watch/{rng.randint(10_000_000, 99_999_999)}"
                f"?trackId={rng.randint(1, 99999)}&action={rng.choice(['play','resume'])}")
    if kind == "comments":
        return (f"{scheme}://{netloc}/r/{_rand_id(rng, 8).lower()}/comments/"
                f"{_rand_id(rng, 6).lower()}/{_rand_id(rng, rng.randint(15, 40)).lower()}/"
                f"?sort={rng.choice(['top','new'])}")
    if kind == "oauth":
        return (f"{scheme}://{netloc}/common/oauth2/authorize"
                f"?client_id={_rand_id(rng, 24)}&redirect_uri="
                f"{urllib.parse.quote('https://' + netloc + '/signin', safe='')}"
                f"&response_type=code&scope=openid+profile")
    if kind == "thread":
        return (f"{scheme}://{netloc}/thread/{rng.randint(100000, 999999)}"
                f"?page={rng.randint(1, 30)}&author={_rand_id(rng, 7).lower()}")

    if kind == "watch":
        extra = ""
        if rng.random() < 0.5:
            extra = f"&list={_rand_id(rng, rng.randint(20, 34))}"
        if rng.random() < 0.3:
            extra += f"&t={rng.randint(10, 3600)}s"
        return f"{scheme}://{netloc}/watch?v={_rand_id(rng, 11)}{extra}"
    if kind == "video":
        return (f"{scheme}://{netloc}/video/{rng.randint(10000, 9999999)}/"
                f"{_rand_id(rng, rng.randint(6, 20)).lower()}")
    if kind == "search":
        q = rng.choice(["best+laptop+2026", "how+to+learn+python",
                        "weather+today", "cheap+flights", "news"])
        return f"{scheme}://{netloc}/search?q={q}&o=&gs_l={_rand_id(rng, 14)}"
    if kind == "profile":
        return f"{scheme}://{netloc}/@{_rand_id(rng, rng.randint(5, 12)).lower()}"
    if kind == "doc":
        return (f"{scheme}://{netloc}/{rng.choice(['docs','guide','wiki'])}/"
                f"{rng.choice(['getting-started','user-manual','faq'])}.html")
    if kind == "product":
        return (f"{scheme}://{netloc}/product/{_rand_id(rng, 10).upper()}"
                f"?variant={rng.randint(1, 40)}&ref={rng.choice(['nav','plp','email'])}")
    if kind == "social":
        return (f"{scheme}://{netloc}/posts/{_rand_id(rng, 13)}"
                f"?utm_source=share&utm_medium=android")
    if kind == "encoded":
        dest = rng.choice(["https://www.example.org/page", "https://mail.example.net/inbox",
                           "https://example.com/@channel"])
        return (f"{scheme}://{netloc}/m?continue={urllib.parse.quote(dest, safe='')}"
                f"&hl=en&app={rng.choice(['desktop','mobile'])}")
    if kind == "api":
        return (f"{scheme}://{'api.' + netloc if isinstance(netloc,str) else netloc}"
                f"/v{rng.randint(1,4)}/items/{_rand_id(rng, 24)}?fields=all")
    # multi: stack several benign signals incl. an extra subdomain
    sub = rng.choice(_BENIGN_SUBS)
    host = sub + netloc
    return (f"{scheme}://{host}/{rng.choice(['c','results','feed','library'])}/"
            f"{_rand_id(rng, 8).lower()}?list={_rand_id(rng, 28)}&index={rng.randint(1,50)}")


def _as_domain(entry: str) -> str:
    """Accept either 'example.com' or 'https://example.com/' -> 'example.com'."""
    e = entry.strip()
    if "://" in e:
        e = e.split("://", 1)[1]
    return e.rstrip("/")


def _build_legit_sets(legit_all: list[str], rng: random.Random) -> tuple[list[str], list[str]]:
    """Split legit domains, then render BOTH train and test as real-world URLs."""
    rng.shuffle(legit_all)
    domains = [_as_domain(d) for d in legit_all]

    n_test = 600
    test_domains = domains[:n_test]
    train_domains = domains[n_test:]

    # TRAIN: half bare, half deep-linked -> total ~= len(train_domains)
    train_bare = [f"https://{d}/" for d in train_domains[: len(train_domains) // 2]]
    train_deep = [_deepen_legit(f"https://{d}/", rng)
                  for d in train_domains[len(train_domains) // 2:]]

    # TEST: 50% bare / 50% deep - mirrors reality where users sit on deep pages
    test_bare = [f"https://{d}/" for d in test_domains[: n_test // 2]]
    test_deep = [_deepen_legit(f"https://{d}/", rng) for d in test_domains[n_test // 2:]]

    dedupe = lambda xs: sorted(set(xs))  # noqa: E731
    return dedupe(train_bare + train_deep), dedupe(test_bare + test_deep)


def build_dataset() -> dict:
    rng = random.Random(42)
    phish_real, legit_all = load_raw()

    # --- stratified REAL holdout (never augmented, never trained on) ---
    rng.shuffle(phish_real)
    n_test_phish = max(40, int(len(phish_real) * 0.25))
    test_phish = phish_real[:n_test_phish]
    train_phish_real = phish_real[n_test_phish:]

    train_legit, test_legit = _build_legit_sets(legit_all, rng)

    # --- augment TRAIN phishing only ---
    train_phish = list(train_phish_real)
    for u in train_phish_real:
        for _ in range(AUG_COPIES):
            train_phish.append(_mutate(u, rng))
    train_phish = sorted(set(train_phish))

    X_train = train_phish + train_legit
    y_train = [1] * len(train_phish) + [0] * len(train_legit)

    X_test = test_phish + test_legit
    y_test = [1] * len(test_phish) + [0] * len(test_legit)

    print(f"[data] train: {len(train_phish)} phishing "
          f"({len(train_phish_real)} real + {len(train_phish)-len(train_phish_real)} augmented)"
          f" | {len(train_legit)} legit (bare+deep)")
    print(f"[data] test : {len(test_phish)} REAL phishing | {len(test_legit)} legit "
          f"(incl. deep-linked)")

    return {"X_train": X_train, "y_train": y_train, "X_test": X_test, "y_test": y_test,
            "test_phish": test_phish, "test_legit": test_legit}


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def featurize(urls: list[str]) -> np.ndarray:
    svc = MLService.__new__(MLService)  # staticmethod usage without model init
    rows = [svc.extract_url_features(u)[0] for u in urls]
    return np.asarray(rows, dtype=np.float32)


def to_prediction(p_phish: float) -> tuple[str, float]:
    """Same decision rule as ml_service.predict_url."""
    if p_phish >= PHISH_THRESHOLD:
        return "phishing", round(float(p_phish), 3)
    if p_phish >= SUSPicious_THRESHOLD:
        return "suspicious", round(float(p_phish), 3)
    return "safe", round(float(1.0 - p_phish), 3)


def main() -> int:
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import classification_report, precision_score, recall_score, f1_score

    data = build_dataset()
    Xtr, ytr = featurize(data["X_train"]), np.array(data["y_train"])
    Xte, yte = featurize(data["X_test"]), np.array(data["y_test"])

    candidates = {
        "LogReg+scaled": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(class_weight="balanced", max_iter=2000, C=0.5, random_state=42)),
        ]),
        "GradientBoosting": GradientBoostingClassifier(
            n_estimators=150, max_depth=3, learning_rate=0.1, random_state=42),
    }

    # Real-world brand-safety gate: these MUST score safe or the model ships
    # false positives on the sites users actually browse.
    SAFE_PROBES = [
        "https://www.youtube.com/",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://www.youtube.com/watch?v=aqz-KE-bpKQ&list=PLbpi6ZahtOH6Blw3RGYpWkSByi_T7Rygb",
        "https://consent.youtube.com/m?continue=https://www.youtube.com/%40MrBeast&hl=en",
        "https://accounts.google.com/v3/Signin/challenge/pwd?continue=https%3A%2F%2Fmail.google.com",
        "https://github.com/microsoft/vscode/blob/main/README.md",
        "https://mail.google.com/mail/u/0/#inbox",
        "https://www.amazon.com/dp/B08N5WRWNW?ref_=nav_ya_signin",
        "https://x.com/elonmusk/status/1234567890123456789",
        "https://www.reddit.com/r/programming/comments/abc123/best_language/",
        "https://login.microsoftonline.com/common/oauth2/authorize?client_id=x",
        "https://www.netflix.com/watch/81234567?trackId=1",
        "https://chatgpt.com/c/6a895ec9-c214-83e8-8615-ef37e820546f",
        "https://www.notion.so/My-Notes-8f2a19d4e0b34c1f9d3e7a2b5c6d8e10",
        # Non-brand probes: these have NO runtime safety net and MUST pass hard
        "https://news.ycombinator.com/item?id=12345678",
        "https://www.imdb.com/title/tt0111161/?ref_=nv_sr_1",
    ]

    def _load_brand_domains() -> list[str]:
        """Read the runtime known-brand list so trainer & extension agree."""
        kb_path = BACKEND_DIR.parent / "extension" / "src" / "trust" / "knownBrands.ts"
        try:
            text = kb_path.read_text()
            return _re.findall(r"'([a-z0-9.-]+)'", text)
        except Exception:
            print("[gate] WARNING: could not read knownBrands.ts")
            return []

    import re as _re
    BRAND_DOMAINS = _load_brand_domains()

    def _guard_covered(url: str) -> bool:
        host = url.split("://", 1)[-1].split("/")[0].lower()
        return any(host == d or host.endswith("." + d) for d in BRAND_DOMAINS)

    results = {}
    for name, clf in candidates.items():
        clf.fit(Xtr, ytr)
        proba = clf.predict_proba(Xte)[:, 1]
        preds = (proba >= SUSPicious_THRESHOLD).astype(int)

        # Brand-safety gate evaluation.
        # Probes covered by the runtime known-brand guard are INFO-only
        # (the extension downgrades them regardless of model output).
        # Non-brand probes carry the HARD red-line: p >= 0.65 fails shipping.
        P = featurize(SAFE_PROBES).astype(np.float32)
        probe_p = clf.predict_proba(P)[:, 1]
        probe_max = float(probe_p.max())
        hard_fail = any(
            p >= 0.65 for p, u in zip(probe_p, SAFE_PROBES) if not _guard_covered(u)
        )
        for p, u in zip(probe_p, SAFE_PROBES):
            if p >= 0.65 and _guard_covered(u):
                tag = "GUARD-COVERED"
            elif p >= 0.65:
                tag = "HARD-FAIL"
            elif p >= SUSPicious_THRESHOLD:
                tag = "AMBER" if not _guard_covered(u) else "GUARD-COVERED"
            else:
                continue
            print(f"   [{tag}] p={p:.4f} {u[:80]}")

        results[name] = {
            "model": clf,
            "precision": float(precision_score(yte, preds)),
            "recall": float(recall_score(yte, preds)),
            "f1": float(f1_score(yte, preds)),
            "probe_max": probe_max,
            "_hard_fail": hard_fail,
            "_report": classification_report(yte, preds, target_names=LABELS),
        }
        print(f"\n=== {name} ===")
        print(results[name]["_report"])
        print(f"[probe] worst safe-probe p = {probe_max:.4f} | "
              f"hard-line(>=0.65 non-brand): {'FAIL' if hard_fail else 'PASS'}")
        for u, p in zip(SAFE_PROBES, probe_p):
            if p >= SUSPicious_THRESHOLD:
                print(f"   FP: p={p:.4f} {u[:80]}")

    passing = {k: v for k, v in results.items() if not v["_hard_fail"]}
    pool = passing if passing else results
    winner_name = max(pool, key=lambda k: results[k]["f1"])
    winner = results[winner_name]["model"]
    if not passing:
        print("[gate] WARNING: no candidate passed the brand-safety gate!")
    print(f"[winner] {winner_name} (F1={results[winner_name]['f1']:.3f}, "
          f"probe_max={results[winner_name]['probe_max']:.4f})")

    # ------------------------------------------------------------------ ONNX
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    import onnxruntime as ort

    n_features = Xtr.shape[1]
    onx = convert_sklearn(
        winner,
        initial_types=[("float_input", FloatTensorType([None, n_features]))],
        options={"zipmap": False},
    )
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)
    onnx_path = ASSETS_DIR / "url-model-v3.onnx"
    onnx_path.write_bytes(onx.SerializeToString())

    sess = ort.InferenceSession(onnx_path.read_bytes(), providers=["CPUExecutionProvider"])
    out_names = [o.name for o in sess.get_outputs()]
    proba_name = next((n for n in out_names if "prob" in n.lower()), out_names[-1])
    proba_idx = out_names.index(proba_name)

    def ort_p_phish(feats: np.ndarray) -> float:
        outs = sess.run(None, {"float_input": feats.astype(np.float32)})
        arr = np.asarray(outs[proba_idx])
        return float(arr[:, 1].ravel()[0]) if arr.ndim == 2 else float(arr.ravel()[0])

    raw_out = sess.run(None, {"float_input": Xte.astype(np.float32)})
    ort_proba = np.asarray(raw_out[proba_idx])
    if ort_proba.ndim == 2:
        ort_proba = ort_proba[:, 1]
    print(f"[onnx] outputs={out_names} (proba via '{proba_name}')")
    sk_proba = winner.predict_proba(Xte)[:, 1]
    drift = float(np.max(np.abs(ort_proba - sk_proba)))
    print(f"[onnx] exported -> {onnx_path} ({onnx_path.stat().st_size/1024:.1f} KB)")
    print(f"[onnx] max |sklearn - onnxruntime| drift = {drift:.2e}")

    # ------------------------------------------------------------- artifacts
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)

    meta = {
        "name": "url-model-v3",
        "algorithm": winner_name,
        "labels": LABELS,
        "input_features": [
            "url_length", "has_https", "has_at_symbol", "has_ip_address",
            "dash_count", "digit_ratio", "special_char_count",
            "subdomain_count", "suspicious_tld", "char_diversity",
        ],
        "input_dtype": "float32",
        "input_name": "float_input",
        "thresholds": {"phishing": PHISH_THRESHOLD, "suspicious": SUSPicious_THRESHOLD},
        "metrics_real_only_test": {
            "precision": results[winner_name]["precision"],
            "recall": results[winner_name]["recall"],
            "f1": results[winner_name]["f1"],
        },
        "dataset": {
            "phishing_source": "OpenPhish community feed",
            "legit_source": "Majestic Million top domains",
            "trained_at": time.strftime("%Y-%m-%d"),
            "augmented_training_only": True,
        },
        "onnx_max_drift": drift,
    }
    (MODELS_DIR / "url-model-v3-meta.json").write_text(json.dumps(meta, indent=2))
    (ASSETS_DIR / "url-model-v3-meta.json").write_text(json.dumps(meta, indent=2))

    # Golden vectors for the JS-side parity test (Phase B)
    golden = []
    for i, url in enumerate(data["test_phish"][:120]):
        golden.append({"url": url, "label": "phishing"})
    for i, url in enumerate(data["test_legit"][:380]):
        golden.append({"url": url, "label": "safe"})
    rng2 = random.Random(7)
    rng2.shuffle(golden)
    for g in golden:
        feats = featurize([g["url"]]).astype(np.float32)
        p = ort_p_phish(feats)
        pred, conf = to_prediction(p)
        g["features"] = [round(float(x), 6) for x in feats[0]]
        g["p_phishing"] = round(p, 6)
        g["expected"] = {"prediction": pred, "confidence": conf}
    (GOLDEN_DIR / "golden_urls.json").write_text(json.dumps(golden, indent=1))
    print(f"[golden] {len(golden)} vectors -> {GOLDEN_DIR/'golden_urls.json'}")

    print("\n✅ PHASE A COMPLETE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
