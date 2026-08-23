"""
PhishGuard AI - Dataset Fetcher (Phase A)

Downloads training data for the standalone ONNX model:
  - Phishing: OpenPhish community feed (live, rotating)
  - Legit:    Majestic Million top domains (sampled)

Caches raw downloads under backend/data/raw/ so re-runs skip the network.
"""

import csv
import io
import random
import sys
import urllib.request
from pathlib import Path

RAW_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"

OPENPHISH_URL = "https://openphish.com/feed.txt"
MAJESTIC_URL = "https://downloads.majestic.com/majestic_million.csv"

LEGIT_SAMPLE_SIZE = 4000  # draw legit domains from the top of Majestic


def _fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "PhishGuardAI-Trainer/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def _cache_fetch(url: str, cache_name: str, max_age_days: int = 7) -> Path:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = RAW_DIR / cache_name
    if cache_path.exists():
        age_s = time.time() - cache_path.stat().st_mtime
        if age_s < max_age_days * 86400:
            print(f"[cache] {cache_name} ({age_s/3600:.1f}h old)")
            return cache_path
    print(f"[download] {url}")
    data = _fetch(url)
    cache_path.write_bytes(data)
    return cache_path


import time  # noqa: E402  (used by _cache_fetch)


def fetch_phishing() -> list[str]:
    path = _cache_fetch(OPENPHISH_URL, "openphish.txt", max_age_days=3)
    urls = [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip().startswith(("http://", "https://"))
    ]
    return sorted(set(urls))


def fetch_legit(sample_size: int = LEGIT_SAMPLE_SIZE) -> list[str]:
    path = _cache_fetch(MAJESTIC_URL, "majestic_million.csv", max_age_days=30)
    text = path.read_text(encoding="utf-8", errors="ignore")
    reader = csv.DictReader(io.StringIO(text))
    domains = []
    for row in reader:
        d = (row.get("Domain") or "").strip().lower()
        if d and "." in d:
            domains.append(d)
        if len(domains) >= max(sample_size * 3, 12000):  # buffer for filtering
            break
    return domains[:sample_size]


def main() -> int:
    random.seed(42)

    phishing_urls = fetch_phishing()
    legit_domains_raw = fetch_legit()

    # Domains seen in the phishing feed must never appear as legit samples
    phish_domains = {u.split("/")[2].lower() for u in phishing_urls if "://" in u}
    legit_urls = []
    for d in legit_domains_raw:
        if d not in phish_domains:
            legit_urls.append(f"https://{d}/")

    out_dir = RAW_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "phishing_urls.txt").write_text("\n".join(phishing_urls), encoding="utf-8")
    (out_dir / "legit_urls.txt").write_text("\n".join(legit_urls), encoding="utf-8")

    overlap_removed = len(legit_domains_raw) - len(legit_urls)
    print(f"\n✓ phishing : {len(phishing_urls)} unique URLs  -> {out_dir/'phishing_urls.txt'}")
    print(f"✓ legit    : {len(legit_urls)} URLs "
          f"({overlap_removed} overlapping domains removed) -> {out_dir/'legit_urls.txt'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
