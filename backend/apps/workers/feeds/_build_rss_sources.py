"""Rebuild rss_sources.json from Watcher's full sources.csv + BreachSentinel extras."""

from __future__ import annotations

import csv
import json
import re
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

WATCHER_CSV = (
    "https://raw.githubusercontent.com/thalesgroup-cert/Watcher/master/"
    "Watcher/Watcher/threats_watcher/datas/sources.csv"
)

items: list[dict] = []
seen: set[str] = set()


def add(url: str, name: str, country: str = "", code: str = "", confidence: int = 2, category: str = "news"):
    u = (url or "").strip()
    if not u or u.lower() in seen:
        return
    seen.add(u.lower())
    items.append(
        {
            "name": name[:64],
            "url": u,
            "country": country or "",
            "country_code": code or "",
            "confidence": int(confidence),
            "category": category,
            "notes": "watcher" if category == "news" else "",
        }
    )


extras = [
    ("https://www.cert.ssi.gouv.fr/feed/", "cert-fr", "France", "FR", 1, "cert"),
    ("https://www.cisa.gov/cybersecurity-advisories/all.xml", "cisa-advisories", "United States", "US", 1, "cert"),
    ("https://www.cyber.gov.au/rss/news", "acsc-news", "Australia", "AU", 1, "cert"),
    ("https://cert.pl/en/rss.xml", "cert-pl", "Poland", "PL", 1, "cert"),
    ("https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml", "ncsc-uk", "United Kingdom", "GB", 1, "cert"),
    ("https://www.databreaches.net/feed/", "databreaches-net", "United States", "US", 2, "breach"),
    ("https://www.bleepingcomputer.com/feed/", "bleepingcomputer", "United States", "US", 2, "news"),
    ("https://feeds.feedburner.com/TheHackersNews", "thehackernews", "United States", "US", 2, "news"),
    ("https://securelist.com/feed/", "securelist", "Global", "ZZ", 2, "news"),
    ("https://blog.malwarebytes.com/feed/", "malwarebytes", "United States", "US", 2, "news"),
    ("https://unit42.paloaltonetworks.com/feed/", "unit42", "United States", "US", 1, "news"),
    ("https://www.crowdstrike.com/blog/feed/", "crowdstrike", "United States", "US", 1, "news"),
    ("https://www.schneier.com/blog/atom.xml", "schneier", "United States", "US", 2, "news"),
    ("https://www.recordedfuture.com/feed", "recordedfuture", "United States", "US", 1, "news"),
    ("https://www.ransomware.live/rss.xml", "ransomware-live-rss", "Global", "ZZ", 2, "ransomware"),
    (
        "https://undercodenews.com/feed/",
        "undercodenews",
        "Global",
        "ZZ",
        2,
        "news",
    ),
]
for row in extras:
    add(*row)

csv_path = Path("/tmp/watcher_sources.csv")
urllib.request.urlretrieve(WATCHER_CSV, csv_path)

# Import full Watcher catalog (all confidence levels 1–5). Opsec: analysts can disable noisy ones.
with csv_path.open(encoding="utf-8") as f:
    reader = csv.DictReader(f, delimiter=";")
    for row in reader:
        conf = int(row.get("confident") or 5)
        conf = max(1, min(5, conf))
        url = (row.get("url") or "").strip()
        if not url:
            continue
        host = urlparse(url).hostname or "source"
        name = re.sub(r"[^a-z0-9-]+", "-", host.lower()).strip("-")[:48]
        add(url, name, row.get("country", ""), row.get("country_code", ""), conf, "news")

out = Path("/app/apps/workers/feeds/rss_sources.json")
out.write_text(json.dumps(items, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"wrote {len(items)} sources -> {out}")
from collections import Counter

print("by_confidence", dict(sorted(Counter(i["confidence"] for i in items).items())))
