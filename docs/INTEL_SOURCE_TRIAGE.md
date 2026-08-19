# External CTI source triage (Wire)

Only clearnet secondary / public APIs with metadata-only storage.
No forum login, no malware samples, no dump bodies, no onion crawl into Wire.

| Source | Decision | Wire path |
|--------|----------|-----------|
| Claim/dark-web news RSS | **Primary** | DataBreaches, Dark Web Informer, The Record, HackRead, … |
| [ransomware.live](https://www.ransomware.live/) | **Primary** | Public API victims |
| X CTI accounts | **Primary** | Curated handles (`X_WIRE_ACCOUNTS`) → Wire via cookie GraphQL |
| Zone-H / haxor defacement | Use | Separate defacement ingest |
| deepdarkCTI / darc / DarkFox | **Removed from Wire** | Catalog/crawler tooling — not claim evidence |
| VECERT / vx-underground / AIL | Skip | No safe public evidence path |

## Tor fetch

Clearnet HTTPS feeds try **direct first**, then **Tor** on 403/429/timeout (or prefer Tor when `requires_tor=true`). HTML/login walls are not accepted as RSS. Dead aggregators (`breach.news`, `data.breach.news`) removed from catalog.
