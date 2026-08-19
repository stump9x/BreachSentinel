"""CREDENTIALS.md — what to put in .env for open-web channels (do not commit secrets).

## X / Twitter cookie search (recommended secondary account)

1. Create or use a **throwaway** X account (not your main).
2. Log in at https://x.com in Chrome/Edge.
3. Install **Cookie-Editor** extension.
4. Open Cookie-Editor on x.com → find:
   - `auth_token`  → value goes to `X_AUTH_TOKEN=`
   - `ct0`         → value goes to `X_CT0=`
5. Add to local `.env` (never git-commit):

```env
X_TWITTER_ENABLED=true
X_AUTH_TOKEN=paste_auth_token_here
X_CT0=paste_ct0_here
```

6. Recreate containers (restart alone may not reload `.env`):

```bat
docker compose up -d --force-recreate backend celery
```

7. OSINT → channel `X / Twitter cookie search` should be **ok**.

---

## Reddit — full cookie + search (secondary account)

Cloud/server IPs often get blocked without login. For **search** you need a **full Cookie header**, not only one field.

### Export (recommended)

1. Create / use a **throwaway** Reddit account.
2. Log in at https://www.reddit.com in Chrome/Edge.
3. Open **Cookie-Editor** while on reddit.com.
4. Click **Export** → choose **Header String** (or “Copy as Header”).
5. You get one long line like:

```text
reddit_session=eyJ...; token_v2=...; csv=2; edgebucket=...; loid=...; session_tracker=...; ...
```

6. Put the **entire line** into `.env` (one line, no quotes unless needed):

```env
REDDIT_SEARCH_ENABLED=true
REDDIT_ENRICH_ENABLED=true
REDDIT_COOKIE=reddit_session=eyJ...; token_v2=...; csv=2; edgebucket=...; loid=...
```

### Minimum cookies

Must include at least **`reddit_session`**. Better to export the **full** header so `token_v2` / `loid` / etc. come along.

### Apply

```bat
docker compose up -d --force-recreate backend celery
```

OSINT doctor should show:

- **Reddit cookie search** → **ok**
- **Reddit post/comment enrich** → **ok**

### How to use

- Keyword search (e.g. `ClickFix`) on OSINT → results with `engine=reddit_search` mixed in.
- Paste a Reddit **post URL** into the search box (with cookie set) → one hit for that URL; tick Persist → enrich reads the body.
- Watch Rule target `searx`/`leaks` + **Open-web sweep** also calls Reddit search.

If search returns empty and logs show 401/403/429 → export cookies again (session expired).

---

## Exa (optional)

1. Sign up at https://exa.ai and create an API key.
2. Set `EXA_API_KEY=...` in `.env`, force-recreate backend/celery.

## Searx engines (open-web)

Default (no GitHub — use GitHub Scanner):

```env
SEARXNG_ENGINES=duckduckgo,brave,bing,gitlab,bitbucket,npm,stackoverflow,qwant,ahmia
```

- **bing / brave / duckduckgo / qwant** — broad clearnet coverage  
- **gitlab / bitbucket / npm / stackoverflow** — code & Q&A (not GitHub)  
- **ahmia** — onion *index* via ahmia.fi (mentions of .onion); not full darkweb crawl  

After changing engines: recreate `searxng` + `backend` + `celery`.

---

## Recency (newest first)

Open-web merge ranks hits by `published` (newest on top). Bias sources with:

```env
SEARX_TIME_RANGE=month
REDDIT_SEARCH_SORT=new
REDDIT_SEARCH_TIME=month
EXA_RECENCY_DAYS=30
```

Use `week` / `day` for tighter windows; set `SEARX_TIME_RANGE=` empty to disable Searx time filter.

---

## Exa semantic search (recommended)

Exa is wired into OSINT + Watch Rule leak sweeps as a **credit-frugal fallback**.
Prefer Searx / X / Reddit first; Exa runs only when those keep fewer than
`EXA_OSINT_MIN_HITS` / `EXA_LEAK_MIN_HITS` hits (or OSINT sends `use_exa=true`).

It uses **natural-language** queries (not Searx dorks), **highlights**, and recency filters.

1. Create a key at https://dashboard.exa.ai  
2. Put it in `.env` (never commit):

```env
EXA_API_KEY=your_exa_key_here
EXA_SEARCH_TYPE=auto
EXA_QUERY_COUNT=1
EXA_OSINT_MODE=fallback
EXA_OSINT_MIN_HITS=5
EXA_LEAK_MODE=fallback
EXA_LEAK_MIN_HITS=5
EXA_HIGHLIGHTS=true
EXA_INCLUDE_TEXT=false
EXA_RECENCY_DAYS=90
```

Keep `EXA_SEARCH_TYPE=auto` — **`deep` burns credits heavily**. Set
`EXA_OSINT_MODE=off` / `EXA_LEAK_MODE=off` to disable Exa for those paths, or
`always` to restore pre-gating behavior.

Aligned with Exa coding-agent recipe: `type=auto` + highlights
(raw `results[]` — no `outputSchema` / deep synthesis for Wire/OSINT).

**Profiles (auto-selected):**
- **leak** (OSINT / Watch Rules): NL queries, `highlights.query=keyword`, `includeText`, local phrase filter, no `category`
- **wire**: `category=news`, `highlights=true`, 14-day window
- **site**: curated domains via `includeDomains`

3. Recreate backend/celery so `.env` reloads:

```bat
docker compose up -d --force-recreate backend celery
```

4. OSINT channel chip **Exa** should show **on**. Search a brand (e.g. `Go2Joy`) —
   Exa runs when other channels are thin (or pass `use_exa=true`).

### Exa → The Wire

When `EXA_WIRE_ENABLED=true` and `EXA_API_KEY` is set, Celery beat runs
`integrations.discover_exa_wire` every **60 minutes** (defaults:
`EXA_WIRE_LIMIT=8`, `EXA_WIRE_QUERY_COUNT=2`, `EXA_WIRE_LIMIT_PER_DOMAIN=2`):

- NL CTI queries (ransomware / breaches / Vietnam / credential leaks)
- Curated no-RSS domains (same list as Searx site discovery) via `includeDomains`

Hits with a **published date** pass Wire relevance/age filters and become Threats
(`raw_payload.discovery` = `exa-wire` or `exa-site`). Undated results are skipped
(same rule as Searx Wire discovery).

Set `EXA_WIRE_ENABLED=false` to pause Wire Exa entirely.
"""
