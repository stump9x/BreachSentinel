"""
BreachSentinel Django settings.

All secrets and host-specific values come from environment variables.
See repository root `.env.example`.
"""

from pathlib import Path

import environ
from celery.schedules import crontab

BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env from repo root (../.env) or backend/.env when running locally
env = environ.Env(
    DJANGO_DEBUG=(bool, False),
    DJANGO_ALLOWED_HOSTS=(list, ["localhost", "127.0.0.1"]),
    MISP_VERIFY_SSL=(bool, True),
)

environ.Env.read_env(BASE_DIR.parent / ".env")
environ.Env.read_env(BASE_DIR / ".env")

SECRET_KEY = env("DJANGO_SECRET_KEY", default="insecure-dev-only-change-me")
DEBUG = env("DJANGO_DEBUG")
ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1", "backend"])

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third-party
    "rest_framework",
    "rest_framework.authtoken",
    "django_filters",
    "drf_spectacular",
    "corsheaders",
    # Local
    "apps.core.apps.CoreConfig",
    "apps.intel.apps.IntelConfig",
    "apps.workers.apps.WorkersConfig",
    "apps.integrations.apps.IntegrationsConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env("POSTGRES_DB", default="breachsentinel"),
        "USER": env("POSTGRES_USER", default="breachsentinel"),
        "PASSWORD": env("POSTGRES_PASSWORD", default="change-me-db-password"),
        "HOST": env("POSTGRES_HOST", default="localhost"),
        "PORT": env("POSTGRES_PORT", default="5432"),
        # Reuse DB connections under Gunicorn on the VPS. Keep local/tests at
        # Django's default (0) unless explicitly configured.
        "CONN_MAX_AGE": env.int("DJANGO_DB_CONN_MAX_AGE", default=0),
        "CONN_HEALTH_CHECKS": True,
    }
}

# Optional local/dev fallback when Postgres is unavailable
if env.bool("USE_SQLITE", default=False):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- CORS / CSRF ---
CORS_ALLOWED_ORIGINS = env.list(
    "DJANGO_CORS_ALLOWED_ORIGINS",
    default=["http://localhost:3000"],
)
CSRF_TRUSTED_ORIGINS = env.list(
    "DJANGO_CSRF_TRUSTED_ORIGINS",
    default=["http://localhost:3000", "http://localhost:8000"],
)

# --- DRF ---
# SPA uses short-lived DRF Token (Authorization: Token <key>).
# BasicAuthentication removed — password never stored in sessionStorage.
REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "apps.core.authentication.ExpiringTokenAuthentication",
    ],
    "DEFAULT_FILTER_BACKENDS": [
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ],
    "DEFAULT_PAGINATION_CLASS": "apps.core.pagination.FlexiblePagination",
    "PAGE_SIZE": 25,
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
        "rest_framework.throttling.ScopedRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "60/min",
        "user": "300/min",
        "auth": "20/min",
        "github_scan_create": "5/hour",
        "log_scan_create": "30/hour",
    },
}

# Large credential dumps for Logs Scanner (staff-only multipart uploads).
DATA_UPLOAD_MAX_MEMORY_SIZE = env.int(
    "DATA_UPLOAD_MAX_MEMORY_SIZE", default=1600 * 1024 * 1024
)
FILE_UPLOAD_MAX_MEMORY_SIZE = env.int(
    "FILE_UPLOAD_MAX_MEMORY_SIZE", default=8 * 1024 * 1024
)
LOG_SCAN_STORAGE_DIR = env("LOG_SCAN_STORAGE_DIR", default="")
LOG_SCAN_MAX_UPLOAD_BYTES = env.int(
    "LOG_SCAN_MAX_UPLOAD_BYTES", default=1536 * 1024 * 1024
)
LOG_SCAN_UPLOAD_CHUNK_BYTES = env.int(
    "LOG_SCAN_UPLOAD_CHUNK_BYTES", default=16 * 1024 * 1024
)
LOG_SCAN_MAX_HITS = env.int("LOG_SCAN_MAX_HITS", default=5000)
LOG_SCAN_MAX_FILES_PER_SCAN = env.int("LOG_SCAN_MAX_FILES_PER_SCAN", default=25)

SPECTACULAR_SETTINGS = {
    "TITLE": "BreachSentinel API",
    "DESCRIPTION": "Threat Intelligence & Data Leak Monitoring Platform",
    "VERSION": "0.7.0",
}

# --- Auth / secrets ---
AUTH_TOKEN_TTL_HOURS = env.int("AUTH_TOKEN_TTL_HOURS", default=12)
CREDENTIAL_PEPPER = env("CREDENTIAL_PEPPER", default="")
FIELD_ENCRYPTION_KEY = env("FIELD_ENCRYPTION_KEY", default="")  # Fernet key (url-safe base64)

# --- Celery / Redis ---
REDIS_PASSWORD = env("REDIS_PASSWORD", default="")
# Prefer explicit CELERY_* from env; compose injects password-aware URLs.
CELERY_BROKER_URL = env("CELERY_BROKER_URL", default="redis://localhost:6379/0")
CELERY_RESULT_BACKEND = env("CELERY_RESULT_BACKEND", default="redis://localhost:6379/1")
REDIS_URL = env("REDIS_URL", default=CELERY_BROKER_URL)
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = TIME_ZONE
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 60 * 15
CELERY_TASK_SOFT_TIME_LIMIT = 60 * 10
# Prefer fair scheduling so long RSS sweeps do not starve translate/Searx tasks.
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
# Drop Celery result keys automatically (Redis DB 1) — safe memory hygiene.
CELERY_RESULT_EXPIRES = env.int("CELERY_RESULT_EXPIRES", default=3600)
# Auto-purge Wire rows past retention windows (safe; never --from-today).
WIRE_HOUSEKEEPING_ENABLED = env.bool("WIRE_HOUSEKEEPING_ENABLED", default=True)

CELERY_BEAT_SCHEDULE = {
    "ingest-cve-feed-hourly": {
        "task": "workers.ingest_cve_feed",
        "schedule": crontab(minute=15),
        "kwargs": {"limit": 40},
    },
    "ingest-ransomware-feed-every-30m": {
        "task": "workers.ingest_ransomware_feed",
        "schedule": 1800.0,
        "kwargs": {"limit": 50},
    },
    "ai-daily-briefing": {
        "task": "integrations.generate_daily_briefing",
        "schedule": crontab(hour=6, minute=0),
        "kwargs": {"window_hours": 24},
    },
    "ai-weekly-digest": {
        "task": "integrations.generate_weekly_digest",
        "schedule": crontab(hour=7, minute=0, day_of_week="mon"),
    },
    # Full-catalog sweep + single-flight lock (skip if previous still running).
    "ingest-rss-feeds-every-6m": {
        "task": "workers.ingest_cert_rss",
        "schedule": 360.0,
        # Scan enough entries per feed; ingest applies age windows (7d / VN 30d).
        "kwargs": {"limit_per_feed": 40},
    },
    "searx-leak-sweep-every-10m": {
        "task": "integrations.scan_searx_leaks",
        "schedule": 600.0,
        "kwargs": {"limit_per_keyword": 15},
    },
    "searx-unstable-intel-sites-every-30m": {
        "task": "integrations.discover_unstable_intel_sites",
        "schedule": 1800.0,
        "kwargs": {"limit_per_domain": 5},
    },
    "exa-wire-discovery-every-60m": {
        "task": "integrations.discover_exa_wire",
        "schedule": 3600.0,
        "kwargs": {"limit": 8, "limit_per_domain": 2},
    },
    "x-wire-discovery-every-15m": {
        "task": "integrations.discover_x_wire",
        "schedule": 900.0,
        "kwargs": {"limit_per_account": 8},
    },
    "zoneh-defacement-archive-every-15m": {
        "task": "workers.ingest_zoneh_archive",
        "schedule": 900.0,
        "kwargs": {"pages": 2},
    },
    "forum-claims-every-30m": {
        "task": "workers.ingest_forum_claims",
        "schedule": 1800.0,
        "kwargs": {"limit_per_feed": 25},
    },
    # Drain pending Vietnamese titles then summaries; one lock avoids provider pile-ups.
    "translate-wire-titles-every-60s": {
        "task": "integrations.translate_threat_titles",
        "schedule": 60.0,
        "kwargs": {"limit": 25},
    },
    # Safe retention: delete Wire items past 7d / VN 30d + generic tags (daily 03:40).
    "wire-housekeeping-daily": {
        "task": "workers.wire_housekeeping",
        "schedule": crontab(hour=3, minute=40),
        "kwargs": {"reset_feed_cache": False},
    },
}


# --- External integrations (Phase 6) ---
OSINT_SERVICE_URL = env("OSINT_SERVICE_URL", default="http://localhost:8080")
ANTHROPIC_API_KEY = env("ANTHROPIC_API_KEY", default="")
ANTHROPIC_MODEL = env("ANTHROPIC_MODEL", default="claude-3-haiku-20240307")
GROQ_API_KEY = env("GROQ_API_KEY", default="")
# Extra keys (comma / newline / semicolon) — exclusive slice vs NewsCrawler on VPS.
GROQ_API_KEYS = env("GROQ_API_KEYS", default="")
GROQ_MODEL = env("GROQ_MODEL", default="llama-3.3-70b-versatile")
GROQ_TIMEOUT_SEC = env.float("GROQ_TIMEOUT_SEC", default=12)
# After a 429, rest that key long enough for free-tier RPM to recover.
GROQ_KEY_COOLDOWN_SEC = env.float("GROQ_KEY_COOLDOWN_SEC", default=120)
# Cap attempts — cascading through the whole pool caused mass 429 burns.
GROQ_MAX_KEY_ATTEMPTS = env.int("GROQ_MAX_KEY_ATTEMPTS", default=2)
GROQ_MIN_INTERVAL_SEC = env.float("GROQ_MIN_INTERVAL_SEC", default=1.25)
GROQ_STOP_ON_FIRST_429 = env.bool("GROQ_STOP_ON_FIRST_429", default=True)
GROQ_CIRCUIT_TTL_SEC = env.int("GROQ_CIRCUIT_TTL_SEC", default=180)
GROQ_FAIL_TRIP_THRESHOLD = env.int("GROQ_FAIL_TRIP_THRESHOLD", default=1)
# Isolate Groq cooldown / logs from NewsCrawler when both run on the same VPS.
GROQ_POOL_NAMESPACE = env("GROQ_POOL_NAMESPACE", default="breachsentinel")
HUGGINGFACE_API_TOKEN = env("HUGGINGFACE_API_TOKEN", default="")
HUGGINGFACE_NER_MODEL = env("HUGGINGFACE_NER_MODEL", default="dslim/bert-base-NER")
HUGGINGFACE_SUMMARIZE_MODEL = env(
    "HUGGINGFACE_SUMMARIZE_MODEL", default="google/flan-t5-base"
)
# Wire title VN translation: Groq (shared key pool) → Google → Ollama → MyMemory.
TITLE_TRANSLATE_ENABLED = env.bool("TITLE_TRANSLATE_ENABLED", default=True)
TITLE_TRANSLATE_GROQ = env.bool("TITLE_TRANSLATE_GROQ", default=True)
TITLE_TRANSLATE_PREFER_GROQ = env.bool("TITLE_TRANSLATE_PREFER_GROQ", default=True)
TITLE_TRANSLATE_AI_REFINE = env.bool("TITLE_TRANSLATE_AI_REFINE", default=False)
# When AI refine is on, only polish titles at/above this Wire priority (50=impact, 100=VN).
TITLE_TRANSLATE_AI_MIN_PRIORITY = env.int("TITLE_TRANSLATE_AI_MIN_PRIORITY", default=50)
# Keep network translation outside RSS ingest so one slow provider cannot stall all feeds.
# New threats enqueue a translation task immediately and still update Wire progressively.
TITLE_TRANSLATE_INLINE_GOOGLE = env.bool("TITLE_TRANSLATE_INLINE_GOOGLE", default=False)
GOOGLE_TRANSLATE_TIMEOUT_SEC = env.float("GOOGLE_TRANSLATE_TIMEOUT_SEC", default=20)
# auto = detect source language (EN/ZH/JA/… → VI). Override only for debugging.
GOOGLE_TRANSLATE_SOURCE_LANGUAGE = env(
    "GOOGLE_TRANSLATE_SOURCE_LANGUAGE", default="auto"
)
# After a Google 429/captcha, skip Google (direct) for this many seconds.
GOOGLE_TRANSLATE_CIRCUIT_SEC = env.float("GOOGLE_TRANSLATE_CIRCUIT_SEC", default=300)
# Min interval between Google calls (titles + summaries share this pace).
GOOGLE_TRANSLATE_PACING_SEC = env.float("GOOGLE_TRANSLATE_PACING_SEC", default=0.8)
GOOGLE_TRANSLATE_TOR_FALLBACK = env.bool("GOOGLE_TRANSLATE_TOR_FALLBACK", default=True)
# NewsCrawler pattern: prefer local Ollama for Chinese/Japanese/Korean titles.
TITLE_TRANSLATE_CJK_PREFER_OLLAMA = env.bool(
    "TITLE_TRANSLATE_CJK_PREFER_OLLAMA", default=True
)
# Non-English (FR/ES/RU/CJK…): compare Ollama vs Google and keep the better VI.
TITLE_TRANSLATE_NON_EN_OLLAMA_COMPARE = env.bool(
    "TITLE_TRANSLATE_NON_EN_OLLAMA_COMPARE", default=True
)
# Free HTTP fallback when Google is blocked/rate-limited and Ollama is unavailable.
TITLE_TRANSLATE_MYMEMORY_FALLBACK = env.bool(
    "TITLE_TRANSLATE_MYMEMORY_FALLBACK", default=True
)
TITLE_TRANSLATE_OLLAMA_FALLBACK = env.bool(
    "TITLE_TRANSLATE_OLLAMA_FALLBACK", default=True
)
OLLAMA_ENABLED = env.bool("OLLAMA_ENABLED", default=False)
# Shared NewsCrawler Ollama on VPS: http://ollama:11434 (alias of nc-ollama).
# Local host install: http://host.docker.internal:11434
OLLAMA_BASE_URL = env("OLLAMA_BASE_URL", default="http://host.docker.internal:11434")
OLLAMA_TRANSLATE_MODEL = env("OLLAMA_TRANSLATE_MODEL", default="qwen2.5:3b")
OLLAMA_TIMEOUT_SEC = env.float("OLLAMA_TIMEOUT_SEC", default=120)
OLLAMA_NUM_PREDICT = env.int("OLLAMA_NUM_PREDICT", default=128)
OLLAMA_NUM_CTX = env.int("OLLAMA_NUM_CTX", default=1024)
OLLAMA_KEEP_ALIVE = env("OLLAMA_KEEP_ALIVE", default="15m")
# Optional refine prompt; must include {title} and {draft}.
TITLE_TRANSLATE_REFINE_PROMPT = env("TITLE_TRANSLATE_REFINE_PROMPT", default="")
TITLE_TRANSLATE_FALLBACK_PROMPT = env(
    "TITLE_TRANSLATE_FALLBACK_PROMPT", default=""
)
TITLE_TRANSLATE_PROMPT = env("TITLE_TRANSLATE_PROMPT", default="")
# Wire summary VN translation: persisted/hash-cached, Google auto-detect first,
# bounded Ollama fallback only when Google fails.
SUMMARY_TRANSLATE_ENABLED = env.bool("SUMMARY_TRANSLATE_ENABLED", default=True)
SUMMARY_TRANSLATE_MAX_CHARS = env.int("SUMMARY_TRANSLATE_MAX_CHARS", default=1200)
SUMMARY_TRANSLATE_MAX_ATTEMPTS = env.int(
    "SUMMARY_TRANSLATE_MAX_ATTEMPTS", default=3
)
SUMMARY_TRANSLATE_OLLAMA_FALLBACK = env.bool(
    "SUMMARY_TRANSLATE_OLLAMA_FALLBACK", default=True
)
SUMMARY_TRANSLATE_OLLAMA_NUM_PREDICT = env.int(
    "SUMMARY_TRANSLATE_OLLAMA_NUM_PREDICT", default=360
)
SUMMARY_TRANSLATE_FALLBACK_PROMPT = env(
    "SUMMARY_TRANSLATE_FALLBACK_PROMPT", default=""
)
HUDSON_ROCK_API_KEY = env("HUDSON_ROCK_API_KEY", default="")
# Delete after N consecutive failures; only permanent 404/410/unsafe URLs delete immediately.
FEED_DELETE_AFTER_FAILURES = env.int("FEED_DELETE_AFTER_FAILURES", default=3)
FEED_MAX_REDIRECTS = env.int("FEED_MAX_REDIRECTS", default=5)
# The Wire: only ingest / surface non-Vietnam RSS items newer than this rolling window.
WIRE_MAX_AGE_DAYS = env.int("WIRE_MAX_AGE_DAYS", default=7)
# Vietnam-related Wire items: 0 = keep forever (no age cut for feed / ingest / purge).
WIRE_VIETNAM_MAX_AGE_DAYS = env.int("WIRE_VIETNAM_MAX_AGE_DAYS", default=0)
WIRE_VIETNAM_PRIORITY = env.int("WIRE_VIETNAM_PRIORITY", default=100)
WIRE_IMPACT_PRIORITY = env.int("WIRE_IMPACT_PRIORITY", default=50)
# Only Vietnam (and other high-priority) rows newer than this stay pinned at top.
# Non-VN items are already capped by WIRE_MAX_AGE_DAYS (7), so they keep full priority.
WIRE_VIETNAM_PIN_DAYS = env.int("WIRE_VIETNAM_PIN_DAYS", default=7)
# Back-compat: hours override if set explicitly; else derived from pin days.
WIRE_PRIORITY_PIN_HOURS = env.int(
    "WIRE_PRIORITY_PIN_HOURS",
    default=0,
) or (WIRE_VIETNAM_PIN_DAYS * 24)
WIRE_STALE_PRIORITY_CAP = env.int("WIRE_STALE_PRIORITY_CAP", default=15)
# Re-scan WordPress sitemap deltas hourly to recover regional posts omitted by
# short rolling RSS feeds. RSS cache is invalidated when parser policy changes.
WIRE_WORDPRESS_BACKFILL_INTERVAL_MINUTES = env.int(
    "WIRE_WORDPRESS_BACKFILL_INTERVAL_MINUTES", default=360
)
WIRE_WORDPRESS_SOURCES_PER_SWEEP = env.int(
    "WIRE_WORDPRESS_SOURCES_PER_SWEEP", default=3
)
RSS_PROCESSING_VERSION = env.int("RSS_PROCESSING_VERSION", default=5)
TOR_ENABLED = env.bool("TOR_ENABLED", default=False)
TOR_SOCKS_PROXY = env("TOR_SOCKS_PROXY", default="socks5h://tor:9150")
PROXYNOVA_API_KEY = env("PROXYNOVA_API_KEY", default="")
BREACHDIRECTORY_API_KEY = env("BREACHDIRECTORY_API_KEY", default="")
MISP_URL = env("MISP_URL", default="")
MISP_API_KEY = env("MISP_API_KEY", default="")
MISP_VERIFY_SSL = env("MISP_VERIFY_SSL")
THEHIVE_URL = env("THEHIVE_URL", default="")
THEHIVE_API_KEY = env("THEHIVE_API_KEY", default="")
SEARXNG_URL = env("SEARXNG_URL", default="")
SEARXNG_ENGINES = env(
    "SEARXNG_ENGINES",
    default="duckduckgo,brave,bing,gitlab,bitbucket,npm,stackoverflow,qwant,ahmia",
)
# Open-web leak enrichment (Jina Reader) — does not affect Wire / GitHub Scanner.
WEB_READER_ENABLED = env.bool("WEB_READER_ENABLED", default=True)
WEB_READER_BACKEND = env("WEB_READER_BACKEND", default="jina")
WEB_READER_MAX_BYTES = env.int("WEB_READER_MAX_BYTES", default=200000)
WEB_READER_TIMEOUT = env.float("WEB_READER_TIMEOUT", default=20.0)
SEARX_LEAK_ENRICH = env.bool("SEARX_LEAK_ENRICH", default=True)
SEARX_LEAK_ENRICH_SYNC = env.bool("SEARX_LEAK_ENRICH_SYNC", default=False)
SEARX_LEAK_ENRICH_BUDGET = env.int("SEARX_LEAK_ENRICH_BUDGET", default=16)
SEARX_QUERY_PACKS = env.bool("SEARX_QUERY_PACKS", default=True)
SEARX_QUERY_PACK_SIZE = env.int("SEARX_QUERY_PACK_SIZE", default=4)
# Prefer fresher open-web hits (Searx time_range: day|week|month|year|"").
SEARX_TIME_RANGE = env("SEARX_TIME_RANGE", default="month")
# Exa semantic search (fallback open-web channel when keyed — prefer Searx/X/Reddit).
EXA_API_KEY = env("EXA_API_KEY", default="")
EXA_RECENCY_DAYS = env.int("EXA_RECENCY_DAYS", default=90)
# auto|fast|deep|… — keep auto; deep burns credits heavily.
EXA_SEARCH_TYPE = env("EXA_SEARCH_TYPE", default="auto")
# NL queries per OSINT/leak keyword (1 = frugal; raise for recall).
EXA_QUERY_COUNT = env.int("EXA_QUERY_COUNT", default=1)
EXA_HIGHLIGHTS = env.bool("EXA_HIGHLIGHTS", default=True)
# Guide: prefer highlights alone; text is opt-in (antipattern to combine by default).
EXA_INCLUDE_TEXT = env.bool("EXA_INCLUDE_TEXT", default=False)
EXA_TEXT_MAX_CHARS = env.int("EXA_TEXT_MAX_CHARS", default=2000)
# Optional highlights object {query} instead of highlights:true
EXA_HIGHLIGHTS_GUIDE = env.bool("EXA_HIGHLIGHTS_GUIDE", default=False)
# Opt-in includeText for leak hunts (default on — anchors brand/keyword).
EXA_REQUIRE_PHRASE = env.bool("EXA_REQUIRE_PHRASE", default=True)
# contents.maxAgeHours: omit empty; 24 / 1 / 0 / -1 per Exa livecrawl docs.
EXA_MAX_AGE_HOURS = env("EXA_MAX_AGE_HOURS", default="")
EXA_TIMEOUT = env.float("EXA_TIMEOUT", default=35.0)
EXA_CATEGORY = env("EXA_CATEGORY", default="")  # optional: news (not company+exclude)
EXA_EXCLUDE_DOMAINS = env(
    "EXA_EXCLUDE_DOMAINS",
    default="github.com,www.github.com,gist.github.com",
)
EXA_INCLUDE_DOMAINS = env("EXA_INCLUDE_DOMAINS", default="")
# OSINT ad-hoc: fallback = Exa only if Searx/X/Reddit kept < MIN_HITS (or use_exa=true).
EXA_OSINT_MODE = env("EXA_OSINT_MODE", default="fallback")  # fallback|always|off
EXA_OSINT_MIN_HITS = env.int("EXA_OSINT_MIN_HITS", default=5)
# Watch Rule leak sweeps: same gating.
EXA_LEAK_MODE = env("EXA_LEAK_MODE", default="fallback")  # fallback|always|off
EXA_LEAK_MIN_HITS = env.int("EXA_LEAK_MIN_HITS", default=5)
# Exa → The Wire (Threat ingest alongside RSS / Searx site discovery).
EXA_WIRE_ENABLED = env.bool("EXA_WIRE_ENABLED", default=True)
EXA_WIRE_MAX_AGE_DAYS = env.int("EXA_WIRE_MAX_AGE_DAYS", default=14)
# Cap results per beat run (lower = fewer Exa calls / credits).
EXA_WIRE_LIMIT = env.int("EXA_WIRE_LIMIT", default=8)
EXA_WIRE_LIMIT_PER_DOMAIN = env.int("EXA_WIRE_LIMIT_PER_DOMAIN", default=2)
# Optional pipe-separated NL queries (empty = built-in CTI pack).
EXA_WIRE_QUERIES = env("EXA_WIRE_QUERIES", default="")
# Max built-in/custom wire NL queries per run (each is an API call).
EXA_WIRE_QUERY_COUNT = env.int("EXA_WIRE_QUERY_COUNT", default=2)
# X/Twitter cookie search (secondary account only — never commit real values).
X_TWITTER_ENABLED = env.bool("X_TWITTER_ENABLED", default=True)
X_AUTH_TOKEN = env("X_AUTH_TOKEN", default="")
X_CT0 = env("X_CT0", default="")
# GraphQL query ids (rotate when X returns 404 — see twikit/xkit release notes).
X_SEARCH_QUERY_ID = env("X_SEARCH_QUERY_ID", default="R0u1RWRf748KzyGBXvOYRA")
X_TWEET_QUERY_ID = env("X_TWEET_QUERY_ID", default="Xl5pC_lBk_gcO2ItU39DQw")
# Curated X CTI accounts → The Wire (requires X cookies).
X_WIRE_ENABLED = env.bool("X_WIRE_ENABLED", default=True)
X_WIRE_MAX_AGE_DAYS = env.int("X_WIRE_MAX_AGE_DAYS", default=7)
X_WIRE_LIMIT_PER_ACCOUNT = env.int("X_WIRE_LIMIT_PER_ACCOUNT", default=8)
# Comma/pipe-separated handles (empty = built-in CTI pack). Append later without code.
X_WIRE_ACCOUNTS = env("X_WIRE_ACCOUNTS", default="")
# Pause between account fetches to reduce GraphQL rate pressure.
X_WIRE_PAUSE_MS = env.int("X_WIRE_PAUSE_MS", default=400)
# Reddit enrich (public JSON; optional cookie if rate-limited).
REDDIT_ENRICH_ENABLED = env.bool("REDDIT_ENRICH_ENABLED", default=True)
REDDIT_SEARCH_ENABLED = env.bool("REDDIT_SEARCH_ENABLED", default=True)
# Reddit search: relevance+all for recall; local phrase filter + published sort.
REDDIT_SEARCH_SORT = env("REDDIT_SEARCH_SORT", default="relevance")
REDDIT_SEARCH_TIME = env("REDDIT_SEARCH_TIME", default="all")
REDDIT_COOKIE = env("REDDIT_COOKIE", default="")
REDDIT_USER_AGENT = env(
    "REDDIT_USER_AGENT",
    default=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    ),
)
PASTE_ENRICH_ENABLED = env.bool("PASTE_ENRICH_ENABLED", default=True)
PASTE_EXTRA_HOSTS = env("PASTE_EXTRA_HOSTS", default="")
GITHUB_TOKEN = env("GITHUB_TOKEN", default="")
GITHUB_MAX_FILE_BYTES = env.int("GITHUB_MAX_FILE_BYTES", default=512000)
# Prefer fewer content GETs: text_matches cover most keyword hits; fetch for secrets only.
GITHUB_CONTENT_FETCH_LIMIT = env.int("GITHUB_CONTENT_FETCH_LIMIT", default=120)
# Small batches so the UI can show repos/files as soon as each page is persisted.
GITHUB_STREAM_BATCH_SIZE = env.int("GITHUB_STREAM_BATCH_SIZE", default=3)
GITHUB_SCAN_STALE_MINUTES = env.int("GITHUB_SCAN_STALE_MINUTES", default=20)
# Cap below GitHub's practical search budget to reduce rate-limit hits.
GITHUB_SCAN_MAX_RESULTS = env.int("GITHUB_SCAN_MAX_RESULTS", default=1500)

# Lab-only login verification service. The service fails closed unless both
# BRUTEFORCEAI_INTERNAL_TOKEN and an allowlisted lab host are configured.
BRUTEFORCEAI_SERVICE_URL = env("BRUTEFORCEAI_SERVICE_URL", default="http://bruteforceai:8000")
BRUTEFORCEAI_INTERNAL_TOKEN = env("BRUTEFORCEAI_INTERNAL_TOKEN", default="")
BRUTEFORCEAI_ALLOWED_HOSTS = env("BRUTEFORCEAI_ALLOWED_HOSTS", default="")
BRUTEFORCEAI_ALLOW_PUBLIC_TARGETS = env.bool("BRUTEFORCEAI_ALLOW_PUBLIC_TARGETS", default=False)
BRUTEFORCEAI_MAX_CREDENTIALS = env.int("BRUTEFORCEAI_MAX_CREDENTIALS", default=20)

# Zone-H / defacement archive → The Wire.
# Default provider=haxor (haxor.id) bypasses zone-h.org captcha from cloud IPs.
# For zone-h.org directly: ZONEH_PROVIDER=zoneh + PHPSESSID + ZHE cookies
# (browser Cookie-Editor after solving captcha once — inspired by BAUZACE7/Zone-H).
ZONEH_ENABLED = env.bool("ZONEH_ENABLED", default=True)
ZONEH_PROVIDER = env("ZONEH_PROVIDER", default="haxor")  # haxor | zoneh
ZONEH_BASE_URL = env("ZONEH_BASE_URL", default="")  # optional override
ZONEH_PAGES = env.int("ZONEH_PAGES", default=2)
ZONEH_INCLUDE_SPECIAL = env.bool("ZONEH_INCLUDE_SPECIAL", default=True)
ZONEH_TIMEOUT = env.float("ZONEH_TIMEOUT", default=30.0)
ZONEH_PHPSESSID = env("ZONEH_PHPSESSID", default="")
ZONEH_ZHE = env("ZONEH_ZHE", default="")

# Clearnet claim / forum-status → The Wire (no forum cookies or VNC).
FORUM_AI_ENRICH = env.bool("FORUM_AI_ENRICH", default=True)

# Fail closed when running production-like (DEBUG=False) with placeholder secrets.
from apps.core.security_checks import assert_secure_settings  # noqa: E402

assert_secure_settings()
