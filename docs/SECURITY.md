# Security hardening notes (pentester + follow-up pass)

## Delivered

| Issue | Mitigation |
|---|---|
| FeedSource SSRF | Public-URL validation + no redirects; mutations **staff-only** |
| Credential `raw_line` / password exposure | Redacted from API + admin; Fernet **encrypt-at-rest**; HMAC pepper fingerprints |
| Health recon | Auth required except `/api/health/` |
| CSRF on SPA | No SessionAuth on API; tokens via login; `credentials: "omit"` |
| Long-lived Basic in browser | Replaced with **expiring DRF Token** (`AUTH_TOKEN_TTL_HOURS`, default 12) |
| Flat privileges | **IsStaffUser** for MISP, AI spend/NER, stealer parse, feed ingest, Searx sweep |
| Redis open | `requirepass` + password in Celery/Redis URLs |
| Django `runserver` | **Gunicorn** in compose |
| Data-plane ports | Bind `127.0.0.1` for db/redis/osint/searx |
| Weak DEBUG=False secrets | Startup refuse placeholders (+ Redis password) |
| Searx abuse | Host port bound to localhost; JSON API used only by internal services |
| Frontend headers | CSP / nosniff / frame / referrer |

## Ops

```bash
# Login (SPA does this automatically)
POST /api/v1/auth/login/  {"username","password"} → {"token","expires_in_hours","is_staff"}
Authorization: Token <token>

# Staff flag required for Workers / AI generate / MISP / Searx sweep / feed create
docker compose exec backend python manage.py shell -c "from django.contrib.auth import get_user_model; u=get_user_model().objects.get(username='admin'); u.is_staff=True; u.save()"
```

Set `REDIS_PASSWORD`, rotate `DJANGO_SECRET_KEY`, optionally `CREDENTIAL_PEPPER` + `FIELD_ENCRYPTION_KEY` in `.env` for production.

## Still later

- Full OIDC/LDAP (env stubs already present)
- Role model finer than staff/analyst (e.g. “integrations” group)
