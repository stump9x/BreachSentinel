"""Backend boundary for the allowlisted BruteForceAI lab service."""

from __future__ import annotations

import logging
import ipaddress
from urllib.parse import urlsplit

import httpx
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.core.crypto import decrypt_secret
from apps.workers.models import LabAllowlistEntry, LabLoginScan, LogScanHit

logger = logging.getLogger(__name__)


def _configured_lab_hosts() -> set[str]:
    return {
        item.strip().casefold().rstrip(".")
        for item in str(getattr(settings, "BRUTEFORCEAI_ALLOWED_HOSTS", "") or "").split(",")
        if item.strip()
    }


def get_lab_allowlisted_hosts() -> set[str]:
    hosts = _configured_lab_hosts()
    hosts.update(LabAllowlistEntry.objects.values_list("host", flat=True))
    return {str(host).casefold().rstrip(".") for host in hosts if host}


def is_safe_lab_host(host: str) -> bool:
    host = (host or "").casefold().rstrip(".")
    if host in {"localhost", "host.docker.internal"}:
        return True
    if host.endswith((".test", ".localhost", ".local", ".internal")):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
    )


def normalize_lab_hostname(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        raise ValueError("Domain is required.")
    parsed = urlsplit(raw if "://" in raw else f"http://{raw}")
    host = (parsed.hostname or "").casefold().rstrip(".")
    if parsed.scheme not in {"http", "https"} or not host:
        raise ValueError("Enter a valid HTTP(S) lab domain.")
    if parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Allowlist accepts a hostname only, without path or credentials.")
    return host


def normalize_lab_target(value: str) -> tuple[str, str]:
    raw = (value or "").strip()
    if "://" not in raw:
        raw = f"http://{raw}"
    parsed = urlsplit(raw)
    host = (parsed.hostname or "").casefold().rstrip(".")
    allowed = get_lab_allowlisted_hosts()
    if parsed.scheme not in {"http", "https"} or not host:
        raise ValueError("Target must be an HTTP(S) URL or lab hostname.")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Target URL may not contain credentials or fragments.")
    if host not in allowed:
        raise ValueError("Target host is not in the configured lab allowlist.")
    if not parsed.path:
        raw = raw.rstrip("/") + "/"
    return raw, host


def run_lab_login_scan(job_id: int) -> dict:
    job = LabLoginScan.objects.select_related("scan").get(pk=job_id)
    with transaction.atomic():
        locked = LabLoginScan.objects.select_for_update().get(pk=job.pk)
        if locked.status != LabLoginScan.Status.QUEUED:
            return {"id": locked.id, "status": locked.status, "skipped": True}
        locked.status = LabLoginScan.Status.RUNNING
        locked.started_at = timezone.now()
        locked.save(update_fields=["status", "started_at", "updated_at"])

    hits = list(
        LogScanHit.objects.filter(scan_id=job.scan_id, id__in=list(job.hit_ids or []))
        .order_by("id")
    )
    credentials = []
    for hit in hits:
        username = (hit.email or hit.username or "").strip()
        password = decrypt_secret(hit.password or "")
        if username and password:
            credentials.append({"username": username, "password": password})

    max_credentials = max(1, int(getattr(settings, "BRUTEFORCEAI_MAX_CREDENTIALS", 20) or 20))
    credentials = credentials[:max_credentials]
    job.candidate_count = len(credentials)
    job.save(update_fields=["candidate_count", "updated_at"])
    if not credentials:
        job.status = LabLoginScan.Status.FAILED
        job.error_message = "No usable username/password pair was found for this target."
        job.completed_at = timezone.now()
        job.save(update_fields=["status", "error_message", "completed_at", "updated_at"])
        return {"id": job.id, "status": job.status}

    url = str(getattr(settings, "BRUTEFORCEAI_SERVICE_URL", "") or "").rstrip("/") + "/scan"
    token = str(getattr(settings, "BRUTEFORCEAI_INTERNAL_TOKEN", "") or "")
    try:
        response = httpx.post(
            url,
            json={
                "target_url": job.target_url,
                "credentials": credentials,
                "allowed_hosts": sorted(get_lab_allowlisted_hosts()),
            },
            headers={"X-BruteForceAI-Token": token},
            timeout=1800.0,
        )
        response.raise_for_status()
        payload = response.json() if response.content else {}
        safe_results = [
            {
                "username": str(item.get("username") or ""),
                "success": bool(item.get("success")),
                "response_time_ms": item.get("response_time_ms"),
                "timestamp": item.get("timestamp"),
            }
            for item in payload.get("results") or []
            if isinstance(item, dict)
        ]
        job.attempt_count = int(payload.get("attempt_count") or len(safe_results))
        job.success_count = int(payload.get("success_count") or sum(1 for item in safe_results if item["success"]))
        service_status = str(payload.get("status") or "failed")
        job.result_summary = {
            "target_domain": job.target_domain,
            "service_status": service_status,
            "reason_code": str(payload.get("reason_code") or ""),
            "analysis": payload.get("analysis") or {},
            "results": safe_results,
        }
        diagnostics = str(payload.get("diagnostics") or "")
        if diagnostics:
            job.result_summary["diagnostics"] = diagnostics[-2000:]
        if service_status == "completed":
            job.status = LabLoginScan.Status.COMPLETED
            job.error_message = ""
        elif service_status == "not_attempted":
            job.status = LabLoginScan.Status.NOT_ATTEMPTED
            job.error_message = str(payload.get("error") or "No login attempt was made.")[:1000]
        else:
            job.status = LabLoginScan.Status.FAILED
            job.error_message = str(payload.get("error") or "BruteForceAI job failed.")[:1000]
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("Lab login service failed for job %s: %s", job.id, type(exc).__name__)
        job.status = LabLoginScan.Status.FAILED
        job.error_message = "Lab login service request failed or returned invalid data."
    finally:
        job.completed_at = timezone.now()
        job.save(
            update_fields=[
                "status",
                "attempt_count",
                "success_count",
                "result_summary",
                "error_message",
                "completed_at",
                "updated_at",
            ]
        )
    return {"id": job.id, "status": job.status, "attempts": job.attempt_count, "successes": job.success_count}
