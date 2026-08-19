"""Stream-scan uploaded credential dumps for keyword matches."""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import time
import uuid
import fcntl
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.core.crypto import encrypt_secret
from apps.workers.parsers.stealer import parse_credential_line

logger = logging.getLogger(__name__)
UPLOAD_IO_CHUNK_BYTES = 8 * 1024 * 1024


def log_scan_storage_dir() -> Path:
    configured = getattr(settings, "LOG_SCAN_STORAGE_DIR", "") or ""
    if configured:
        path = Path(configured)
    else:
        path = Path(settings.BASE_DIR) / "media" / "log_uploads"
    path.mkdir(parents=True, exist_ok=True)
    return path


def max_upload_bytes() -> int:
    return int(getattr(settings, "LOG_SCAN_MAX_UPLOAD_BYTES", 250 * 1024 * 1024) or 0)


def max_hits_per_scan() -> int:
    return int(getattr(settings, "LOG_SCAN_MAX_HITS", 5000) or 5000)


def max_files_per_scan() -> int:
    return int(getattr(settings, "LOG_SCAN_MAX_FILES_PER_SCAN", 25) or 25)


def upload_chunk_bytes() -> int:
    return int(
        getattr(settings, "LOG_SCAN_UPLOAD_CHUNK_BYTES", 16 * 1024 * 1024)
        or 16 * 1024 * 1024
    )


def _hash_file(path: Path, *, limit: int = 0) -> tuple[int, str]:
    """Hash a file with large reads while enforcing the upload limit."""
    digest = hashlib.sha256()
    written = 0
    with path.open("rb") as source:
        while True:
            chunk = source.read(UPLOAD_IO_CHUNK_BYTES)
            if not chunk:
                break
            written += len(chunk)
            if limit and written > limit:
                raise ValueError(f"File exceeds max size ({limit} bytes).")
            digest.update(chunk)
    return written, digest.hexdigest()


def store_upload_file(*, uploaded_file, user) -> "LogUpload":
    """Store an upload with one disk write for large temporary files."""
    from apps.workers.models import LogUpload

    name = Path(getattr(uploaded_file, "name", "") or "upload.txt").name
    if not name.lower().endswith(".txt"):
        raise ValueError("Only .txt files are accepted.")

    size = int(getattr(uploaded_file, "size", 0) or 0)
    limit = max_upload_bytes()
    if limit and size and size > limit:
        raise ValueError(f"File exceeds max size ({limit} bytes).")

    folder = log_scan_storage_dir()
    uid = getattr(user, "pk", None) or 0
    safe = "".join(ch if ch.isalnum() or ch in "._-#" else "_" for ch in name)[:180]
    tmp_path = folder / f".tmp_u{uid}_{safe}"
    source_path = None
    stored = None
    try:
        temporary_file_path = getattr(uploaded_file, "temporary_file_path", None)
        if callable(temporary_file_path):
            candidate = Path(temporary_file_path())
            if candidate.is_file():
                source_path = candidate

        if source_path is not None:
            # TemporaryUploadedFile already exists on disk; hash it in place and
            # rename it below instead of copying 1.5GB to a second file.
            written, hexdigest = _hash_file(source_path, limit=limit)
        else:
            digest = hashlib.sha256()
            written = 0
            with tmp_path.open("wb") as dest:
                for chunk in uploaded_file.chunks(UPLOAD_IO_CHUNK_BYTES):
                    written += len(chunk)
                    if limit and written > limit:
                        raise ValueError(f"File exceeds max size ({limit} bytes).")
                    digest.update(chunk)
                    dest.write(chunk)
            hexdigest = digest.hexdigest()
            source_path = tmp_path

        existing = (
            LogUpload.objects.filter(sha256=hexdigest, uploaded_by=user)
            .order_by("-id")
            .first()
        )
        if existing and Path(existing.stored_path).is_file():
            source_path.unlink(missing_ok=True)
            return existing

        stored = folder / f"u{uid}_{hexdigest[:16]}_{safe}"
        try:
            source_path.replace(stored)
        except OSError:
            # Fallback for a temporary directory on another filesystem.
            copy_path = folder / f".copy_u{uid}_{hexdigest[:16]}_{safe}"
            with copy_path.open("wb") as dest, source_path.open("rb") as source:
                while True:
                    chunk = source.read(UPLOAD_IO_CHUNK_BYTES)
                    if not chunk:
                        break
                    dest.write(chunk)
            source_path.unlink(missing_ok=True)
            copy_path.replace(stored)
        source_path = None
        return LogUpload.objects.create(
            original_name=name,
            size_bytes=written,
            stored_path=str(stored),
            sha256=hexdigest,
            uploaded_by=user,
        )
    except Exception:
        tmp_path.unlink(missing_ok=True)
        if stored is not None:
            stored.unlink(missing_ok=True)
        raise


def _partial_upload_root() -> Path:
    root = log_scan_storage_dir() / ".partial_uploads"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _partial_upload_dir(*, user_id: int, upload_id: uuid.UUID) -> Path:
    return _partial_upload_root() / f"u{user_id}_{upload_id.hex}"


def _cleanup_stale_partial_uploads(max_age_seconds: int = 48 * 60 * 60) -> None:
    cutoff = time.time() - max_age_seconds
    root = _partial_upload_root()
    for path in root.iterdir():
        try:
            if path.is_dir() and path.stat().st_mtime < cutoff:
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            logger.warning("Failed to inspect partial upload %s", path)


def _chunk_meta_path(session_dir: Path) -> Path:
    return session_dir / "meta.json"


def _chunk_result_path(session_dir: Path) -> Path:
    return session_dir / "result.json"


def _read_chunk_result(session_dir: Path):
    result_path = _chunk_result_path(session_dir)
    if not result_path.is_file():
        return None
    try:
        result = json.loads(result_path.read_text(encoding="utf-8"))
        return result.get("upload_id")
    except (OSError, ValueError, TypeError):
        return None


def store_upload_chunk(
    *,
    uploaded_file,
    user,
    upload_id: uuid.UUID,
    original_name: str,
    file_size: int,
    total_chunks: int,
    chunk_index: int,
) -> dict:
    """Write one idempotent chunk to a resumable upload session."""
    from apps.workers.models import LogUpload

    name = Path(original_name or "upload.txt").name
    if not name.lower().endswith(".txt"):
        raise ValueError("Only .txt files are accepted.")
    limit = max_upload_bytes()
    chunk_size = upload_chunk_bytes()
    expected_chunks = (file_size + chunk_size - 1) // chunk_size if file_size else 0
    if file_size <= 0 or (limit and file_size > limit):
        raise ValueError(f"File exceeds max size ({limit} bytes).")
    if total_chunks != expected_chunks or not 0 <= chunk_index < total_chunks:
        raise ValueError("Invalid chunk metadata.")

    user_id = getattr(user, "pk", None) or 0
    session_dir = _partial_upload_dir(user_id=user_id, upload_id=upload_id)
    result_id = _read_chunk_result(session_dir)
    if result_id:
        existing = LogUpload.objects.filter(pk=result_id, uploaded_by=user).first()
        if existing:
            return {
                "complete": True,
                "upload": existing,
                "received_bytes": file_size,
            }

    if chunk_index == 0:
        _cleanup_stale_partial_uploads()
    session_dir.mkdir(parents=True, exist_ok=True)
    meta_path = _chunk_meta_path(session_dir)
    meta = {
        "original_name": name,
        "file_size": file_size,
        "total_chunks": total_chunks,
    }
    if meta_path.is_file():
        try:
            stored_meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError("Upload session metadata is invalid.") from exc
        if stored_meta != meta:
            raise ValueError("Upload session metadata does not match.")
    else:
        meta_path.write_text(json.dumps(meta), encoding="utf-8")

    offset = chunk_index * chunk_size
    expected_size = min(chunk_size, file_size - offset)
    reported_size = int(getattr(uploaded_file, "size", 0) or 0)
    if reported_size != expected_size:
        raise ValueError("Chunk size does not match its position.")

    data_path = session_dir / "data.part"
    mode = "r+b" if data_path.exists() else "w+b"
    written = 0
    with data_path.open(mode) as dest:
        dest.seek(offset)
        for chunk in uploaded_file.chunks(UPLOAD_IO_CHUNK_BYTES):
            written += len(chunk)
            if written > expected_size:
                raise ValueError("Chunk is larger than declared.")
            dest.write(chunk)
        dest.flush()
    if written != expected_size:
        raise ValueError("Chunk ended before the declared size.")

    marker = session_dir / f"part-{chunk_index}.done"
    marker_tmp = session_dir / f".part-{chunk_index}.done.tmp"
    marker_tmp.write_text(str(expected_size), encoding="ascii")
    marker_tmp.replace(marker)
    received = 0
    for marker_path in session_dir.glob("part-*.done"):
        try:
            received += int(marker_path.read_text(encoding="ascii"))
        except (OSError, ValueError):
            continue
    return {
        "complete": received == file_size and len(list(session_dir.glob("part-*.done"))) == total_chunks,
        "received_bytes": received,
    }


def finalize_upload_chunks(
    *, user, upload_id: uuid.UUID, original_name: str, file_size: int
) -> "LogUpload":
    """Finalize a complete chunk session; safe to call repeatedly."""
    from apps.workers.models import LogUpload

    user_id = getattr(user, "pk", None) or 0
    session_dir = _partial_upload_dir(user_id=user_id, upload_id=upload_id)
    session_dir.mkdir(parents=True, exist_ok=True)
    lock_path = session_dir / "finalize.lock"
    with lock_path.open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        result_id = _read_chunk_result(session_dir)
        if result_id:
            existing = LogUpload.objects.filter(pk=result_id, uploaded_by=user).first()
            if existing:
                return existing

        data_path = session_dir / "data.part"
        if not data_path.is_file():
            raise ValueError("Upload session is incomplete.")
        markers = list(session_dir.glob("part-*.done"))
        if len(markers) == 0 or sum(
            int(path.read_text(encoding="ascii")) for path in markers
        ) != file_size:
            raise ValueError("Upload session is incomplete.")

        written, hexdigest = _hash_file(data_path, limit=max_upload_bytes())
        if written != file_size:
            raise ValueError("Uploaded file size does not match metadata.")

        name = Path(original_name or "upload.txt").name
        existing = (
            LogUpload.objects.filter(sha256=hexdigest, uploaded_by=user)
            .order_by("-id")
            .first()
        )
        if existing and Path(existing.stored_path).is_file():
            row = existing
        else:
            safe = "".join(ch if ch.isalnum() or ch in "._-#" else "_" for ch in name)[:180]
            stored = log_scan_storage_dir() / f"u{user_id}_{hexdigest[:16]}_{safe}"
            data_path.replace(stored)
            row = LogUpload.objects.create(
                original_name=name,
                size_bytes=written,
                stored_path=str(stored),
                sha256=hexdigest,
                uploaded_by=user,
            )

        _chunk_result_path(session_dir).write_text(
            json.dumps({"upload_id": row.pk}), encoding="utf-8"
        )
        for path in session_dir.iterdir():
            if path.name not in {"result.json", "finalize.lock"}:
                path.unlink(missing_ok=True)
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        return row


def store_upload_bytes(*, original_name: str, content: bytes, user) -> "LogUpload":
    """Small-file helper (tests). Prefer store_upload_file for API uploads."""
    from apps.workers.models import LogUpload

    limit = max_upload_bytes()
    if limit and len(content) > limit:
        raise ValueError(f"File exceeds max size ({limit} bytes).")

    name = Path(original_name or "upload.txt").name
    if not name.lower().endswith(".txt"):
        raise ValueError("Only .txt files are accepted.")

    digest = hashlib.sha256(content).hexdigest()
    existing = (
        LogUpload.objects.filter(sha256=digest, uploaded_by=user)
        .order_by("-id")
        .first()
    )
    if existing and Path(existing.stored_path).is_file():
        return existing

    folder = log_scan_storage_dir()
    uid = getattr(user, "pk", None) or 0
    safe = "".join(ch if ch.isalnum() or ch in "._-#" else "_" for ch in name)[:180]
    stored = folder / f"u{uid}_{digest[:16]}_{safe}"
    stored.write_bytes(content)

    return LogUpload.objects.create(
        original_name=name,
        size_bytes=len(content),
        stored_path=str(stored),
        sha256=digest,
        uploaded_by=user,
    )


def delete_upload(upload) -> None:
    path = Path(upload.stored_path or "")
    try:
        if path.is_file():
            path.unlink()
    except OSError:
        logger.warning("Failed to delete log upload file %s", path)
    upload.delete()


def scan_file_for_hits(
    path: Path,
    *,
    keyword: str = "",
    max_hits: int | None = None,
) -> tuple[int, list]:
    """Return (lines_scanned, [ParsedCredential, ...]) in a single pass."""
    kw = (keyword or "").strip().lower()
    limit = max_hits if max_hits is not None else max_hits_per_scan()
    hits = []
    lines = 0
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        for line in handle:
            lines += 1
            if kw and kw not in line.lower():
                continue
            parsed = parse_credential_line(line)
            if not parsed:
                continue
            hits.append(parsed)
            if limit and len(hits) >= limit:
                # Still finish counting remaining lines for stats.
                for _ in handle:
                    lines += 1
                break
    return lines, hits


def run_log_scan(scan_id: int) -> dict:
    from apps.workers.models import LogScan, LogScanHit

    with transaction.atomic():
        scan = LogScan.objects.select_for_update().get(pk=scan_id)
        if scan.status not in {LogScan.Status.QUEUED, LogScan.Status.RUNNING}:
            return {"scan_id": scan_id, "status": scan.status, "skipped": True}
        scan.status = LogScan.Status.RUNNING
        scan.started_at = timezone.now()
        scan.error_message = ""
        scan.save(
            update_fields=["status", "started_at", "error_message", "updated_at"]
        )

    uploads = list(scan.uploads.all())
    keyword = scan.keyword or ""
    hit_budget = max_hits_per_scan()
    lines_scanned = 0
    files_scanned = 0
    batch: list[LogScanHit] = []
    total_hits = 0

    try:
        LogScanHit.objects.filter(scan=scan, is_kept=False).delete()

        for upload in uploads:
            if total_hits >= hit_budget:
                break
            path = Path(upload.stored_path or "")
            if not path.is_file():
                logger.warning("Missing upload file for LogUpload#%s", upload.pk)
                continue
            files_scanned += 1
            remaining = hit_budget - total_hits
            file_lines, parsed_hits = scan_file_for_hits(
                path, keyword=keyword, max_hits=remaining
            )
            lines_scanned += file_lines
            for parsed in parsed_hits:
                batch.append(
                    LogScanHit(
                        scan=scan,
                        upload=upload,
                        url=(parsed.url or "")[:2048],
                        domain=(parsed.domain or "")[:255],
                        username=(parsed.username or "")[:255],
                        email=(parsed.email or "")[:255],
                        password=encrypt_secret(parsed.password or ""),
                        raw_line=(parsed.raw_line or "")[:4000],
                    )
                )
                total_hits += 1
                if len(batch) >= 500:
                    LogScanHit.objects.bulk_create(batch)
                    batch.clear()

        if batch:
            LogScanHit.objects.bulk_create(batch)

        scan.status = LogScan.Status.COMPLETED
        scan.hit_count = total_hits
        scan.lines_scanned = lines_scanned
        scan.files_scanned = files_scanned
        scan.completed_at = timezone.now()
        scan.save(
            update_fields=[
                "status",
                "hit_count",
                "lines_scanned",
                "files_scanned",
                "completed_at",
                "updated_at",
            ]
        )
        return {
            "scan_id": scan_id,
            "status": scan.status,
            "hit_count": total_hits,
            "lines_scanned": lines_scanned,
            "files_scanned": files_scanned,
        }
    except Exception as exc:  # noqa: BLE001
        logger.exception("run_log_scan failed scan_id=%s", scan_id)
        scan.status = LogScan.Status.FAILED
        scan.error_message = str(exc)[:2000]
        scan.completed_at = timezone.now()
        scan.save(
            update_fields=[
                "status",
                "error_message",
                "completed_at",
                "updated_at",
            ]
        )
        raise
