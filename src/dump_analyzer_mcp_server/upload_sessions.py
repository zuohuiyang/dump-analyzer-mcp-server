import logging
import os
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, Optional, Tuple

from .logging_utils import make_context, sanitize_exception_message, sanitize_path

logger = logging.getLogger(__name__)

DEFAULT_MAX_UPLOAD_MB = 100
DEFAULT_SESSION_TTL_SECONDS = 1800
DEFAULT_MAX_ACTIVE_SESSIONS = 10
MINIDUMP_SIGNATURE = b"MDMP"
PAGE_DUMP_SIGNATURE = b"PAGE"
SUPPORTED_DUMP_SIGNATURES = {
    ".dmp": (MINIDUMP_SIGNATURE, PAGE_DUMP_SIGNATURE),
    ".mdmp": (MINIDUMP_SIGNATURE,),
    ".hdmp": (MINIDUMP_SIGNATURE, PAGE_DUMP_SIGNATURE),
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class UploadSessionStatus(str, Enum):
    PENDING = "pending"
    UPLOADING = "uploading"
    UPLOADED = "uploaded"
    FAILED = "failed"


class AnalysisSessionStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    CLOSED = "closed"


@dataclass
class UploadSessionMetadata:
    file_id: str
    original_file_name: str
    expected_file_size: int
    temp_file_path: str
    status: UploadSessionStatus = UploadSessionStatus.PENDING
    analysis_session_id: Optional[str] = None
    created_at: datetime = field(default_factory=_utc_now)
    last_access_at: datetime = field(default_factory=_utc_now)
    expires_at: Optional[datetime] = None
    upload_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    is_analyzing: bool = False

    def touch(self, ttl_seconds: int) -> None:
        now = _utc_now()
        self.last_access_at = now
        self.expires_at = now + timedelta(seconds=ttl_seconds)


@dataclass
class AnalysisSessionMetadata:
    session_id: str
    file_id: str
    status: AnalysisSessionStatus = AnalysisSessionStatus.CREATED
    created_at: datetime = field(default_factory=_utc_now)
    last_access_at: datetime = field(default_factory=_utc_now)
    expires_at: Optional[datetime] = None

    def touch(self, ttl_seconds: int) -> None:
        now = _utc_now()
        self.last_access_at = now
        self.expires_at = now + timedelta(seconds=ttl_seconds)


@dataclass
class UploadRuntimeConfig:
    upload_dir: str
    max_upload_mb: int
    session_ttl_seconds: int
    max_active_sessions: int


@dataclass
class SessionRegistry:
    cdb_sessions: Dict[str, object] = field(default_factory=dict)
    upload_sessions: Dict[str, UploadSessionMetadata] = field(default_factory=dict)
    analysis_sessions: Dict[str, AnalysisSessionMetadata] = field(default_factory=dict)
    cdb_creation_locks: Dict[str, threading.Lock] = field(default_factory=dict, repr=False)
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)


class UploadSessionLimitError(RuntimeError):
    pass


_upload_storage_lock = threading.Lock()
_initialized_upload_dir: Optional[str] = None


def _default_upload_dir() -> str:
    program_data = os.getenv("PROGRAMDATA")
    if program_data:
        return str(Path(program_data) / "dump-analyzer-mcp-server" / "uploads")
    return str(Path(tempfile.gettempdir()) / "dump-analyzer-mcp-server" / "uploads")


def create_upload_runtime_config(
    *,
    upload_dir: Optional[str] = None,
    max_upload_mb: int = DEFAULT_MAX_UPLOAD_MB,
    session_ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    max_active_sessions: int = DEFAULT_MAX_ACTIVE_SESSIONS,
) -> UploadRuntimeConfig:
    if max_upload_mb <= 0:
        raise ValueError("max_upload_mb must be greater than 0")
    if session_ttl_seconds <= 0:
        raise ValueError("session_ttl_seconds must be greater than 0")
    if max_active_sessions <= 0:
        raise ValueError("max_active_sessions must be greater than 0")

    resolved_upload_dir = os.path.abspath((upload_dir or "").strip() or _default_upload_dir())
    return UploadRuntimeConfig(
        upload_dir=resolved_upload_dir,
        max_upload_mb=max_upload_mb,
        session_ttl_seconds=session_ttl_seconds,
        max_active_sessions=max_active_sessions,
    )


def configure_upload_runtime(
    *,
    upload_dir: Optional[str] = None,
    max_upload_mb: int = DEFAULT_MAX_UPLOAD_MB,
    session_ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    max_active_sessions: int = DEFAULT_MAX_ACTIVE_SESSIONS,
) -> UploadRuntimeConfig:
    global upload_runtime_config
    upload_runtime_config = create_upload_runtime_config(
        upload_dir=upload_dir,
        max_upload_mb=max_upload_mb,
        session_ttl_seconds=session_ttl_seconds,
        max_active_sessions=max_active_sessions,
    )
    initialize_upload_storage(upload_runtime_config)
    return upload_runtime_config


def ensure_controlled_upload_dir(upload_dir: str) -> str:
    path = Path(upload_dir).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise RuntimeError(f"Upload path is not a directory: {path}")
    return str(path)


def initialize_upload_storage(config: Optional[UploadRuntimeConfig] = None) -> UploadRuntimeConfig:
    global _initialized_upload_dir
    runtime_config = config or upload_runtime_config
    configured_dir = os.path.abspath(runtime_config.upload_dir)
    with _upload_storage_lock:
        if _initialized_upload_dir == configured_dir and os.path.isdir(configured_dir):
            runtime_config.upload_dir = configured_dir
            return runtime_config
        runtime_config.upload_dir = ensure_controlled_upload_dir(configured_dir)
        _initialized_upload_dir = runtime_config.upload_dir
    return runtime_config


def get_supported_dump_extension(file_name: str) -> Optional[str]:
    normalized = os.path.basename(file_name.strip()).lower()
    if not normalized:
        return None
    suffix = Path(normalized).suffix
    return suffix if suffix in SUPPORTED_DUMP_SIGNATURES else None


def is_supported_dump_filename(file_name: str) -> bool:
    return get_supported_dump_extension(file_name) is not None


def get_expected_dump_signatures(file_name: str) -> Tuple[bytes, ...]:
    ext = get_supported_dump_extension(file_name)
    if ext is None:
        raise ValueError("Only .dmp, .mdmp, and .hdmp files are supported")
    return SUPPORTED_DUMP_SIGNATURES[ext]


def sanitize_upload_file_name(file_name: str) -> str:
    base_name = os.path.basename(file_name.strip())
    if not base_name:
        return "upload.dmp"
    ext = get_supported_dump_extension(base_name)
    stem = base_name[: -len(ext)] if ext else base_name
    safe_stem = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in stem).strip("._-") or "upload"
    return f"{safe_stem}{ext or '.dmp'}"


def _build_upload_temp_file_path(file_id: str, file_name: str) -> str:
    return os.path.join(upload_runtime_config.upload_dir, f"{file_id}-{sanitize_upload_file_name(file_name)}")


def build_upload_cdb_session_key(session_id: str) -> str:
    return f"analysis:{session_id}"


def cleanup_temp_upload_file(path: str) -> None:
    try:
        Path(path).unlink(missing_ok=True)
    except OSError:
        pass


def create_upload_session(file_name: str, file_size: int) -> Dict[str, object]:
    initialize_upload_storage()
    original_file_name = os.path.basename(file_name.strip())
    if not is_supported_dump_filename(original_file_name):
        raise ValueError("Only .dmp, .mdmp, and .hdmp files are supported")
    if file_size <= 0:
        raise ValueError("file_size must be greater than 0")
    max_bytes = upload_runtime_config.max_upload_mb * 1024 * 1024
    if file_size > max_bytes:
        logger.warning(
            "Upload session rejected because file exceeds configured limit",
            extra=make_context(event="upload.session.create", outcome="rejected"),
        )
        raise UploadSessionLimitError(f"file_size exceeds limit: {upload_runtime_config.max_upload_mb}MB")

    cleanup_expired_upload_sessions()

    with session_registry.lock:
        if len(session_registry.upload_sessions) >= upload_runtime_config.max_active_sessions:
            logger.warning(
                "Upload session rejected because active session limit was reached",
                extra=make_context(event="upload.session.create", outcome="rejected"),
            )
            raise UploadSessionLimitError(
                f"maximum active upload sessions reached ({upload_runtime_config.max_active_sessions})"
            )
        file_id = uuid.uuid4().hex
        metadata = UploadSessionMetadata(
            file_id=file_id,
            original_file_name=original_file_name,
            expected_file_size=file_size,
            temp_file_path=_build_upload_temp_file_path(file_id, original_file_name),
        )
        metadata.touch(upload_runtime_config.session_ttl_seconds)
        session_registry.upload_sessions[file_id] = metadata
        logger.info(
            "Upload session created for %s",
            sanitize_path(original_file_name),
            extra=make_context(event="upload.session.create", outcome="success", file_id=file_id),
        )
        return {
            "file_id": file_id,
            "expires_at": metadata.expires_at.isoformat() if metadata.expires_at else "",
            "max_upload_mb": upload_runtime_config.max_upload_mb,
        }


def cleanup_expired_upload_sessions(now: Optional[datetime] = None) -> int:
    current = now or _utc_now()
    removed = 0
    to_cleanup: list[tuple[UploadSessionMetadata, object]] = []
    with session_registry.lock:
        for file_id, metadata in list(session_registry.upload_sessions.items()):
            if metadata.expires_at and metadata.expires_at <= current and not metadata.is_analyzing:
                session_registry.upload_sessions.pop(file_id, None)
                if metadata.analysis_session_id:
                    session_registry.analysis_sessions.pop(metadata.analysis_session_id, None)
                    cdb = session_registry.cdb_sessions.pop(build_upload_cdb_session_key(metadata.analysis_session_id), None)
                    to_cleanup.append((metadata, cdb))
                else:
                    to_cleanup.append((metadata, None))
                removed += 1
    for metadata, cdb in to_cleanup:
        if cdb and callable(getattr(cdb, "shutdown", None)):
            try:
                cdb.shutdown()
            except Exception:
                logger.exception(
                    "Failed to shutdown CDB session for expired upload session",
                    extra=make_context(event="upload.session.expire", outcome="error", file_id=metadata.file_id),
                )
        cleanup_temp_upload_file(metadata.temp_file_path)
        logger.info(
            "Expired upload session cleaned up",
            extra=make_context(
                event="upload.session.expire",
                outcome="expired",
                file_id=metadata.file_id,
                session_id=metadata.analysis_session_id,
            ),
        )
    return removed


def prepare_upload_session_for_upload(file_id: str, ttl_seconds: int) -> Tuple[Optional[UploadSessionMetadata], str, str]:
    with session_registry.lock:
        metadata = session_registry.upload_sessions.get(file_id)
    if metadata is None:
        logger.warning(
            "Upload session not found during upload preparation",
            extra=make_context(event="upload.session.prepare", outcome="missing", file_id=file_id),
        )
        return None, "not_found", "Upload session not found"
    if not metadata.upload_lock.acquire(blocking=False):
        logger.warning(
            "Upload session is busy",
            extra=make_context(event="upload.session.prepare", outcome="busy", file_id=file_id),
        )
        return None, "busy", "Upload session is already processing an upload"

    with session_registry.lock:
        latest = session_registry.upload_sessions.get(file_id)
        if latest is None:
            metadata.upload_lock.release()
            logger.warning(
                "Upload session disappeared before upload began",
                extra=make_context(event="upload.session.prepare", outcome="missing", file_id=file_id),
            )
            return None, "not_found", "Upload session not found"
        metadata = latest
        if metadata.status != UploadSessionStatus.PENDING:
            metadata.upload_lock.release()
            logger.warning(
                "Upload session is in invalid state for upload start",
                extra=make_context(event="upload.session.prepare", outcome="invalid", file_id=file_id),
            )
            return None, "invalid_state", f"Upload session state is {metadata.status.value}, expected pending"
        metadata.status = UploadSessionStatus.UPLOADING
        metadata.touch(ttl_seconds)
        logger.info(
            "Upload session entered uploading state",
            extra=make_context(event="upload.session.prepare", outcome="success", file_id=file_id),
        )
        return metadata, "", ""


def mark_upload_failed(metadata: UploadSessionMetadata) -> None:
    with session_registry.lock:
        session_registry.upload_sessions.pop(metadata.file_id, None)
    cleanup_temp_upload_file(metadata.temp_file_path)
    logger.info(
        "Upload session marked failed and temporary data cleaned",
        extra=make_context(event="upload.session.fail", outcome="failed", file_id=metadata.file_id),
    )


def mark_upload_completed(metadata: UploadSessionMetadata, ttl_seconds: int, uploaded_size: int) -> Optional[str]:
    with session_registry.lock:
        current = session_registry.upload_sessions.get(metadata.file_id)
        if current is not metadata:
            logger.warning(
                "Upload completion target was not found",
                extra=make_context(event="upload.session.complete", outcome="missing", file_id=metadata.file_id),
            )
            return "Upload session not found"
        if uploaded_size != metadata.expected_file_size:
            session_registry.upload_sessions.pop(metadata.file_id, None)
            cleanup_temp_upload_file(metadata.temp_file_path)
            logger.warning(
                "Upload size mismatch during completion",
                extra=make_context(event="upload.session.complete", outcome="invalid", file_id=metadata.file_id),
            )
            return f"Uploaded file size mismatch: expected {metadata.expected_file_size}, got {uploaded_size}"
        metadata.status = UploadSessionStatus.UPLOADED
        metadata.touch(ttl_seconds)
    logger.info(
        "Upload session marked uploaded",
        extra=make_context(event="upload.session.complete", outcome="success", file_id=metadata.file_id),
    )
    return None


def release_upload_lock(metadata: Optional[UploadSessionMetadata]) -> None:
    if metadata is None:
        return
    try:
        metadata.upload_lock.release()
    except RuntimeError:
        pass


def acquire_uploaded_file_for_analysis(file_id: str, ttl_seconds: int) -> Tuple[Optional[UploadSessionMetadata], Optional[str]]:
    with session_registry.lock:
        metadata = session_registry.upload_sessions.get(file_id)
        if metadata is None:
            logger.warning(
                "Uploaded file not found for analysis",
                extra=make_context(event="analysis.acquire_file", outcome="missing", file_id=file_id),
            )
            return None, "Upload session not found"
        if metadata.status != UploadSessionStatus.UPLOADED:
            logger.warning(
                "Uploaded file is not ready for analysis",
                extra=make_context(event="analysis.acquire_file", outcome="invalid", file_id=file_id),
            )
            return None, f"Upload session state is {metadata.status.value}, expected uploaded"
        metadata.touch(ttl_seconds)
        logger.info(
            "Uploaded file acquired for analysis",
            extra=make_context(event="analysis.acquire_file", outcome="success", file_id=file_id),
        )
        return metadata, None


def get_or_create_analysis_session(file_id: str, ttl_seconds: int) -> Tuple[Optional[AnalysisSessionMetadata], Optional[str]]:
    with session_registry.lock:
        metadata = session_registry.upload_sessions.get(file_id)
        if metadata is None:
            return None, "Upload session not found"
        if metadata.status != UploadSessionStatus.UPLOADED:
            return None, f"Upload session state is {metadata.status.value}, expected uploaded"
        if metadata.analysis_session_id and metadata.analysis_session_id in session_registry.analysis_sessions:
            analysis = session_registry.analysis_sessions[metadata.analysis_session_id]
            analysis.touch(ttl_seconds)
            metadata.touch(ttl_seconds)
            logger.info(
                "Reusing existing analysis session",
                extra=make_context(
                    event="analysis.session.create",
                    outcome="reused",
                    file_id=file_id,
                    session_id=analysis.session_id,
                ),
            )
            return analysis, None
        session_id = uuid.uuid4().hex
        analysis = AnalysisSessionMetadata(session_id=session_id, file_id=file_id, status=AnalysisSessionStatus.CREATED)
        analysis.touch(ttl_seconds)
        metadata.analysis_session_id = session_id
        metadata.touch(ttl_seconds)
        session_registry.analysis_sessions[session_id] = analysis
        logger.info(
            "Analysis session created",
            extra=make_context(event="analysis.session.create", outcome="success", file_id=file_id, session_id=session_id),
        )
        return analysis, None


def acquire_analysis_session(session_id: str, ttl_seconds: int) -> Tuple[Optional[AnalysisSessionMetadata], Optional[UploadSessionMetadata], Optional[str]]:
    with session_registry.lock:
        analysis = session_registry.analysis_sessions.get(session_id)
        if analysis is None:
            return None, None, "Analysis session not found"
        upload = session_registry.upload_sessions.get(analysis.file_id)
        if upload is None:
            return None, None, "Upload session not found"
        analysis.touch(ttl_seconds)
        upload.touch(ttl_seconds)
        upload.is_analyzing = True
        analysis.status = AnalysisSessionStatus.RUNNING
        logger.info(
            "Analysis session acquired for command execution",
            extra=make_context(
                event="analysis.session.acquire",
                outcome="success",
                file_id=upload.file_id,
                session_id=session_id,
            ),
        )
        return analysis, upload, None


def release_analysis_session(session_id: str, ttl_seconds: int) -> None:
    with session_registry.lock:
        analysis = session_registry.analysis_sessions.get(session_id)
        if analysis is None:
            return
        upload = session_registry.upload_sessions.get(analysis.file_id)
        analysis.touch(ttl_seconds)
        if upload is not None:
            upload.is_analyzing = False
            upload.touch(ttl_seconds)
        logger.info(
            "Analysis session released after command execution",
            extra=make_context(
                event="analysis.session.release",
                outcome="success",
                file_id=analysis.file_id,
                session_id=session_id,
            ),
        )


def close_analysis_session(session_id: str) -> Tuple[Optional[Dict[str, object]], str, str]:
    with session_registry.lock:
        analysis = session_registry.analysis_sessions.get(session_id)
        if analysis is None:
            logger.warning(
                "Analysis session close requested for unknown session",
                extra=make_context(event="analysis.session.close", outcome="missing", session_id=session_id),
            )
            return None, "not_found", "Analysis session not found"
        session_key = build_upload_cdb_session_key(session_id)
        cdb = session_registry.cdb_sessions.get(session_key)
        if cdb and callable(getattr(cdb, "has_pending_command", None)) and cdb.has_pending_command():
            logger.warning(
                "Analysis session close rejected because a command is still running",
                extra=make_context(event="analysis.session.close", outcome="busy", file_id=analysis.file_id, session_id=session_id),
            )
            return None, "busy", "Analysis session still has a running or queued command"
        analysis = session_registry.analysis_sessions.pop(session_id, None)
        upload = session_registry.upload_sessions.pop(analysis.file_id, None)
        cdb = session_registry.cdb_sessions.pop(session_key, None)
        session_registry.cdb_creation_locks.pop(session_key, None)

    if cdb and callable(getattr(cdb, "shutdown", None)):
        try:
            cdb.shutdown()
        except Exception:
            logger.exception(
                "Failed to shutdown CDB session while closing analysis session",
                extra=make_context(
                    event="analysis.session.close",
                    outcome="error",
                    file_id=analysis.file_id,
                    session_id=session_id,
                ),
            )
    if upload:
        cleanup_temp_upload_file(upload.temp_file_path)
    logger.info(
        "Analysis session closed",
        extra=make_context(event="analysis.session.close", outcome="success", file_id=analysis.file_id, session_id=session_id),
    )
    return {"session_id": session_id, "status": "closed"}, "", ""


def _get_cdb_creation_lock(session_key: str) -> threading.Lock:
    with session_registry.lock:
        lock = session_registry.cdb_creation_locks.get(session_key)
        if lock is None:
            lock = threading.Lock()
            session_registry.cdb_creation_locks[session_key] = lock
        return lock


def get_or_create_cdb_session(session_key: str, factory):
    with session_registry.lock:
        existing = session_registry.cdb_sessions.get(session_key)
        if existing is not None:
            logger.info(
                "Reusing existing CDB session",
                extra=make_context(event="cdb.session.get_or_create", outcome="reused", session_id=session_key),
            )
            return existing
    with _get_cdb_creation_lock(session_key):
        with session_registry.lock:
            existing = session_registry.cdb_sessions.get(session_key)
            if existing is not None:
                logger.info(
                    "Reusing existing CDB session after waiting on creation lock",
                    extra=make_context(event="cdb.session.get_or_create", outcome="reused", session_id=session_key),
                )
                return existing
        created = factory()
        with session_registry.lock:
            current = session_registry.cdb_sessions.get(session_key)
            if current is None:
                session_registry.cdb_sessions[session_key] = created
                logger.info(
                    "Created new CDB session",
                    extra=make_context(event="cdb.session.get_or_create", outcome="success", session_id=session_key),
                )
                return created
            existing = current
    shutdown = getattr(created, "shutdown", None)
    if callable(shutdown):
        try:
            shutdown()
        except Exception:
            logger.exception(
                "Failed to shut down duplicate CDB session",
                extra=make_context(event="cdb.session.get_or_create", outcome="error", session_id=session_key),
            )
    logger.info(
        "Discarded duplicate CDB session after race",
        extra=make_context(event="cdb.session.get_or_create", outcome="duplicate", session_id=session_key),
    )
    return existing


def cleanup_sessions() -> None:
    with session_registry.lock:
        cdb_sessions = list(session_registry.cdb_sessions.values())
        uploads = list(session_registry.upload_sessions.values())
        session_registry.cdb_sessions.clear()
        session_registry.upload_sessions.clear()
        session_registry.analysis_sessions.clear()
        session_registry.cdb_creation_locks.clear()
    for session in cdb_sessions:
        shutdown = getattr(session, "shutdown", None)
        if callable(shutdown):
            try:
                shutdown()
            except Exception:
                pass
    for metadata in uploads:
        cleanup_temp_upload_file(metadata.temp_file_path)
    logger.info(
        "Process-wide session cleanup completed",
        extra=make_context(event="session.cleanup_all", outcome="success"),
    )


session_registry = SessionRegistry()
upload_runtime_config = create_upload_runtime_config()
