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


@dataclass
class UploadSessionMetadata:
    """Metadata for uploaded DMP sessions."""

    session_id: str
    original_file_name: str
    temp_file_path: str
    status: UploadSessionStatus = UploadSessionStatus.PENDING
    created_at: datetime = field(default_factory=_utc_now)
    last_access_at: datetime = field(default_factory=_utc_now)
    expires_at: Optional[datetime] = None
    upload_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    is_analyzing: bool = False

    def mark_status(self, status: UploadSessionStatus) -> None:
        self.status = status

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
    """Unified registry for all session types."""

    cdb_sessions: Dict[str, object] = field(default_factory=dict)
    upload_sessions: Dict[str, UploadSessionMetadata] = field(default_factory=dict)
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    cdb_creation_locks: Dict[str, threading.Lock] = field(default_factory=dict, repr=False)


class UploadSessionLimitError(RuntimeError):
    """Raised when the active upload session limit is exceeded."""


_upload_storage_lock = threading.Lock()
_initialized_upload_dir: Optional[str] = None


def _load_positive_int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default

    try:
        value = int(raw)
    except ValueError:
        logger.warning("Invalid integer in %s=%r, using default=%d", name, raw, default)
        return default

    if value <= 0:
        logger.warning("Non-positive value in %s=%r, using default=%d", name, raw, default)
        return default

    return value


def _default_upload_dir() -> str:
    program_data = os.getenv("PROGRAMDATA")
    if program_data:
        return str(Path(program_data) / "mcp-windbg" / "uploads")

    return str(Path(tempfile.gettempdir()) / "mcp-windbg" / "uploads")


def load_upload_runtime_config() -> UploadRuntimeConfig:
    upload_dir = os.getenv("WINDBG_UPLOAD_DIR", "").strip() or _default_upload_dir()
    return UploadRuntimeConfig(
        upload_dir=os.path.abspath(upload_dir),
        max_upload_mb=_load_positive_int_env("WINDBG_MAX_UPLOAD_MB", DEFAULT_MAX_UPLOAD_MB),
        session_ttl_seconds=_load_positive_int_env("WINDBG_SESSION_TTL_SECONDS", DEFAULT_SESSION_TTL_SECONDS),
        max_active_sessions=_load_positive_int_env("WINDBG_MAX_ACTIVE_SESSIONS", DEFAULT_MAX_ACTIVE_SESSIONS),
    )


def ensure_controlled_upload_dir(upload_dir: str) -> str:
    path = Path(upload_dir).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise RuntimeError(f"Upload path is not a directory: {path}")

    probe_file = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path,
            prefix=".mcp_windbg_write_probe_",
            delete=False,
        ) as probe:
            probe_file = Path(probe.name)
            probe.write(b"ok")
    except OSError as exc:
        raise RuntimeError(f"Upload directory is not writable: {path}") from exc
    finally:
        if probe_file is not None:
            try:
                probe_file.unlink(missing_ok=True)
            except OSError:
                pass

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
    return Path(normalized).suffix if Path(normalized).suffix in SUPPORTED_DUMP_SIGNATURES else None


def is_supported_dump_filename(file_name: str) -> bool:
    return get_supported_dump_extension(file_name) is not None


def get_expected_dump_signatures(file_name: str) -> Tuple[bytes, ...]:
    extension = get_supported_dump_extension(file_name)
    if extension is None:
        raise ValueError("Only .dmp, .mdmp, and .hdmp files are supported")
    return SUPPORTED_DUMP_SIGNATURES[extension]


def sanitize_upload_file_name(file_name: str) -> str:
    base_name = os.path.basename(file_name.strip())
    if not base_name:
        return "upload.dmp"

    extension = get_supported_dump_extension(base_name)
    stem = base_name[: -len(extension)] if extension else base_name
    sanitized_stem = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in stem)
    sanitized_stem = sanitized_stem.strip("._-") or "upload"
    return f"{sanitized_stem}{extension or '.dmp'}"


def _build_upload_temp_file_path(session_id: str, file_name: str) -> str:
    safe_name = sanitize_upload_file_name(file_name)
    return os.path.join(upload_runtime_config.upload_dir, f"{session_id}-{safe_name}")


def build_upload_cdb_session_key(session_id: str) -> str:
    return f"upload:{session_id}"


def discard_cdb_creation_lock(session_key: str) -> None:
    with session_registry.lock:
        session_registry.cdb_creation_locks.pop(session_key, None)


def _active_upload_session_count_unlocked() -> int:
    return len(session_registry.upload_sessions)


def _is_upload_session_expired_unlocked(
    metadata: UploadSessionMetadata, now: Optional[datetime] = None
) -> bool:
    expires_at = metadata.expires_at
    if expires_at is None:
        return False

    return expires_at <= (now or _utc_now())


def _has_active_analysis_unlocked(metadata: UploadSessionMetadata) -> bool:
    return metadata.is_analyzing


def _create_upload_metadata(
    session_id: str,
    original_file_name: str,
    temp_file_path: str,
) -> UploadSessionMetadata:
    return UploadSessionMetadata(
        session_id=session_id,
        original_file_name=original_file_name,
        temp_file_path=temp_file_path,
        status=UploadSessionStatus.PENDING,
    )


def cleanup_temp_upload_file(path: str) -> None:
    try:
        Path(path).unlink(missing_ok=True)
    except OSError:
        pass


def _cleanup_upload_session_resources(
    metadata: UploadSessionMetadata,
    cdb_session: object,
    *,
    swallow_shutdown_errors: bool = False,
) -> None:
    if cdb_session is not None:
        shutdown = getattr(cdb_session, "shutdown", None)
        if callable(shutdown):
            if swallow_shutdown_errors:
                try:
                    shutdown()
                except Exception:
                    logger.exception(
                        "Failed to shut down CDB session while cleaning upload session %s",
                        metadata.session_id,
                    )
            else:
                shutdown()

    cleanup_temp_upload_file(metadata.temp_file_path)


def _get_cdb_creation_lock(session_key: str) -> threading.Lock:
    with session_registry.lock:
        creation_lock = session_registry.cdb_creation_locks.get(session_key)
        if creation_lock is None:
            creation_lock = threading.Lock()
            session_registry.cdb_creation_locks[session_key] = creation_lock
        return creation_lock


def _pop_upload_session_unlocked(session_id: str) -> Tuple[Optional[UploadSessionMetadata], object]:
    metadata = session_registry.upload_sessions.pop(session_id, None)
    session_key = build_upload_cdb_session_key(session_id)
    cdb_session = session_registry.cdb_sessions.pop(session_key, None)
    session_registry.cdb_creation_locks.pop(session_key, None)
    return metadata, cdb_session


def create_upload_session(file_name: str) -> Dict[str, object]:
    initialize_upload_storage()
    original_file_name = os.path.basename(file_name.strip())
    if not is_supported_dump_filename(original_file_name):
        raise ValueError("Only .dmp, .mdmp, and .hdmp files are supported")

    cleanup_expired_upload_sessions()

    with session_registry.lock:
        if _active_upload_session_count_unlocked() >= upload_runtime_config.max_active_sessions:
            raise UploadSessionLimitError(
                f"maximum active upload sessions reached ({upload_runtime_config.max_active_sessions})"
            )

        session_id = uuid.uuid4().hex
        temp_file_path = _build_upload_temp_file_path(session_id, original_file_name)
        metadata = _create_upload_metadata(session_id, original_file_name, temp_file_path)
        metadata.touch(upload_runtime_config.session_ttl_seconds)
        session_registry.upload_sessions[session_id] = metadata

        return {
            "session_id": session_id,
            "expires_at": metadata.expires_at.isoformat() if metadata.expires_at else "",
            "max_upload_mb": upload_runtime_config.max_upload_mb,
        }


def cleanup_expired_upload_sessions(now: Optional[datetime] = None) -> int:
    """Remove expired upload sessions and associated temporary files."""
    current = now or _utc_now()
    expired: list[tuple[str, UploadSessionMetadata, object]] = []

    with session_registry.lock:
        for session_id, metadata in list(session_registry.upload_sessions.items()):
            if not _is_upload_session_expired_unlocked(metadata, current):
                continue
            if not metadata.upload_lock.acquire(blocking=False):
                continue
            latest_metadata = session_registry.upload_sessions.get(session_id)
            if latest_metadata is None:
                release_upload_lock(metadata)
                continue
            metadata = latest_metadata
            if (
                not _is_upload_session_expired_unlocked(metadata, current)
                or _has_active_analysis_unlocked(metadata)
            ):
                release_upload_lock(metadata)
                continue
            popped_metadata, cdb_session = _pop_upload_session_unlocked(session_id)
            if popped_metadata is not None:
                expired.append((session_id, popped_metadata, cdb_session))
            else:
                release_upload_lock(metadata)

    removed = 0
    for session_id, metadata, cdb_session in expired:
        try:
            _cleanup_upload_session_resources(metadata, cdb_session, swallow_shutdown_errors=True)
        except Exception:
            with session_registry.lock:
                session_registry.upload_sessions.setdefault(session_id, metadata)
                if cdb_session is not None:
                    session_registry.cdb_sessions.setdefault(
                        build_upload_cdb_session_key(session_id), cdb_session
                    )
            logger.exception("Failed to clean up expired upload session: %s", session_id)
            continue
        finally:
            release_upload_lock(metadata)
        removed += 1

    return removed


def prepare_upload_session_for_upload(
    session_id: str, ttl_seconds: int
) -> Tuple[Optional[UploadSessionMetadata], str, str]:
    with session_registry.lock:
        metadata = session_registry.upload_sessions.get(session_id)

    if metadata is None:
        return None, "not_found", "Upload session not found"

    if not metadata.upload_lock.acquire(blocking=False):
        return None, "busy", "Upload session is already processing an upload"

    expired_metadata = None
    expired_cdb_session = None
    error_kind = "not_found"
    error_message = "Upload session not found"
    with session_registry.lock:
        latest_metadata = session_registry.upload_sessions.get(session_id)
        if latest_metadata is None:
            pass
        else:
            metadata = latest_metadata
            if _is_upload_session_expired_unlocked(metadata):
                expired_metadata, expired_cdb_session = _pop_upload_session_unlocked(session_id)
                error_kind = "expired"
                error_message = "Upload session has expired"
            elif metadata.status != UploadSessionStatus.PENDING:
                error_kind = "invalid_state"
                error_message = f"Upload session state is {metadata.status.value}, expected pending"
            else:
                metadata.mark_status(UploadSessionStatus.UPLOADING)
                metadata.touch(ttl_seconds)
                return metadata, "", ""

    try:
        if expired_metadata is not None:
            _cleanup_upload_session_resources(expired_metadata, expired_cdb_session, swallow_shutdown_errors=True)
    finally:
        metadata.upload_lock.release()

    return None, error_kind, error_message


def mark_upload_failed(metadata: UploadSessionMetadata) -> None:
    popped_metadata = None
    cdb_session = None
    with session_registry.lock:
        current = session_registry.upload_sessions.get(metadata.session_id)
        if current is metadata:
            popped_metadata, cdb_session = _pop_upload_session_unlocked(metadata.session_id)

    try:
        _cleanup_upload_session_resources(
            popped_metadata or metadata,
            cdb_session,
            swallow_shutdown_errors=True,
        )
    except Exception:
        logger.exception("Failed to clean up failed upload session: %s", metadata.session_id)


def mark_upload_completed(metadata: UploadSessionMetadata, ttl_seconds: int) -> None:
    with session_registry.lock:
        current = session_registry.upload_sessions.get(metadata.session_id)
        if current is metadata:
            metadata.mark_status(UploadSessionStatus.UPLOADED)
            metadata.touch(ttl_seconds)


def release_upload_lock(metadata: Optional[UploadSessionMetadata]) -> None:
    if metadata is None:
        return

    try:
        metadata.upload_lock.release()
    except RuntimeError:
        pass


def acquire_uploaded_session(
    session_id: str, ttl_seconds: int, *, for_analysis: bool = False
) -> Tuple[Optional[UploadSessionMetadata], Optional[str]]:
    expired_metadata = None
    expired_cdb_session = None

    with session_registry.lock:
        metadata = session_registry.upload_sessions.get(session_id)
        if metadata is None:
            return None, "Upload session not found"
        if _is_upload_session_expired_unlocked(metadata):
            if not _has_active_analysis_unlocked(metadata):
                expired_metadata, expired_cdb_session = _pop_upload_session_unlocked(session_id)
        elif metadata.status != UploadSessionStatus.UPLOADED:
            return None, f"Upload session state is {metadata.status.value}, expected uploaded"
        else:
            if for_analysis:
                if _has_active_analysis_unlocked(metadata):
                    return None, "Upload session is currently being analyzed"
                metadata.is_analyzing = True
            metadata.touch(ttl_seconds)
            return metadata, None

    if expired_metadata is not None:
        try:
            _cleanup_upload_session_resources(
                expired_metadata,
                expired_cdb_session,
                swallow_shutdown_errors=True,
            )
        except Exception:
            logger.exception("Failed to clean up expired upload session after access: %s", session_id)

    return None, "Upload session has expired"


def release_uploaded_session_after_analysis(metadata: Optional[UploadSessionMetadata], ttl_seconds: int) -> None:
    if metadata is None:
        return

    with session_registry.lock:
        current = session_registry.upload_sessions.get(metadata.session_id)
        if current is metadata:
            metadata.is_analyzing = False
            metadata.touch(ttl_seconds)


def close_upload_session(session_id: str) -> Tuple[Optional[Dict[str, object]], str, str]:
    with session_registry.lock:
        metadata = session_registry.upload_sessions.get(session_id)
        if metadata is None:
            return None, "not_found", "Upload session not found"
        if not metadata.upload_lock.acquire(blocking=False):
            return None, "busy", "Upload session is already processing an upload"

        latest_metadata = session_registry.upload_sessions.get(session_id)
        if latest_metadata is None:
            release_upload_lock(metadata)
            return None, "not_found", "Upload session not found"

        metadata = latest_metadata
        if _has_active_analysis_unlocked(metadata):
            release_upload_lock(metadata)
            return None, "invalid_state", "Upload session is currently being analyzed"

        popped_metadata, cdb_session = _pop_upload_session_unlocked(session_id)

    if popped_metadata is None:
        release_upload_lock(metadata)
        return None, "not_found", "Upload session not found"

    try:
        _cleanup_upload_session_resources(popped_metadata, cdb_session, swallow_shutdown_errors=True)
        return {
            "session_id": session_id,
            "status": "closed",
        }, "", ""
    finally:
        release_upload_lock(popped_metadata)


def get_cdb_session(session_key: str) -> object:
    with session_registry.lock:
        return session_registry.cdb_sessions.get(session_key)


def get_or_create_cdb_session(session_key: str, factory):
    existing = get_cdb_session(session_key)
    if existing is not None:
        return existing

    with _get_cdb_creation_lock(session_key):
        existing = get_cdb_session(session_key)
        if existing is not None:
            return existing

        created = factory()

        with session_registry.lock:
            existing = session_registry.cdb_sessions.get(session_key)
            if existing is None:
                session_registry.cdb_sessions[session_key] = created
                return created

    shutdown = getattr(created, "shutdown", None)
    if callable(shutdown):
        try:
            shutdown()
        except Exception:
            logger.exception("Failed to shut down duplicate CDB session for key %s", session_key)

    return existing


def pop_cdb_session(session_key: str) -> object:
    with session_registry.lock:
        session = session_registry.cdb_sessions.pop(session_key, None)
        session_registry.cdb_creation_locks.pop(session_key, None)
        return session


def cleanup_sessions() -> None:
    with session_registry.lock:
        cdb_sessions = list(session_registry.cdb_sessions.values())
        upload_sessions = list(session_registry.upload_sessions.values())
        session_registry.cdb_sessions.clear()
        session_registry.upload_sessions.clear()
        session_registry.cdb_creation_locks.clear()

    for session in cdb_sessions:
        shutdown = getattr(session, "shutdown", None)
        if callable(shutdown):
            try:
                shutdown()
            except Exception:
                pass

    for metadata in upload_sessions:
        cleanup_temp_upload_file(metadata.temp_file_path)


session_registry = SessionRegistry()
upload_runtime_config = load_upload_runtime_config()
