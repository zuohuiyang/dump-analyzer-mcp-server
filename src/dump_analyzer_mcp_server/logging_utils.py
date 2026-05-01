import atexit
import logging
import os
import queue
import tempfile
from dataclasses import dataclass
from datetime import datetime
from logging.handlers import QueueHandler, QueueListener, TimedRotatingFileHandler
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse


DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_LOG_RETENTION_DAYS = 14
DEFAULT_LOG_OUTPUT_PREVIEW_CHARS = 400
DEFAULT_LOG_MAX_TOTAL_SIZE_MB = 2048
DEFAULT_LOG_MAX_FILE_SIZE_MB = 100
BYTES_PER_MB = 1024 * 1024
DEFAULT_COMMAND_PREVIEW_CHARS = 120
LOG_FILE_NAME = "server.log"

_listener: Optional[QueueListener] = None
_listener_registered = False
_active_config: Optional["LoggingRuntimeConfig"] = None


@dataclass
class LoggingRuntimeConfig:
    log_dir: str
    log_level: str = DEFAULT_LOG_LEVEL
    log_retention_days: int = DEFAULT_LOG_RETENTION_DAYS
    log_keep_console: bool = True
    log_output_preview_chars: int = DEFAULT_LOG_OUTPUT_PREVIEW_CHARS
    log_max_total_size_mb: int = DEFAULT_LOG_MAX_TOTAL_SIZE_MB

    @property
    def log_max_total_size_bytes(self) -> int:
        return self.log_max_total_size_mb * BYTES_PER_MB


class CappedTimedRotatingFileHandler(TimedRotatingFileHandler):
    def __init__(self, *args, log_dir: str, max_total_size_bytes: int, **kwargs):
        self.log_dir = log_dir
        self.max_total_size_bytes = max_total_size_bytes
        self.max_file_size_bytes = DEFAULT_LOG_MAX_FILE_SIZE_MB * BYTES_PER_MB
        self._prune_emit_counter = 0
        super().__init__(*args, **kwargs)
        prune_log_dir_to_size_limit(self.log_dir, self.max_total_size_bytes, active_log_file=self.baseFilename)

    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        self._rollover_active_file_if_oversized()
        self._prune_emit_counter += 1
        if self._prune_emit_counter >= 20:
            self._prune_emit_counter = 0
            prune_log_dir_to_size_limit(self.log_dir, self.max_total_size_bytes, active_log_file=self.baseFilename)

    def doRollover(self) -> None:
        super().doRollover()
        prune_log_dir_to_size_limit(self.log_dir, self.max_total_size_bytes, active_log_file=self.baseFilename)

    def _rollover_active_file_if_oversized(self) -> None:
        try:
            current_size = os.path.getsize(self.baseFilename)
        except OSError:
            return
        if current_size <= self.max_file_size_bytes:
            return
        if self.stream:
            self.stream.close()
            self.stream = None
        archived_name = self.rotation_filename(self._build_size_rollover_name())
        os.replace(self.baseFilename, archived_name)
        if not self.delay:
            self.stream = self._open()
        prune_log_dir_to_size_limit(self.log_dir, self.max_total_size_bytes, active_log_file=self.baseFilename)

    def _build_size_rollover_name(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        candidate = f"{self.baseFilename}.size-{timestamp}"
        index = 1
        while os.path.exists(candidate):
            candidate = f"{self.baseFilename}.size-{timestamp}-{index}"
            index += 1
        return candidate


class ContextLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg: str, kwargs: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        extra = dict(self.extra)
        provided = kwargs.get("extra")
        if isinstance(provided, dict):
            extra.update(provided)
        kwargs["extra"] = extra
        return msg, kwargs


class ContextDefaultsFilter(logging.Filter):
    DEFAULTS = {
        "event": "-",
        "outcome": "-",
        "request_id": "-",
        "file_id": "-",
        "session_id": "-",
        "client_addr": "-",
        "command_preview": "-",
    }

    def filter(self, record: logging.LogRecord) -> bool:
        for key, value in self.DEFAULTS.items():
            if not hasattr(record, key):
                setattr(record, key, value)
        return True


def default_log_dir() -> str:
    program_data = os.getenv("PROGRAMDATA")
    if program_data:
        return str(Path(program_data) / "dump-analyzer-mcp-server" / "logs")
    return str(Path(tempfile.gettempdir()) / "dump-analyzer-mcp-server" / "logs")


def create_logging_runtime_config(
    *,
    log_dir: Optional[str] = None,
    log_level: str = DEFAULT_LOG_LEVEL,
    log_retention_days: int = DEFAULT_LOG_RETENTION_DAYS,
    log_keep_console: bool = True,
    log_output_preview_chars: int = DEFAULT_LOG_OUTPUT_PREVIEW_CHARS,
    log_max_total_size_mb: int = DEFAULT_LOG_MAX_TOTAL_SIZE_MB,
) -> LoggingRuntimeConfig:
    if log_retention_days <= 0:
        raise ValueError("log_retention_days must be greater than 0")
    if log_output_preview_chars <= 0:
        raise ValueError("log_output_preview_chars must be greater than 0")
    if log_max_total_size_mb <= 0:
        raise ValueError("log_max_total_size_mb must be greater than 0")
    normalized_level = normalize_log_level(log_level)
    resolved_log_dir = os.path.abspath((log_dir or "").strip() or default_log_dir())
    return LoggingRuntimeConfig(
        log_dir=resolved_log_dir,
        log_level=normalized_level,
        log_retention_days=log_retention_days,
        log_keep_console=log_keep_console,
        log_output_preview_chars=log_output_preview_chars,
        log_max_total_size_mb=log_max_total_size_mb,
    )


def normalize_log_level(level: str) -> str:
    normalized = (level or "").strip().upper()
    if normalized not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
        raise ValueError(f"Unsupported log level: {level}")
    return normalized


def ensure_log_dir(log_dir: str) -> str:
    path = Path(log_dir).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise RuntimeError(f"Log path is not a directory: {path}")
    return str(path)


def _iter_log_files(log_dir: str) -> list[Path]:
    directory = Path(log_dir)
    return sorted(
        [path for path in directory.glob(f"{LOG_FILE_NAME}*") if path.is_file()],
        key=lambda path: (path.stat().st_mtime, path.name),
    )


def get_log_dir_total_size_bytes(log_dir: str) -> int:
    return sum(path.stat().st_size for path in _iter_log_files(log_dir))


def prune_log_dir_to_size_limit(
    log_dir: str,
    max_total_size_bytes: int,
    *,
    active_log_file: Optional[str] = None,
) -> list[str]:
    removed: list[str] = []
    files = _iter_log_files(log_dir)
    total_size = sum(path.stat().st_size for path in files)
    active_path = os.path.abspath(active_log_file) if active_log_file else None
    for path in files:
        if total_size <= max_total_size_bytes:
            break
        if active_path and os.path.abspath(str(path)) == active_path:
            continue
        size = path.stat().st_size
        path.unlink(missing_ok=True)
        total_size -= size
        removed.append(str(path))
    return removed


def sanitize_path(path: Optional[str]) -> str:
    if not path:
        return "-"
    name = Path(path).name
    return name or "<redacted-path>"


def sanitize_url(url: Optional[str]) -> str:
    if not url:
        return "-"
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return "<redacted-url>"
    safe_path = parsed.path or "/"
    return f"{parsed.scheme}://{parsed.netloc}{safe_path}"


def sanitize_client_addr(client_addr: Optional[str]) -> str:
    if not client_addr:
        return "-"
    text = str(client_addr).strip()
    return text or "-"


def sanitize_command(command: Optional[str], limit: int = DEFAULT_COMMAND_PREVIEW_CHARS) -> str:
    if not command:
        return "-"
    normalized = " ".join(str(command).split())
    if len(normalized) <= limit:
        return normalized
    return f"{normalized[:limit]}...<truncated>"


def sanitize_output_text(text: Optional[str], limit: int = DEFAULT_LOG_OUTPUT_PREVIEW_CHARS) -> str:
    if not text:
        return "-"
    if limit <= 0 and _active_config is not None:
        limit = _active_config.log_output_preview_chars
    elif _active_config is not None and limit == DEFAULT_LOG_OUTPUT_PREVIEW_CHARS:
        limit = _active_config.log_output_preview_chars
    normalized = str(text).replace("\r\n", "\n").replace("\r", "\n")
    if len(normalized) <= limit:
        return normalized
    return f"{normalized[:limit]}...<truncated>"


def sanitize_exception_message(text: Optional[str], limit: int = DEFAULT_LOG_OUTPUT_PREVIEW_CHARS) -> str:
    return sanitize_output_text(text, limit=limit)


def make_context(
    *,
    event: Optional[str] = None,
    outcome: Optional[str] = None,
    request_id: Optional[str] = None,
    file_id: Optional[str] = None,
    session_id: Optional[str] = None,
    client_addr: Optional[str] = None,
    command_preview: Optional[str] = None,
) -> dict[str, str]:
    context: dict[str, str] = {}
    if event is not None:
        context["event"] = event
    if outcome is not None:
        context["outcome"] = outcome
    if request_id is not None:
        context["request_id"] = request_id
    if file_id is not None:
        context["file_id"] = file_id
    if session_id is not None:
        context["session_id"] = session_id
    if client_addr is not None:
        context["client_addr"] = sanitize_client_addr(client_addr)
    if command_preview is not None:
        context["command_preview"] = command_preview
    return context


def bind_context(logger: logging.Logger, **context: Optional[str]) -> ContextLoggerAdapter:
    return ContextLoggerAdapter(logger, make_context(**context))


def configure_logging(config: LoggingRuntimeConfig) -> LoggingRuntimeConfig:
    global _active_config, _listener, _listener_registered
    shutdown_logging()

    config.log_dir = ensure_log_dir(config.log_dir)
    formatter = logging.Formatter(
        fmt=(
            "%(asctime)s.%(msecs)03d [%(levelname)s] %(name)s "
            "event=%(event)s outcome=%(outcome)s request_id=%(request_id)s "
            "file_id=%(file_id)s session_id=%(session_id)s client_addr=%(client_addr)s "
            "command_preview=%(command_preview)s %(message)s"
        ),
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    defaults_filter = ContextDefaultsFilter()
    file_handler = CappedTimedRotatingFileHandler(
        filename=os.path.join(config.log_dir, LOG_FILE_NAME),
        when="midnight",
        backupCount=config.log_retention_days,
        encoding="utf-8",
        log_dir=config.log_dir,
        max_total_size_bytes=config.log_max_total_size_bytes,
    )
    file_handler.setFormatter(formatter)
    file_handler.addFilter(defaults_filter)

    handlers: list[logging.Handler] = [file_handler]
    if config.log_keep_console:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.addFilter(defaults_filter)
        handlers.append(console_handler)

    log_queue: queue.SimpleQueue[logging.LogRecord] = queue.SimpleQueue()
    queue_handler = QueueHandler(log_queue)
    queue_handler.addFilter(defaults_filter)

    root_logger = logging.getLogger()
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass
    root_logger.setLevel(getattr(logging, config.log_level))
    root_logger.addHandler(queue_handler)

    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.propagate = True

    _listener = QueueListener(log_queue, *handlers, respect_handler_level=True)
    _listener.start()
    _active_config = config
    if not _listener_registered:
        atexit.register(shutdown_logging)
        _listener_registered = True
    return config


def shutdown_logging() -> None:
    global _active_config, _listener
    if _listener is not None:
        _listener.stop()
        _listener = None
    _active_config = None
