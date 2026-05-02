import asyncio
import atexit
import errno
import json
import logging
import threading
import time
from contextlib import asynccontextmanager
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

from mcp.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.shared.exceptions import McpError
from mcp.types import ErrorData, TextContent, Tool, INVALID_PARAMS, INTERNAL_ERROR
from pydantic import BaseModel, Field, model_validator

from .logging_utils import (
    bind_context,
    make_context,
    normalize_output_line_for_log,
    sanitize_client_addr,
    sanitize_command,
    sanitize_exception_message,
    sanitize_path,
    sanitize_url,
)
from . import upload_sessions
from .cdb_session import CDBError, CDBSession
from .upload_sessions import UploadSessionStatus

logger = logging.getLogger(__name__)

DEFAULT_MAX_UPLOAD_MB = upload_sessions.DEFAULT_MAX_UPLOAD_MB
DEFAULT_SESSION_TTL_SECONDS = upload_sessions.DEFAULT_SESSION_TTL_SECONDS
DEFAULT_MAX_ACTIVE_SESSIONS = upload_sessions.DEFAULT_MAX_ACTIVE_SESSIONS
DEFAULT_UPLOAD_CLEANUP_INTERVAL_SECONDS = 30
UPLOAD_ROUTE_PATH = "/uploads/dumps/{file_id}"
SERVER_NAME = "dump-analyzer-mcp-server"
UPLOAD_ERROR_TOO_LARGE = "UPLOAD_TOO_LARGE"
UPLOAD_ERROR_INVALID_FORMAT = "INVALID_DUMP_FORMAT"
UPLOAD_ERROR_INSUFFICIENT_STORAGE = "INSUFFICIENT_STORAGE"
UPLOAD_ERROR_WRITE_FAILED = "UPLOAD_WRITE_FAILED"
UPLOAD_ERROR_SESSION_NOT_FOUND = "UPLOAD_SESSION_NOT_FOUND"
UPLOAD_ERROR_INVALID_STATE = "UPLOAD_SESSION_INVALID_STATE"
UPLOAD_ERROR_TOO_MANY_SESSIONS = "UPLOAD_TOO_MANY_SESSIONS"
UPLOAD_ERROR_UPLOAD_FAILED = "UPLOAD_FAILED"
UPLOAD_ERROR_URL_UNAVAILABLE = "UPLOAD_URL_UNAVAILABLE"
UPLOAD_ERROR_SIZE_MISMATCH = "UPLOAD_SIZE_MISMATCH"
DEFAULT_SYMBOL_PATH = r"srv*c:\symbols*https://msdl.microsoft.com/download/symbols"

DANGEROUS_PATTERNS: Tuple[str, ...] = (
    ".shell",
    "|",
    "<",
    ">",
    ".create",
    ".attach",
    ".kill",
    ".write_mem",
    ".remote",
    ".server",
)
DANGEROUS_PREFIXES: Tuple[str, ...] = ("reg", "sc")

session_registry = upload_sessions.session_registry
upload_runtime_config = upload_sessions.upload_runtime_config
public_base_url = ""
_running_requests: dict[str, threading.Event] = {}
_running_lock = threading.Lock()


def _request_id_from_ctx(ctx) -> str:
    if ctx is None:
        return "-"
    request_id = getattr(ctx, "request_id", None)
    if request_id is None:
        return "-"
    return str(request_id)


def _request_context_meta(server: Server) -> dict[str, str]:
    ctx = _try_get_request_context(server)
    return make_context(request_id=_request_id_from_ctx(ctx))


def _client_addr_from_request(request) -> str:
    client = getattr(request, "client", None)
    if client is None:
        return "-"
    host = getattr(client, "host", None)
    port = getattr(client, "port", None)
    if host and port is not None:
        return sanitize_client_addr(f"{host}:{port}")
    if host:
        return sanitize_client_addr(host)
    return "-"


class UploadWorkflowError(RuntimeError):
    def __init__(
        self,
        *,
        code: str,
        message: str,
        remediation: str,
        details: Optional[Dict[str, object]] = None,
        http_status: int = 400,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.remediation = remediation
        self.details = details or {}
        self.http_status = http_status

    def to_payload(self) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "code": self.code,
            "message": self.message,
            "remediation": self.remediation,
        }
        if self.details:
            payload["details"] = self.details
        return payload


class PrepareDumpUploadParams(BaseModel):
    file_size: int = Field(description="File size in bytes")
    file_name: str = Field(description="Original file name")

    @model_validator(mode="after")
    def validate_payload(self):
        if self.file_size <= 0:
            raise ValueError("file_size must be greater than 0")
        if not upload_sessions.is_supported_dump_filename(self.file_name):
            raise ValueError("Only .dmp, .mdmp, and .hdmp files are supported")
        return self


class StartAnalysisSessionParams(BaseModel):
    file_id: str = Field(description="File ID returned after a successful upload")
    sym_noisy: bool = Field(
        default=True,
        description="Enable !sym noisy for this analysis session before running later commands",
    )


class ExecuteWindbgCommandParams(BaseModel):
    session_id: str = Field(description="Analysis session ID")
    command: str = Field(description="CDB command to execute")
    timeout: int = Field(
        default=1800,
        description="Command timeout in seconds; if the command has not completed within this period, it returns status=timeout",
    )

    @model_validator(mode="after")
    def validate_timeout(self):
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than 0")
        return self


class StartAsyncWindbgCommandParams(BaseModel):
    session_id: str = Field(description="Analysis session ID")
    command: str = Field(description="CDB command to execute asynchronously")


class GetAsyncWindbgCommandStatusParams(BaseModel):
    session_id: str = Field(description="Analysis session ID")
    command_id: str = Field(description="Command ID returned by start_async_windbg_command")


class GetAsyncWindbgCommandResultParams(BaseModel):
    session_id: str = Field(description="Analysis session ID")
    command_id: str = Field(description="Command ID returned by start_async_windbg_command")
    wait_timeout: int = Field(
        default=0,
        description="Optional wait timeout in seconds. Use 0 to return immediately if the command is still running.",
    )

    @model_validator(mode="after")
    def validate_wait_timeout(self):
        if self.wait_timeout < 0:
            raise ValueError("wait_timeout must be greater than or equal to 0")
        return self


class CloseAnalysisSessionParams(BaseModel):
    session_id: str = Field(description="Session ID")


async def upload_session_cleanup_loop(interval_seconds: int = DEFAULT_UPLOAD_CLEANUP_INTERVAL_SECONDS) -> None:
    safe_interval = max(1, interval_seconds)
    while True:
        try:
            removed = upload_sessions.cleanup_expired_upload_sessions()
            if removed:
                logger.info(
                    "Expired upload sessions removed: %s",
                    removed,
                    extra=make_context(event="upload.cleanup_loop", outcome="success"),
                )
        except Exception:
            logger.exception(
                "Unexpected error during upload session cleanup loop",
                extra=make_context(event="upload.cleanup_loop", outcome="error"),
            )
        await asyncio.sleep(safe_interval)


def build_upload_path(file_id: str) -> str:
    return UPLOAD_ROUTE_PATH.format(file_id=file_id)


def configure_public_base_url(
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    explicit_base_url: Optional[str] = None,
) -> str:
    global public_base_url
    configured = (explicit_base_url or "").strip().rstrip("/")
    public_base_url = configured or f"http://{host}:{port}"
    return public_base_url


def build_upload_url(file_id: str) -> str:
    parsed = urlparse(public_base_url)
    hostname = (parsed.hostname or "").strip().lower()
    if not parsed.scheme or not parsed.netloc or hostname in {"0.0.0.0", "::", "localhost", "127.0.0.1"}:
        raise UploadWorkflowError(
            code=UPLOAD_ERROR_URL_UNAVAILABLE,
            message="upload URL cannot be derived from missing or non-routable public base URL",
            remediation="Configure --public-base-url with a client-reachable IP or hostname.",
            details={"public_base_url": public_base_url},
            http_status=500,
        )
    return f"{public_base_url}{build_upload_path(file_id)}"


def _validate_dangerous_command(command: str) -> Optional[str]:
    stripped = command.strip()
    lowered = stripped.lower()
    for token in DANGEROUS_PATTERNS:
        if token in lowered:
            return token
    for prefix in DANGEROUS_PREFIXES:
        if lowered == prefix or lowered.startswith(f"{prefix} "):
            return prefix
    if lowered.startswith(".dump "):
        return ".dump(path)"
    return None


def create_upload_session(file_name: str, file_size: int) -> Dict[str, object]:
    try:
        payload = upload_sessions.create_upload_session(file_name, file_size)
    except upload_sessions.UploadSessionLimitError as exc:
        logger.warning(
            "Upload session rejected: %s",
            sanitize_exception_message(str(exc)),
            extra=make_context(event="upload.prepare", outcome="rejected"),
        )
        raise UploadWorkflowError(
            code=UPLOAD_ERROR_TOO_MANY_SESSIONS,
            message=str(exc),
            remediation="Close or wait for existing upload sessions before creating another one.",
            http_status=409,
        ) from exc
    except ValueError as exc:
        logger.warning(
            "Upload session validation failed: %s",
            sanitize_exception_message(str(exc)),
            extra=make_context(event="upload.prepare", outcome="invalid"),
        )
        raise UploadWorkflowError(
            code=UPLOAD_ERROR_INVALID_FORMAT,
            message=str(exc),
            remediation="Use a supported dump filename with .dmp, .mdmp, or .hdmp extension.",
        ) from exc
    file_id = payload["file_id"]
    try:
        payload["upload_url"] = build_upload_url(file_id)
    except UploadWorkflowError:
        metadata = session_registry.upload_sessions.get(file_id)
        if metadata is not None:
            upload_sessions.mark_upload_failed(metadata)
        raise
    logger.info(
        "Prepared upload session for %s",
        sanitize_path(file_name),
        extra=make_context(
            event="upload.prepare",
            outcome="success",
            file_id=file_id,
        ),
    )
    return payload


async def _send_progress(
    session,
    request_id: str,
    phase: str,
    event: str,
    message: Optional[str] = None,
) -> None:
    payload = {
        "phase": phase,
        "event": event,
    }
    if message is not None:
        payload["message"] = message
    await session.send_progress_notification(
        progress_token=request_id,
        progress=0.0,
        total=None,
        message=json.dumps(payload, ensure_ascii=False),
        related_request_id=request_id,
    )


def _try_get_request_context(server: Server):
    try:
        return server.request_context
    except LookupError:
        return None


def _upload_error_payload(
    code: str,
    message: str,
    *,
    remediation: str,
    details: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    payload: Dict[str, object] = {"code": code, "message": message, "remediation": remediation}
    if details:
        payload["details"] = details
    return payload


def _build_suggested_next_step(result: Dict[str, object]) -> Optional[str]:
    status = str(result.get("status") or "")
    if status == "timeout":
        if result.get("first_output_delay_ms") is None:
            return "Retry with a larger timeout or run a lighter command first, such as .lastevent or .ecxr;kv."
        return "Review the partial output, then retry with a larger timeout or continue with a lighter follow-up command."
    if status in {"busy", "queued"}:
        running_command = result.get("running_command") or "the previous command"
        return f"Wait for {running_command} to finish, then retry this command or use the async status/result tools."
    if status == "cancelled":
        return "Retry the command if you still need the full output."
    return None


def _build_pending_command_payload(args_command: str, pending: Dict[str, object], status: str) -> Dict[str, object]:
    payload = {
        "success": False,
        "status": status,
        "command": args_command,
        "output": "",
        "execution_time_ms": 0,
        "cancelled": False,
        "timed_out": False,
        "first_output_delay_ms": None,
        "queue_wait_ms": 0,
        "running_command_id": pending.get("request_id"),
        "running_command": pending.get("command"),
        "running_status": pending.get("status"),
    }
    suggested_next_step = _build_suggested_next_step(payload)
    if suggested_next_step:
        payload["suggested_next_step"] = suggested_next_step
    return payload


async def _stream_upload_to_file(
    request,
    target_path: str,
    max_bytes: int,
    expected_signatures: Tuple[bytes, ...],
) -> int:
    total_size = 0
    header = b""
    pending = bytearray()

    with open(target_path, "wb") as f:
        async for chunk in request.stream():
            if not chunk:
                continue
            total_size += len(chunk)
            if total_size > max_bytes:
                raise ValueError(UPLOAD_ERROR_TOO_LARGE)
            if len(header) < 4:
                pending.extend(chunk)
                if len(pending) < 4:
                    continue
                header = bytes(pending[:4])
                if header not in expected_signatures:
                    raise ValueError(UPLOAD_ERROR_INVALID_FORMAT)
                f.write(pending)
                pending.clear()
                continue
            f.write(chunk)

    if len(header) < 4:
        raise ValueError(UPLOAD_ERROR_INVALID_FORMAT)

    return total_size


async def serve_http(
    host: str = "127.0.0.1",
    port: int = 8000,
    cdb_path: Optional[str] = None,
    symbols_path: Optional[str] = None,
    timeout: int = 1800,
    verbose: bool = False,
    public_base_url_override: Optional[str] = None,
    upload_dir: Optional[str] = None,
    max_upload_mb: int = DEFAULT_MAX_UPLOAD_MB,
    session_ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    max_active_sessions: int = DEFAULT_MAX_ACTIVE_SESSIONS,
) -> None:
    import uvicorn

    global upload_runtime_config
    upload_runtime_config = upload_sessions.configure_upload_runtime(
        upload_dir=upload_dir,
        max_upload_mb=max_upload_mb,
        session_ttl_seconds=session_ttl_seconds,
        max_active_sessions=max_active_sessions,
    )
    configure_public_base_url(host=host, port=port, explicit_base_url=public_base_url_override)
    app = create_http_app(
        cdb_path=cdb_path,
        symbols_path=symbols_path,
        timeout=timeout,
        verbose=verbose,
        public_base_url_override=public_base_url_override,
    )

    logger.info(
        "Starting %s on %s:%s",
        SERVER_NAME,
        host,
        port,
        extra=make_context(event="server.start", outcome="starting"),
    )
    logger.info(
        "Server configuration prepared: public_base_url=%s upload_dir=%s max_active_sessions=%s session_ttl_seconds=%s",
        sanitize_url(public_base_url),
        sanitize_path(upload_runtime_config.upload_dir),
        upload_runtime_config.max_active_sessions,
        upload_runtime_config.session_ttl_seconds,
        extra=make_context(event="server.start", outcome="configured"),
    )

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="debug" if verbose else "info",
        log_config=None,
    )
    server_instance = uvicorn.Server(config)
    try:
        await server_instance.serve()
    finally:
        logger.info(
            "Server stopped",
            extra=make_context(event="server.stop", outcome="completed"),
        )


def create_http_app(
    cdb_path: Optional[str] = None,
    symbols_path: Optional[str] = None,
    timeout: int = 1800,
    verbose: bool = False,
    public_base_url_override: Optional[str] = None,
):
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route
    from starlette.types import Receive, Scope, Send

    if public_base_url_override:
        configure_public_base_url(explicit_base_url=public_base_url_override)

    server = _create_server(cdb_path, symbols_path, timeout, verbose)
    session_manager = StreamableHTTPSessionManager(app=server)

    async def handle_streamable_http(scope: Scope, receive: Receive, send: Send) -> None:
        await session_manager.handle_request(scope, receive, send)

    def upload_error(
        status_code: int,
        code: str,
        message: str,
        *,
        remediation: str,
        details: Optional[Dict[str, object]] = None,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status_code,
            content={"error": _upload_error_payload(code, message, remediation=remediation, details=details)},
        )

    async def upload_dump(request: Request) -> JSONResponse:
        file_id = request.path_params["file_id"]
        client_addr = _client_addr_from_request(request)
        request_logger = bind_context(
            logger,
            event="upload.put",
            file_id=file_id,
            client_addr=client_addr,
        )
        metadata, error_kind, error_message = upload_sessions.prepare_upload_session_for_upload(
            file_id, upload_runtime_config.session_ttl_seconds
        )
        if metadata is None:
            if error_kind in {"busy", "invalid_state"}:
                request_logger.warning(
                    "Upload rejected before start: %s",
                    sanitize_exception_message(error_message),
                    extra=make_context(outcome="invalid"),
                )
                return upload_error(
                    409,
                    UPLOAD_ERROR_INVALID_STATE,
                    error_message,
                    remediation="Create a new upload session if the previous upload is stuck, or wait and retry.",
                    details={"file_id": file_id},
                )
            request_logger.warning(
                "Upload target not found: %s",
                sanitize_exception_message(error_message),
                extra=make_context(outcome="missing"),
            )
            return upload_error(
                404,
                UPLOAD_ERROR_SESSION_NOT_FOUND,
                error_message,
                remediation="Create a new upload session before uploading.",
                details={"file_id": file_id},
            )

        def fail_upload(
            status_code: int,
            code: str,
            message: str,
            *,
            remediation: str,
            details: Optional[Dict[str, object]] = None,
            log_unexpected: bool = False,
        ) -> JSONResponse:
            upload_sessions.mark_upload_failed(metadata)
            if log_unexpected:
                request_logger.exception(
                    "Unexpected upload failure",
                    extra=make_context(outcome="error"),
                )
            else:
                request_logger.warning(
                    "%s",
                    sanitize_exception_message(message),
                    extra=make_context(outcome="failed"),
                )
            return upload_error(status_code, code, message, remediation=remediation, details=details)

        try:
            request_logger.info(
                "Upload started for %s",
                sanitize_path(metadata.original_file_name),
                extra=make_context(outcome="started"),
            )
            max_bytes = upload_runtime_config.max_upload_mb * 1024 * 1024
            expected_signatures = upload_sessions.get_expected_dump_signatures(metadata.original_file_name)
            total_size = await _stream_upload_to_file(
                request,
                metadata.temp_file_path,
                max_bytes,
                expected_signatures,
            )
            size_error = upload_sessions.mark_upload_completed(
                metadata,
                upload_runtime_config.session_ttl_seconds,
                total_size,
            )
            if size_error:
                return fail_upload(
                    400,
                    UPLOAD_ERROR_SIZE_MISMATCH,
                    size_error,
                    remediation="Retry upload with the exact same bytes and file_size declared in prepare_dump_upload.",
                    details={"file_id": file_id},
                )
        except ValueError as exc:
            if str(exc) == UPLOAD_ERROR_TOO_LARGE:
                return fail_upload(
                    413,
                    UPLOAD_ERROR_TOO_LARGE,
                    f"Upload exceeds limit ({upload_runtime_config.max_upload_mb}MB)",
                    remediation="Use a smaller dump file or increase --max-upload-mb on the server.",
                    details={"file_id": file_id, "max_upload_mb": upload_runtime_config.max_upload_mb},
                )
            return fail_upload(
                400,
                UPLOAD_ERROR_INVALID_FORMAT,
                "Invalid dump upload payload",
                remediation="Upload the raw bytes of a supported .dmp, .mdmp, or .hdmp file.",
                details={"file_id": file_id},
            )
        except OSError as exc:
            if exc.errno == errno.ENOSPC:
                return fail_upload(
                    507,
                    UPLOAD_ERROR_INSUFFICIENT_STORAGE,
                    "Insufficient storage space",
                    remediation="Free disk space on the server upload directory and retry.",
                    details={"file_id": file_id},
                )
            return fail_upload(
                500,
                UPLOAD_ERROR_WRITE_FAILED,
                f"Upload write failure: {exc}",
                remediation="Check server upload directory permissions and storage health, then retry.",
                details={"file_id": file_id},
            )
        except asyncio.CancelledError:
            upload_sessions.mark_upload_failed(metadata)
            request_logger.warning(
                "Upload cancelled",
                extra=make_context(outcome="cancelled"),
            )
            raise
        except Exception:
            return fail_upload(
                500,
                UPLOAD_ERROR_UPLOAD_FAILED,
                "Unexpected upload failure",
                remediation="Retry the upload. If the problem persists, inspect server logs.",
                details={"file_id": file_id},
                log_unexpected=True,
            )
        finally:
            upload_sessions.release_upload_lock(metadata)

        request_logger.info(
            "Upload completed with %s bytes",
            total_size,
            extra=make_context(outcome="success"),
        )
        return JSONResponse(
            status_code=201,
            content={"file_id": file_id, "status": UploadSessionStatus.UPLOADED.value, "size_bytes": total_size},
        )

    @asynccontextmanager
    async def lifespan(app: Starlette):
        cleanup_task = asyncio.create_task(upload_session_cleanup_loop(DEFAULT_UPLOAD_CLEANUP_INTERVAL_SECONDS))
        try:
            async with session_manager.run():
                logger.info(
                    "HTTP application lifespan started",
                    extra=make_context(event="server.lifespan", outcome="started"),
                )
                yield
        finally:
            cleanup_task.cancel()
            try:
                await cleanup_task
            except asyncio.CancelledError:
                pass
            cleanup_sessions()
            logger.info(
                "HTTP application lifespan stopped",
                extra=make_context(event="server.lifespan", outcome="stopped"),
            )

    return Starlette(
        debug=verbose,
        routes=[
            Mount("/mcp", app=handle_streamable_http),
            Route("/uploads/dumps/{file_id}", endpoint=upload_dump, methods=["PUT"]),
        ],
        lifespan=lifespan,
    )


def _create_server(
    cdb_path: Optional[str] = None,
    symbols_path: Optional[str] = None,
    timeout: int = 1800,
    verbose: bool = False,
) -> Server:
    import mcp.types as types

    server = Server(SERVER_NAME)

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="prepare_dump_upload",
                description="Prepare a crash dump upload and return a pre-signed upload URL.",
                inputSchema=PrepareDumpUploadParams.model_json_schema(),
            ),
            Tool(
                name="start_analysis_session",
                description=(
                    "Start a crash dump analysis session and load the dump file and symbols. "
                    "sym_noisy defaults to true so the session enables !sym noisy before later commands. "
                    "For hosts without visible streaming progress, prefer lighter follow-up commands first, "
                    "such as .lastevent or .ecxr;kv, before heavier analysis."
                ),
                inputSchema=StartAnalysisSessionParams.model_json_schema(),
            ),
            Tool(
                name="execute_windbg_command",
                description=(
                    "Execute any CDB command in an analysis session and stream the raw output. "
                    "Prefer this synchronous tool for lighter commands such as .lastevent, k, and lmv m <module>. "
                    "Use the async command tools for heavier commands such as .reload /f or !analyze -v. "
                    "On timeout, the server returns structured status instead of a tool error."
                ),
                inputSchema=ExecuteWindbgCommandParams.model_json_schema(),
            ),
            Tool(
                name="start_async_windbg_command",
                description=(
                    "Start a CDB command asynchronously and return a command_id. "
                    "Use this for heavy commands such as .reload /f, .ecxr;kv on a cold symbol cache, or !analyze -v."
                ),
                inputSchema=StartAsyncWindbgCommandParams.model_json_schema(),
            ),
            Tool(
                name="get_async_windbg_command_status",
                description="Get the current status of an asynchronously running CDB command.",
                inputSchema=GetAsyncWindbgCommandStatusParams.model_json_schema(),
            ),
            Tool(
                name="get_async_windbg_command_result",
                description="Get the result of an asynchronously running CDB command, optionally waiting a short time.",
                inputSchema=GetAsyncWindbgCommandResultParams.model_json_schema(),
            ),
            Tool(
                name="close_analysis_session",
                description="Close the analysis session, release all resources, and delete temporary files.",
                inputSchema=CloseAnalysisSessionParams.model_json_schema(),
            ),
        ]

    async def _send_tool_progress(phase: str, message: str) -> None:
        ctx = _try_get_request_context(server)
        if ctx is None:
            return
        await _send_progress(ctx.session, str(ctx.request_id), phase, "lifecycle", message)

    @server.call_tool()
    async def call_tool(name, arguments: dict) -> list[TextContent]:
        base_context = _request_context_meta(server)
        tool_logger = bind_context(
            logger,
            event="mcp.call_tool",
            request_id=base_context["request_id"],
        )
        try:
            if name == "prepare_dump_upload":
                args = PrepareDumpUploadParams(**arguments)
                payload = create_upload_session(args.file_name, args.file_size)
                tool_logger.info(
                    "Tool completed: %s",
                    name,
                    extra=make_context(
                        event="mcp.call_tool",
                        outcome="success",
                        request_id=base_context["request_id"],
                        file_id=str(payload["file_id"]),
                    ),
                )
                return [TextContent(type="text", text=json.dumps(payload))]

            if name == "start_analysis_session":
                args = StartAnalysisSessionParams(**arguments)
                start_logger = bind_context(
                    logger,
                    event="analysis.start",
                    request_id=base_context["request_id"],
                    file_id=args.file_id,
                )
                metadata, error_message = upload_sessions.acquire_uploaded_file_for_analysis(
                    args.file_id, upload_runtime_config.session_ttl_seconds
                )
                if metadata is None:
                    start_logger.warning(
                        "Analysis start rejected: %s",
                        sanitize_exception_message(error_message),
                        extra=make_context(outcome="invalid"),
                    )
                    raise McpError(
                        ErrorData(code=INVALID_PARAMS, message=f"{UPLOAD_ERROR_INVALID_STATE}: {error_message}")
                    )

                analysis, error_message = upload_sessions.get_or_create_analysis_session(
                    args.file_id, upload_runtime_config.session_ttl_seconds
                )
                if analysis is None:
                    start_logger.warning(
                        "Analysis session creation failed: %s",
                        sanitize_exception_message(error_message),
                        extra=make_context(outcome="invalid"),
                    )
                    raise McpError(
                        ErrorData(code=INVALID_PARAMS, message=f"{UPLOAD_ERROR_INVALID_STATE}: {error_message}")
                    )

                session = upload_sessions.get_or_create_cdb_session(
                    upload_sessions.build_upload_cdb_session_key(analysis.session_id),
                    lambda: CDBSession(
                        dump_path=metadata.temp_file_path,
                        cdb_path=cdb_path,
                        symbols_path=symbols_path or DEFAULT_SYMBOL_PATH,
                        timeout=timeout,
                        verbose=verbose,
                        log_context={
                            "request_id": base_context["request_id"],
                            "file_id": args.file_id,
                            "session_id": analysis.session_id,
                        },
                    ),
                )
                if args.sym_noisy:
                    try:
                        session.ensure_symbol_diagnostics(timeout=timeout)
                    except CDBError as exc:
                        start_logger.exception(
                            "Failed to enable symbol diagnostics: %s",
                            sanitize_exception_message(str(exc)),
                            extra=make_context(outcome="error"),
                        )
                        raise McpError(
                            ErrorData(
                                code=INTERNAL_ERROR,
                                message="Failed to enable symbol diagnostics for the new analysis session.",
                            )
                        ) from exc
                payload = {"session_id": analysis.session_id, "file_id": args.file_id, "status": "ready"}
                start_logger.info(
                    "Analysis session ready",
                    extra=make_context(
                        outcome="success",
                        request_id=base_context["request_id"],
                        file_id=args.file_id,
                        session_id=analysis.session_id,
                    ),
                )
                return [TextContent(type="text", text=json.dumps(payload))]

            if name == "execute_windbg_command":
                args = ExecuteWindbgCommandParams(**arguments)
                command_preview = sanitize_command(args.command)
                command_logger = bind_context(
                    logger,
                    event="analysis.execute",
                    request_id=base_context["request_id"],
                    session_id=args.session_id,
                    command_preview=command_preview,
                )
                blocked = _validate_dangerous_command(args.command)
                if blocked:
                    blocked_preview = f"<blocked:{blocked}>"
                    command_logger.warning(
                        "Dangerous command blocked by policy",
                        extra=make_context(outcome="blocked", command_preview=blocked_preview),
                    )
                    raise McpError(
                        ErrorData(
                            code=INVALID_PARAMS,
                            message=(
                                "DANGEROUS_COMMAND_BLOCKED: "
                                + json.dumps(
                                    {
                                        "message": "Command blocked by security policy",
                                        "blocked_token": blocked,
                                        "command": args.command,
                                    }
                                )
                            ),
                        )
                    )

                analysis, metadata, error_message = upload_sessions.acquire_analysis_session(
                    args.session_id, upload_runtime_config.session_ttl_seconds
                )
                if analysis is None or metadata is None:
                    command_logger.warning(
                        "Analysis session acquisition failed: %s",
                        sanitize_exception_message(error_message),
                        extra=make_context(outcome="missing"),
                    )
                    raise McpError(
                        ErrorData(code=INVALID_PARAMS, message=f"{UPLOAD_ERROR_SESSION_NOT_FOUND}: {error_message}")
                    )

                request_id = base_context["request_id"]
                try:
                    session = upload_sessions.get_or_create_cdb_session(
                        upload_sessions.build_upload_cdb_session_key(args.session_id),
                        lambda: CDBSession(
                            dump_path=metadata.temp_file_path,
                            cdb_path=cdb_path,
                            symbols_path=symbols_path or DEFAULT_SYMBOL_PATH,
                            timeout=timeout,
                            verbose=verbose,
                            log_context={
                                "request_id": base_context["request_id"],
                                "file_id": metadata.file_id,
                                "session_id": args.session_id,
                            },
                        ),
                    )
                    pending = session.get_pending_command()
                    if pending is not None:
                        command_logger.info(
                            "Synchronous command rejected because another command is still running",
                            extra=make_context(
                                outcome="busy",
                                request_id=request_id,
                                file_id=metadata.file_id,
                                session_id=args.session_id,
                                command_preview=command_preview,
                            ),
                        )
                        payload = _build_pending_command_payload(args.command, pending, "busy")
                        return [TextContent(type="text", text=json.dumps(payload))]
                    ctx = _try_get_request_context(server)
                    request_id = str(ctx.request_id) if ctx is not None else request_id
                    loop = asyncio.get_running_loop()
                    cancel_event = threading.Event()
                    with _running_lock:
                        _running_requests[request_id] = cancel_event

                    command_logger.info(
                        "Command execution queued",
                        extra=make_context(
                            outcome="queued",
                            request_id=request_id,
                            file_id=metadata.file_id,
                            session_id=args.session_id,
                            command_preview=command_preview,
                        ),
                    )
                    await _send_tool_progress("queued", f"Running command: {args.command}")

                    first_output_logged = False

                    def on_output(line: str) -> None:
                        nonlocal first_output_logged
                        if not first_output_logged:
                            first_output_logged = True
                            command_logger.info(
                                "First command output observed: %s",
                                normalize_output_line_for_log(line),
                                extra=make_context(
                                    outcome="streaming",
                                    request_id=request_id,
                                    file_id=metadata.file_id,
                                    session_id=args.session_id,
                                    command_preview=command_preview,
                                ),
                            )
                        if ctx is None:
                            return
                        fut = asyncio.run_coroutine_threadsafe(
                            _send_progress(ctx.session, request_id, "running", "output", f"{line}\n"),
                            loop,
                        )
                        try:
                            fut.result(timeout=5)
                        except Exception:
                            pass

                    def on_heartbeat() -> None:
                        if ctx is None:
                            return
                        fut = asyncio.run_coroutine_threadsafe(
                            _send_progress(ctx.session, request_id, "running", "heartbeat"),
                            loop,
                        )
                        try:
                            fut.result(timeout=5)
                        except Exception:
                            pass

                    result = await asyncio.to_thread(
                        session.execute_command,
                        args.command,
                        args.timeout,
                        on_output,
                        on_heartbeat,
                        5.0,
                        cancel_event,
                    )
                    completion_message = (
                        "Command timed out"
                        if result["status"] == "timeout"
                        else ("Command cancelled" if result["status"] == "cancelled" else "Command completed")
                    )
                    await _send_tool_progress("completed", completion_message)
                    log_method = command_logger.warning if result["status"] == "timeout" else command_logger.info
                    log_method(
                        "Command finished with status=%s in %sms with %s output lines",
                        result["status"],
                        result["execution_time_ms"],
                        len(result["output_lines"]),
                        extra=make_context(
                            outcome="timeout" if result["status"] == "timeout" else "success",
                            request_id=request_id,
                            file_id=metadata.file_id,
                            session_id=args.session_id,
                            command_preview=command_preview,
                        ),
                    )
                    if result["status"] == "timeout" and result.get("background_running"):
                        command_logger.warning(
                            "Foreground command timed out while background execution continues",
                            extra=make_context(
                                outcome="background_running",
                                request_id=request_id,
                                file_id=metadata.file_id,
                                session_id=args.session_id,
                                command_preview=command_preview,
                            ),
                        )
                    payload = {
                        "success": result["status"] == "completed",
                        "status": result["status"],
                        "command": args.command,
                        "output": "\n".join(result["output_lines"]),
                        "execution_time_ms": result["execution_time_ms"],
                        "cancelled": bool(result["cancelled"]),
                        "timed_out": bool(result["timed_out"]),
                        "first_output_delay_ms": result["first_output_delay_ms"],
                        "queue_wait_ms": result["queue_wait_ms"],
                    }
                    suggested_next_step = _build_suggested_next_step(result)
                    if suggested_next_step:
                        payload["suggested_next_step"] = suggested_next_step
                    return [TextContent(type="text", text=json.dumps(payload))]
                finally:
                    with _running_lock:
                        _running_requests.pop(request_id, None)
                    upload_sessions.release_analysis_session(args.session_id, upload_runtime_config.session_ttl_seconds)

            if name == "start_async_windbg_command":
                args = StartAsyncWindbgCommandParams(**arguments)
                command_preview = sanitize_command(args.command)
                blocked = _validate_dangerous_command(args.command)
                if blocked:
                    raise McpError(
                        ErrorData(
                            code=INVALID_PARAMS,
                            message=(
                                "DANGEROUS_COMMAND_BLOCKED: "
                                + json.dumps(
                                    {
                                        "message": "Command blocked by security policy",
                                        "blocked_token": blocked,
                                        "command": args.command,
                                    }
                                )
                            ),
                        )
                    )
                analysis, metadata, error_message = upload_sessions.acquire_analysis_session(
                    args.session_id, upload_runtime_config.session_ttl_seconds
                )
                if analysis is None or metadata is None:
                    raise McpError(
                        ErrorData(code=INVALID_PARAMS, message=f"{UPLOAD_ERROR_SESSION_NOT_FOUND}: {error_message}")
                    )
                try:
                    session = upload_sessions.get_or_create_cdb_session(
                        upload_sessions.build_upload_cdb_session_key(args.session_id),
                        lambda: CDBSession(
                            dump_path=metadata.temp_file_path,
                            cdb_path=cdb_path,
                            symbols_path=symbols_path or DEFAULT_SYMBOL_PATH,
                            timeout=timeout,
                            verbose=verbose,
                            log_context={
                                "request_id": base_context["request_id"],
                                "file_id": metadata.file_id,
                                "session_id": args.session_id,
                            },
                        ),
                    )
                    result = session.start_async_command(args.command)
                    payload = {
                        "command_id": result["request_id"],
                        "session_id": args.session_id,
                        "status": result["status"],
                        "command": args.command,
                        "queue_wait_ms": result["queue_wait_ms"],
                    }
                    return [TextContent(type="text", text=json.dumps(payload))]
                finally:
                    upload_sessions.release_analysis_session(args.session_id, upload_runtime_config.session_ttl_seconds)

            if name == "get_async_windbg_command_status":
                args = GetAsyncWindbgCommandStatusParams(**arguments)
                analysis, metadata, error_message = upload_sessions.acquire_analysis_session(
                    args.session_id, upload_runtime_config.session_ttl_seconds
                )
                if analysis is None or metadata is None:
                    raise McpError(
                        ErrorData(code=INVALID_PARAMS, message=f"{UPLOAD_ERROR_SESSION_NOT_FOUND}: {error_message}")
                    )
                try:
                    session = upload_sessions.get_or_create_cdb_session(
                        upload_sessions.build_upload_cdb_session_key(args.session_id),
                        lambda: CDBSession(
                            dump_path=metadata.temp_file_path,
                            cdb_path=cdb_path,
                            symbols_path=symbols_path or DEFAULT_SYMBOL_PATH,
                            timeout=timeout,
                            verbose=verbose,
                            log_context={
                                "request_id": base_context["request_id"],
                                "file_id": metadata.file_id,
                                "session_id": args.session_id,
                            },
                        ),
                    )
                    result = session.get_command_status(args.command_id)
                    payload = {
                        "command_id": args.command_id,
                        "session_id": args.session_id,
                        "status": result["status"],
                        "command": result["command"],
                        "queue_wait_ms": result["queue_wait_ms"],
                        "execution_time_ms": result["execution_time_ms"],
                        "first_output_delay_ms": result["first_output_delay_ms"],
                        "output_line_count": result["output_line_count"],
                        "started": result["started"],
                        "completed": result["completed"],
                    }
                    return [TextContent(type="text", text=json.dumps(payload))]
                finally:
                    upload_sessions.release_analysis_session(args.session_id, upload_runtime_config.session_ttl_seconds)

            if name == "get_async_windbg_command_result":
                args = GetAsyncWindbgCommandResultParams(**arguments)
                analysis, metadata, error_message = upload_sessions.acquire_analysis_session(
                    args.session_id, upload_runtime_config.session_ttl_seconds
                )
                if analysis is None or metadata is None:
                    raise McpError(
                        ErrorData(code=INVALID_PARAMS, message=f"{UPLOAD_ERROR_SESSION_NOT_FOUND}: {error_message}")
                    )
                request_id = base_context["request_id"]
                try:
                    session = upload_sessions.get_or_create_cdb_session(
                        upload_sessions.build_upload_cdb_session_key(args.session_id),
                        lambda: CDBSession(
                            dump_path=metadata.temp_file_path,
                            cdb_path=cdb_path,
                            symbols_path=symbols_path or DEFAULT_SYMBOL_PATH,
                            timeout=timeout,
                            verbose=verbose,
                            log_context={
                                "request_id": base_context["request_id"],
                                "file_id": metadata.file_id,
                                "session_id": args.session_id,
                            },
                        ),
                    )
                    ctx = _try_get_request_context(server)
                    request_id = str(ctx.request_id) if ctx is not None else request_id
                    loop = asyncio.get_running_loop()
                    cancel_event = threading.Event()
                    with _running_lock:
                        _running_requests[request_id] = cancel_event

                    def on_output(line: str) -> None:
                        if ctx is None:
                            return
                        fut = asyncio.run_coroutine_threadsafe(
                            _send_progress(ctx.session, request_id, "running", "output", f"{line}\n"),
                            loop,
                        )
                        try:
                            fut.result(timeout=5)
                        except Exception:
                            pass

                    def on_heartbeat() -> None:
                        if ctx is None:
                            return
                        fut = asyncio.run_coroutine_threadsafe(
                            _send_progress(ctx.session, request_id, "running", "heartbeat"),
                            loop,
                        )
                        try:
                            fut.result(timeout=5)
                        except Exception:
                            pass

                    result = await asyncio.to_thread(
                        session.wait_for_command_result,
                        args.command_id,
                        float(args.wait_timeout),
                        on_output,
                        on_heartbeat,
                        5.0,
                        cancel_event,
                    )
                    payload = {
                        "command_id": args.command_id,
                        "session_id": args.session_id,
                        "success": result["status"] == "completed",
                        "status": result["status"],
                        "command": result["command"],
                        "output": "\n".join(result["output_lines"]),
                        "output_line_count": result["output_line_count"],
                        "execution_time_ms": result["execution_time_ms"],
                        "queue_wait_ms": result["queue_wait_ms"],
                        "cancelled": bool(result["cancelled"]),
                        "timed_out": bool(result["timed_out"]),
                        "first_output_delay_ms": result["first_output_delay_ms"],
                        "completed": result["completed"],
                    }
                    suggested_next_step = _build_suggested_next_step(result)
                    if suggested_next_step:
                        payload["suggested_next_step"] = suggested_next_step
                    return [TextContent(type="text", text=json.dumps(payload))]
                finally:
                    with _running_lock:
                        _running_requests.pop(request_id, None)
                    upload_sessions.release_analysis_session(args.session_id, upload_runtime_config.session_ttl_seconds)

            if name == "close_analysis_session":
                args = CloseAnalysisSessionParams(**arguments)
                close_logger = bind_context(
                    logger,
                    event="analysis.close",
                    request_id=base_context["request_id"],
                    session_id=args.session_id,
                )
                payload, error_kind, error_message = upload_sessions.close_analysis_session(args.session_id)
                if payload is None:
                    close_logger.warning(
                        "Close analysis session failed: %s",
                        sanitize_exception_message(error_message),
                        extra=make_context(outcome="missing"),
                    )
                    raise McpError(ErrorData(code=INVALID_PARAMS, message=f"{error_kind}: {error_message}"))
                close_logger.info(
                    "Analysis session closed",
                    extra=make_context(outcome="success"),
                )
                return [TextContent(type="text", text=json.dumps(payload))]

            tool_logger.warning(
                "Unknown tool requested: %s",
                name,
                extra=make_context(event="mcp.call_tool", outcome="invalid", request_id=base_context["request_id"]),
            )
            raise McpError(ErrorData(code=INVALID_PARAMS, message=f"Unknown tool: {name}"))

        except UploadWorkflowError as exc:
            tool_logger.warning(
                "Upload workflow error: %s",
                sanitize_exception_message(exc.message),
                extra=make_context(event="mcp.call_tool", outcome="invalid", request_id=base_context["request_id"]),
            )
            raise McpError(ErrorData(code=INVALID_PARAMS, message=json.dumps({"error": exc.to_payload()}))) from exc
        except McpError:
            raise
        except CDBError as exc:
            tool_logger.exception(
                "CDB execution failed: %s",
                sanitize_exception_message(str(exc)),
                extra=make_context(event="mcp.call_tool", outcome="error", request_id=base_context["request_id"]),
            )
            raise McpError(ErrorData(code=INTERNAL_ERROR, message=str(exc))) from exc
        except Exception as exc:
            tool_logger.exception(
                "Unhandled tool execution error for %s: %s",
                name,
                sanitize_exception_message(str(exc)),
                extra=make_context(event="mcp.call_tool", outcome="error", request_id=base_context["request_id"]),
            )
            raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Error executing tool {name}: {exc}")) from exc

    @server.progress_notification()
    async def _on_progress(_token: str | int, _progress: float, _total: float | None, _message: str | None) -> None:
        return None

    async def _on_cancelled(notification: types.CancelledNotification) -> None:
        request_id = notification.params.requestId
        if request_id is None:
            return
        with _running_lock:
            event = _running_requests.get(str(request_id))
        if event:
            event.set()
            logger.info(
                "Cancellation requested for running command",
                extra=make_context(event="analysis.cancel", outcome="requested", request_id=str(request_id)),
            )

    server.notification_handlers[types.CancelledNotification] = _on_cancelled
    return server


def cleanup_sessions():
    upload_sessions.cleanup_sessions()


atexit.register(cleanup_sessions)
