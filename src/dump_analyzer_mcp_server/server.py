import asyncio
import atexit
import copy
import errno
import json
import logging
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

from mcp.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.shared.exceptions import McpError
from mcp.types import ErrorData, TextContent, Tool, INVALID_PARAMS, INTERNAL_ERROR
from pydantic import BaseModel, Field, model_validator

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


def configure_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s.%(msecs)03d [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        force=True,
    )


def timestamped_print(message: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"[{timestamp}] {message}")


def build_uvicorn_log_config() -> dict:
    from uvicorn.config import LOGGING_CONFIG

    log_config = copy.deepcopy(LOGGING_CONFIG)
    default_formatter = log_config.get("formatters", {}).get("default")
    if isinstance(default_formatter, dict):
        default_formatter["fmt"] = "%(asctime)s.%(msecs)03d %(levelprefix)s %(message)s"
        default_formatter["datefmt"] = "%Y-%m-%d %H:%M:%S"
    access_formatter = log_config.get("formatters", {}).get("access")
    if isinstance(access_formatter, dict):
        access_formatter["fmt"] = (
            '%(asctime)s.%(msecs)03d %(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s'
        )
        access_formatter["datefmt"] = "%Y-%m-%d %H:%M:%S"
    return log_config


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


class ExecuteWindbgCommandParams(BaseModel):
    session_id: str = Field(description="Analysis session ID")
    command: str = Field(description="CDB command to execute")
    timeout: int = Field(default=600, description="Idle timeout in seconds, applied when there is no output")

    @model_validator(mode="after")
    def validate_timeout(self):
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than 0")
        return self


class CloseAnalysisSessionParams(BaseModel):
    session_id: str = Field(description="Session ID")


async def upload_session_cleanup_loop(interval_seconds: int = DEFAULT_UPLOAD_CLEANUP_INTERVAL_SECONDS) -> None:
    safe_interval = max(1, interval_seconds)
    while True:
        try:
            upload_sessions.cleanup_expired_upload_sessions()
        except Exception:
            logger.exception("Unexpected error during upload session cleanup loop")
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
        raise UploadWorkflowError(
            code=UPLOAD_ERROR_TOO_MANY_SESSIONS,
            message=str(exc),
            remediation="Close or wait for existing upload sessions before creating another one.",
            http_status=409,
        ) from exc
    except ValueError as exc:
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
    timeout: int = 30,
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

    logger.info("Starting %s on %s:%s", SERVER_NAME, host, port)
    timestamped_print(f"{SERVER_NAME} running on http://{host}:{port}")
    timestamped_print(f"MCP endpoint: {public_base_url}/mcp")
    timestamped_print(f"Upload base URL: {public_base_url}")

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="info" if verbose else "warning",
        log_config=build_uvicorn_log_config(),
    )
    server_instance = uvicorn.Server(config)
    await server_instance.serve()


def create_http_app(
    cdb_path: Optional[str] = None,
    symbols_path: Optional[str] = None,
    timeout: int = 30,
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
        metadata, error_kind, error_message = upload_sessions.prepare_upload_session_for_upload(
            file_id, upload_runtime_config.session_ttl_seconds
        )
        if metadata is None:
            if error_kind in {"busy", "invalid_state"}:
                return upload_error(
                    409,
                    UPLOAD_ERROR_INVALID_STATE,
                    error_message,
                    remediation="Create a new upload session if the previous upload is stuck, or wait and retry.",
                    details={"file_id": file_id},
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
                logger.exception("Unexpected upload failure for file_id=%s", file_id)
            return upload_error(status_code, code, message, remediation=remediation, details=details)

        try:
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

        return JSONResponse(
            status_code=201,
            content={"file_id": file_id, "status": UploadSessionStatus.UPLOADED.value, "size_bytes": total_size},
        )

    @asynccontextmanager
    async def lifespan(app: Starlette):
        cleanup_task = asyncio.create_task(upload_session_cleanup_loop(DEFAULT_UPLOAD_CLEANUP_INTERVAL_SECONDS))
        try:
            async with session_manager.run():
                yield
        finally:
            cleanup_task.cancel()
            try:
                await cleanup_task
            except asyncio.CancelledError:
                pass
            cleanup_sessions()

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
    timeout: int = 30,
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
                description="Start a crash dump analysis session and load the dump file and symbols. This may take 3-10 minutes and reports progress in real time.",
                inputSchema=StartAnalysisSessionParams.model_json_schema(),
            ),
            Tool(
                name="execute_windbg_command",
                description="Execute any CDB command in an analysis session and stream the raw output. Long-running commands send heartbeats automatically to keep the connection alive.",
                inputSchema=ExecuteWindbgCommandParams.model_json_schema(),
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
        try:
            if name == "prepare_dump_upload":
                args = PrepareDumpUploadParams(**arguments)
                payload = create_upload_session(args.file_name, args.file_size)
                return [TextContent(type="text", text=json.dumps(payload))]

            if name == "start_analysis_session":
                args = StartAnalysisSessionParams(**arguments)
                metadata, error_message = upload_sessions.acquire_uploaded_file_for_analysis(
                    args.file_id, upload_runtime_config.session_ttl_seconds
                )
                if metadata is None:
                    raise McpError(
                        ErrorData(code=INVALID_PARAMS, message=f"{UPLOAD_ERROR_INVALID_STATE}: {error_message}")
                    )

                analysis, error_message = upload_sessions.get_or_create_analysis_session(
                    args.file_id, upload_runtime_config.session_ttl_seconds
                )
                if analysis is None:
                    raise McpError(
                        ErrorData(code=INVALID_PARAMS, message=f"{UPLOAD_ERROR_INVALID_STATE}: {error_message}")
                    )

                upload_sessions.get_or_create_cdb_session(
                    upload_sessions.build_upload_cdb_session_key(analysis.session_id),
                    lambda: CDBSession(
                        dump_path=metadata.temp_file_path,
                        cdb_path=cdb_path,
                        symbols_path=symbols_path or DEFAULT_SYMBOL_PATH,
                        timeout=timeout,
                        verbose=verbose,
                    ),
                )
                payload = {"session_id": analysis.session_id, "file_id": args.file_id, "status": "ready"}
                return [TextContent(type="text", text=json.dumps(payload))]

            if name == "execute_windbg_command":
                args = ExecuteWindbgCommandParams(**arguments)
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
                        ),
                    )
                    ctx = _try_get_request_context(server)
                    request_id = str(ctx.request_id) if ctx is not None else f"local-{int(time.time() * 1000)}"
                    loop = asyncio.get_running_loop()
                    cancel_event = threading.Event()
                    with _running_lock:
                        _running_requests[request_id] = cancel_event

                    await _send_tool_progress("queued", f"Running command: {args.command}")

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
                        session.execute_command,
                        args.command,
                        args.timeout,
                        on_output,
                        on_heartbeat,
                        5.0,
                        cancel_event,
                    )
                    await _send_tool_progress("completed", "Command completed")
                    payload = {
                        "success": True,
                        "command": args.command,
                        "output": "\n".join(result["output_lines"]),
                        "execution_time_ms": result["execution_time_ms"],
                        "cancelled": bool(result["cancelled"]),
                    }
                    return [TextContent(type="text", text=json.dumps(payload))]
                finally:
                    with _running_lock:
                        _running_requests.pop(request_id, None)
                    upload_sessions.release_analysis_session(args.session_id, upload_runtime_config.session_ttl_seconds)

            if name == "close_analysis_session":
                args = CloseAnalysisSessionParams(**arguments)
                payload, error_kind, error_message = upload_sessions.close_analysis_session(args.session_id)
                if payload is None:
                    raise McpError(ErrorData(code=INVALID_PARAMS, message=f"{error_kind}: {error_message}"))
                return [TextContent(type="text", text=json.dumps(payload))]

            raise McpError(ErrorData(code=INVALID_PARAMS, message=f"Unknown tool: {name}"))

        except UploadWorkflowError as exc:
            raise McpError(ErrorData(code=INVALID_PARAMS, message=json.dumps({"error": exc.to_payload()}))) from exc
        except McpError:
            raise
        except CDBError as exc:
            raise McpError(ErrorData(code=INTERNAL_ERROR, message=str(exc))) from exc
        except Exception as exc:
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

    server.notification_handlers[types.CancelledNotification] = _on_cancelled
    return server


def cleanup_sessions():
    upload_sessions.cleanup_sessions()


atexit.register(cleanup_sessions)
