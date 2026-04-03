import asyncio
import atexit
import errno
import glob
import json
import logging
import os
import traceback
import winreg
from contextlib import asynccontextmanager, contextmanager
from typing import Dict, Optional, Tuple

from . import upload_sessions
from .cdb_session import CDBSession
from .prompts import load_prompt
from .upload_sessions import UploadSessionMetadata, UploadSessionStatus

from mcp.shared.exceptions import McpError
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.types import (
    ErrorData,
    TextContent,
    Tool,
    Prompt,
    PromptArgument,
    PromptMessage,
    GetPromptResult,
    INVALID_PARAMS,
    INTERNAL_ERROR,
)
from pydantic import BaseModel, Field, model_validator

logger = logging.getLogger(__name__)

DEFAULT_MAX_UPLOAD_MB = upload_sessions.DEFAULT_MAX_UPLOAD_MB
DEFAULT_SESSION_TTL_SECONDS = upload_sessions.DEFAULT_SESSION_TTL_SECONDS
DEFAULT_MAX_ACTIVE_SESSIONS = upload_sessions.DEFAULT_MAX_ACTIVE_SESSIONS
DEFAULT_UPLOAD_CLEANUP_INTERVAL_SECONDS = 30
UPLOAD_ROUTE_PATH = "/uploads/dumps/{session_id}"
UPLOAD_ERROR_TOO_LARGE = "UPLOAD_TOO_LARGE"
UPLOAD_ERROR_INVALID_FORMAT = "INVALID_DUMP_FORMAT"
UPLOAD_ERROR_INSUFFICIENT_STORAGE = "INSUFFICIENT_STORAGE"
UPLOAD_ERROR_WRITE_FAILED = "UPLOAD_WRITE_FAILED"
UPLOAD_ERROR_SESSION_NOT_FOUND = "UPLOAD_SESSION_NOT_FOUND"
UPLOAD_ERROR_INVALID_STATE = "UPLOAD_SESSION_INVALID_STATE"
UPLOAD_ERROR_TOO_MANY_SESSIONS = "UPLOAD_TOO_MANY_SESSIONS"
UPLOAD_ERROR_UPLOAD_FAILED = "UPLOAD_FAILED"


def _build_session_id(
    dump_path: Optional[str] = None,
    connection_string: Optional[str] = None,
    session_id: Optional[str] = None,
) -> str:
    if dump_path:
        return os.path.abspath(dump_path)
    if connection_string:
        return f"remote:{connection_string}"
    if session_id:
        return upload_sessions.build_upload_cdb_session_key(session_id)
    raise ValueError("One target must be provided")


session_registry = upload_sessions.session_registry
upload_runtime_config = upload_sessions.upload_runtime_config

def get_local_dumps_path() -> Optional[str]:
    """Get the local dumps path from the Windows registry."""
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"
        ) as key:
            dump_folder, _ = winreg.QueryValueEx(key, "DumpFolder")
            if os.path.exists(dump_folder) and os.path.isdir(dump_folder):
                return dump_folder
    except (OSError, WindowsError):
        # Registry key might not exist or other issues
        pass

    # Default Windows dump location
    default_path = os.path.join(os.environ.get("LOCALAPPDATA", ""), "CrashDumps")
    if os.path.exists(default_path) and os.path.isdir(default_path):
        return default_path

    return None

class OpenWindbgDump(BaseModel):
    """Parameters for analyzing a crash dump."""
    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    session_id: Optional[str] = Field(default=None, description="Upload session identifier returned by create_upload_session")
    include_stack_trace: bool = Field(description="Whether to include stack traces in the analysis")
    include_modules: bool = Field(description="Whether to include loaded module information")
    include_threads: bool = Field(description="Whether to include thread information")

    @model_validator(mode='after')
    def validate_target_params(self):
        target_count = int(bool(self.dump_path)) + int(bool(self.session_id))
        if target_count == 0:
            raise ValueError("One of dump_path or session_id must be provided")
        if target_count > 1:
            raise ValueError("dump_path and session_id are mutually exclusive")
        return self


class OpenWindbgDumpStdioParams(BaseModel):
    """Parameters for analyzing a local crash dump."""

    dump_path: str = Field(description="Path to the Windows crash dump file")
    include_stack_trace: bool = Field(description="Whether to include stack traces in the analysis")
    include_modules: bool = Field(description="Whether to include loaded module information")
    include_threads: bool = Field(description="Whether to include thread information")


class OpenWindbgRemote(BaseModel):
    """Parameters for connecting to a remote debug session."""
    connection_string: str = Field(description="Remote connection string (e.g., 'tcp:Port=5005,Server=192.168.0.100')")
    include_stack_trace: bool = Field(default=False, description="Whether to include stack traces in the analysis")
    include_modules: bool = Field(default=False, description="Whether to include loaded module information")
    include_threads: bool = Field(default=False, description="Whether to include thread information")


class CreateUploadSessionParams(BaseModel):
    """Parameters for creating an upload session."""
    file_name: str = Field(
        description="Original dump filename. Must use a supported dump extension such as .dmp, .mdmp, or .hdmp"
    )

    @model_validator(mode='after')
    def validate_file_name(self):
        file_name = self.file_name.strip()
        if not file_name:
            raise ValueError("file_name must not be empty")
        if not upload_sessions.is_supported_dump_filename(file_name):
            raise ValueError("Only .dmp, .mdmp, and .hdmp files are supported")
        return self


class RunWindbgCmdParams(BaseModel):
    """Parameters for executing a WinDbg command."""
    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    connection_string: Optional[str] = Field(default=None, description="Remote connection string (e.g., 'tcp:Port=5005,Server=192.168.0.100')")
    session_id: Optional[str] = Field(default=None, description="Upload session identifier returned by create_upload_session")
    command: str = Field(description="WinDbg command to execute")

    @model_validator(mode='after')
    def validate_connection_params(self):
        """Validate that exactly one target identifier is provided."""
        target_count = int(bool(self.dump_path)) + int(bool(self.connection_string)) + int(bool(self.session_id))
        if target_count == 0:
            raise ValueError("One of dump_path, connection_string, or session_id must be provided")
        if target_count > 1:
            raise ValueError("dump_path, connection_string, and session_id are mutually exclusive")
        return self


class RunWindbgCmdStdioParams(BaseModel):
    """Parameters for executing a WinDbg command on a local or remote session."""

    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    connection_string: Optional[str] = Field(
        default=None,
        description="Remote connection string (e.g., 'tcp:Port=5005,Server=192.168.0.100')",
    )
    command: str = Field(description="WinDbg command to execute")

    @model_validator(mode='after')
    def validate_connection_params(self):
        target_count = int(bool(self.dump_path)) + int(bool(self.connection_string))
        if target_count == 0:
            raise ValueError("One of dump_path or connection_string must be provided")
        if target_count > 1:
            raise ValueError("dump_path and connection_string are mutually exclusive")
        return self


class CloseWindbgDumpParams(BaseModel):
    """Parameters for unloading a local or uploaded crash dump."""

    dump_path: Optional[str] = Field(
        default=None,
        description="Path to the Windows crash dump file to unload",
    )
    session_id: Optional[str] = Field(
        default=None,
        description="Upload session identifier returned by create_upload_session",
    )

    @model_validator(mode='after')
    def validate_target_params(self):
        target_count = int(bool(self.dump_path)) + int(bool(self.session_id))
        if target_count == 0:
            raise ValueError("One of dump_path or session_id must be provided")
        if target_count > 1:
            raise ValueError("dump_path and session_id are mutually exclusive")
        return self


class CloseWindbgDumpStdioParams(BaseModel):
    """Parameters for unloading a local crash dump."""

    dump_path: str = Field(description="Path to the Windows crash dump file to unload")


class CloseWindbgRemoteParams(BaseModel):
    """Parameters for closing a remote debugging connection."""
    connection_string: str = Field(description="Remote connection string to close")


class ListWindbgDumpsParams(BaseModel):
    """Parameters for listing crash dumps in a directory."""
    directory_path: Optional[str] = Field(
        default=None,
        description="Directory path to search for dump files. If not specified, will use the configured dump path from registry."
    )
    recursive: bool = Field(
        default=False,
        description="Whether to search recursively in subdirectories"
    )


class SendCtrlBreakParams(BaseModel):
    """Parameters for sending CTRL+BREAK to a CDB/WinDbg session."""

    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    connection_string: Optional[str] = Field(
        default=None,
        description="Remote connection string (e.g., 'tcp:Port=5005,Server=192.168.0.100')",
    )

    @model_validator(mode='after')
    def validate_connection_params(self):
        if not self.dump_path and not self.connection_string:
            raise ValueError("Either dump_path or connection_string must be provided")
        if self.dump_path and self.connection_string:
            raise ValueError("dump_path and connection_string are mutually exclusive")
        return self


def cleanup_expired_upload_sessions(now=None) -> int:
    return upload_sessions.cleanup_expired_upload_sessions(now=now)


async def upload_session_cleanup_loop(interval_seconds: int = DEFAULT_UPLOAD_CLEANUP_INTERVAL_SECONDS) -> None:
    """Background task that periodically cleans expired upload sessions."""
    safe_interval = max(1, interval_seconds)
    while True:
        try:
            cleanup_expired_upload_sessions()
        except Exception:
            logger.exception("Unexpected error during upload session cleanup loop")
        await asyncio.sleep(safe_interval)


def create_upload_session(file_name: str) -> Dict[str, object]:
    """Create a new upload session and reserve a temp path."""
    try:
        payload = upload_sessions.create_upload_session(file_name)
    except upload_sessions.UploadSessionLimitError as exc:
        raise McpError(
            ErrorData(
                code=INVALID_PARAMS,
                message=f"{UPLOAD_ERROR_TOO_MANY_SESSIONS}: {exc}",
            )
        ) from exc
    except ValueError as exc:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(exc))) from exc

    payload["upload_path"] = build_upload_path(payload["session_id"])
    return payload


def acquire_uploaded_session_for_tool(session_id: str) -> UploadSessionMetadata:
    metadata, error_message = upload_sessions.acquire_uploaded_session(
        session_id,
        upload_runtime_config.session_ttl_seconds,
        for_analysis=True,
    )
    if metadata is None:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=error_message))
    return metadata


def build_upload_path(session_id: str) -> str:
    return UPLOAD_ROUTE_PATH.format(session_id=session_id)


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


def get_or_create_session(
    dump_path: Optional[str] = None,
    connection_string: Optional[str] = None,
    cdb_path: Optional[str] = None,
    symbols_path: Optional[str] = None,
    timeout: int = 30,
    verbose: bool = False
) -> CDBSession:
    """Get an existing CDB session or create a new one."""
    target_count = int(bool(dump_path)) + int(bool(connection_string))
    if target_count == 0:
        raise ValueError("One of dump_path or connection_string must be provided")
    if target_count > 1:
        raise ValueError("dump_path and connection_string are mutually exclusive")

    cdb_session_id = _build_session_id(
        dump_path=dump_path,
        connection_string=connection_string,
    )

    try:
        return upload_sessions.get_or_create_cdb_session(
            cdb_session_id,
            lambda: CDBSession(
                dump_path=dump_path,
                remote_connection=connection_string,
                cdb_path=cdb_path,
                symbols_path=symbols_path,
                timeout=timeout,
                verbose=verbose,
            ),
        )
    except Exception as e:
        raise McpError(ErrorData(
            code=INTERNAL_ERROR,
            message=f"Failed to create CDB session: {str(e)}"
        ))


def get_or_create_uploaded_session(
    metadata: UploadSessionMetadata,
    cdb_path: Optional[str] = None,
    symbols_path: Optional[str] = None,
    timeout: int = 30,
    verbose: bool = False,
) -> CDBSession:
    """Get or create a CDB session for an uploaded dump."""
    try:
        return upload_sessions.get_or_create_cdb_session(
            _build_session_id(session_id=metadata.session_id),
            lambda: CDBSession(
                dump_path=metadata.temp_file_path,
                cdb_path=cdb_path,
                symbols_path=symbols_path,
                timeout=timeout,
                verbose=verbose,
            ),
        )
    except Exception as e:
        raise McpError(ErrorData(
            code=INTERNAL_ERROR,
            message=f"Failed to create CDB session: {str(e)}"
        ))


@contextmanager
def debugger_session_for_tool(
    *,
    dump_path: Optional[str] = None,
    connection_string: Optional[str] = None,
    session_id: Optional[str] = None,
    cdb_path: Optional[str] = None,
    symbols_path: Optional[str] = None,
    timeout: int = 30,
    verbose: bool = False,
):
    """Resolve the requested target into a reusable CDB session."""
    analysis_metadata = None
    try:
        if session_id:
            analysis_metadata = acquire_uploaded_session_for_tool(session_id)
            session = get_or_create_uploaded_session(
                analysis_metadata,
                cdb_path=cdb_path,
                symbols_path=symbols_path,
                timeout=timeout,
                verbose=verbose,
            )
        else:
            session = get_or_create_session(
                dump_path=dump_path,
                connection_string=connection_string,
                cdb_path=cdb_path,
                symbols_path=symbols_path,
                timeout=timeout,
                verbose=verbose,
            )
        yield session
    finally:
        upload_sessions.release_uploaded_session_after_analysis(
            analysis_metadata,
            upload_runtime_config.session_ttl_seconds,
        )


def unload_session(
    dump_path: Optional[str] = None,
    connection_string: Optional[str] = None,
) -> bool:
    """Unload and clean up a CDB session."""
    target_count = int(bool(dump_path)) + int(bool(connection_string))
    if target_count == 0:
        return False
    if target_count > 1:
        return False

    cdb_session_id = _build_session_id(
        dump_path=dump_path,
        connection_string=connection_string,
    )

    session = upload_sessions.pop_cdb_session(cdb_session_id)
    if session is not None:
        try:
            session.shutdown()
        except Exception:
            pass
        return True

    return False


def close_upload_session(session_id: str) -> Dict[str, object]:
    """Close upload session, shutdown CDB session and remove temp file."""
    payload, error_kind, error_message = upload_sessions.close_upload_session(session_id)
    if payload is None:
        if error_kind == "not_found":
            raise McpError(
                ErrorData(
                    code=INVALID_PARAMS,
                    message=f"{UPLOAD_ERROR_SESSION_NOT_FOUND}: {error_message}",
                )
            )
        raise McpError(
            ErrorData(
                code=INVALID_PARAMS,
                message=f"{UPLOAD_ERROR_INVALID_STATE}: {error_message}",
            )
        )
    return payload


def close_windbg_dump(
    dump_path: Optional[str] = None,
    session_id: Optional[str] = None,
) -> Dict[str, object]:
    """Close a local or uploaded dump session."""
    if session_id:
        return close_upload_session(session_id)

    if not dump_path:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="dump_path must be provided"))

    success = unload_session(dump_path=dump_path)
    if success:
        return {"status": "closed", "dump_path": dump_path}
    return {"status": "not_found", "dump_path": dump_path}


async def serve(
    cdb_path: Optional[str] = None,
    symbols_path: Optional[str] = None,
    timeout: int = 30,
    verbose: bool = False,
) -> None:
    """Run the WinDbg MCP server with stdio transport.

    Args:
        cdb_path: Optional custom path to cdb.exe
        symbols_path: Optional custom symbols path
        timeout: Command timeout in seconds
        verbose: Whether to enable verbose output
    """
    server = _create_server(cdb_path, symbols_path, timeout, verbose)

    options = server.create_initialization_options()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, options, raise_exceptions=True)


async def serve_http(
    host: str = "127.0.0.1",
    port: int = 8000,
    cdb_path: Optional[str] = None,
    symbols_path: Optional[str] = None,
    timeout: int = 30,
    verbose: bool = False,
) -> None:
    """Run the WinDbg MCP server with Streamable HTTP transport.

    Args:
        host: Host to bind the HTTP server to
        port: Port to bind the HTTP server to
        cdb_path: Optional custom path to cdb.exe
        symbols_path: Optional custom symbols path
        timeout: Command timeout in seconds
        verbose: Whether to enable verbose output
    """
    import uvicorn

    app = create_http_app(
        cdb_path=cdb_path,
        symbols_path=symbols_path,
        timeout=timeout,
        verbose=verbose,
    )

    logger.info(f"Starting MCP WinDbg server with streamable-http transport on {host}:{port}")
    print(f"MCP WinDbg server running on http://{host}:{port}")
    print(f"  MCP endpoint: http://{host}:{port}/mcp")

    config = uvicorn.Config(app, host=host, port=port, log_level="info" if verbose else "warning")
    server_instance = uvicorn.Server(config)
    await server_instance.serve()


def create_http_app(
    cdb_path: Optional[str] = None,
    symbols_path: Optional[str] = None,
    timeout: int = 30,
    verbose: bool = False,
):
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route
    from starlette.types import Receive, Scope, Send

    server = _create_server(
        cdb_path,
        symbols_path,
        timeout,
        verbose,
        enable_upload_tools=True,
    )

    session_manager = StreamableHTTPSessionManager(
        app=server,
        json_response=True,
    )

    async def handle_streamable_http(scope: Scope, receive: Receive, send: Send) -> None:
        await session_manager.handle_request(scope, receive, send)

    def upload_error(status_code: int, code: str, message: str) -> JSONResponse:
        return JSONResponse(
            status_code=status_code,
            content={"error": {"code": code, "message": message}},
        )

    async def upload_dump(request: Request) -> JSONResponse:
        session_id = request.path_params["session_id"]
        metadata, error_kind, error_message = upload_sessions.prepare_upload_session_for_upload(
            session_id, upload_runtime_config.session_ttl_seconds
        )
        if metadata is None:
            if error_kind in {"busy", "invalid_state", "expired"}:
                return upload_error(409, UPLOAD_ERROR_INVALID_STATE, error_message)
            return upload_error(404, UPLOAD_ERROR_SESSION_NOT_FOUND, error_message)

        def fail_upload(status_code: int, code: str, message: str, *, log_unexpected: bool = False) -> JSONResponse:
            upload_sessions.mark_upload_failed(metadata)
            if log_unexpected:
                logger.exception("Unexpected upload failure for session %s", session_id)
            return upload_error(status_code, code, message)

        try:
            max_bytes = upload_runtime_config.max_upload_mb * 1024 * 1024
            expected_signatures = upload_sessions.get_expected_dump_signatures(metadata.original_file_name)
            total_size = await _stream_upload_to_file(
                request,
                metadata.temp_file_path,
                max_bytes,
                expected_signatures,
            )
            upload_sessions.mark_upload_completed(metadata, upload_runtime_config.session_ttl_seconds)
        except ValueError as exc:
            if str(exc) == UPLOAD_ERROR_TOO_LARGE:
                return fail_upload(
                    413,
                    UPLOAD_ERROR_TOO_LARGE,
                    f"Upload exceeds limit ({upload_runtime_config.max_upload_mb}MB)",
                )
            return fail_upload(400, UPLOAD_ERROR_INVALID_FORMAT, "Invalid dump upload payload")
        except OSError as exc:
            if exc.errno == errno.ENOSPC:
                return fail_upload(507, UPLOAD_ERROR_INSUFFICIENT_STORAGE, "Insufficient storage space")
            return fail_upload(500, UPLOAD_ERROR_WRITE_FAILED, f"Upload write failure: {exc}")
        except asyncio.CancelledError:
            upload_sessions.mark_upload_failed(metadata)
            raise
        except Exception:
            return fail_upload(500, UPLOAD_ERROR_UPLOAD_FAILED, "Unexpected upload failure", log_unexpected=True)
        finally:
            upload_sessions.release_upload_lock(metadata)

        return JSONResponse(
            status_code=201,
            content={
                "session_id": session_id,
                "status": UploadSessionStatus.UPLOADED.value,
                "size_bytes": total_size,
            },
        )

    @asynccontextmanager
    async def lifespan(app: Starlette):
        cleanup_task = asyncio.create_task(
            upload_session_cleanup_loop(DEFAULT_UPLOAD_CLEANUP_INTERVAL_SECONDS)
        )
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
            Route("/uploads/dumps/{session_id}", endpoint=upload_dump, methods=["PUT"]),
        ],
        lifespan=lifespan,
    )


def _create_server(
    cdb_path: Optional[str] = None,
    symbols_path: Optional[str] = None,
    timeout: int = 30,
    verbose: bool = False,
    enable_upload_tools: bool = False,
) -> Server:
    """Create and configure the MCP server with all tools and prompts.

    Args:
        cdb_path: Optional custom path to cdb.exe
        symbols_path: Optional custom symbols path
        timeout: Command timeout in seconds
        verbose: Whether to enable verbose output

    Returns:
        Configured Server instance
    """
    server = Server("mcp-windbg")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        open_dump_schema = (
            OpenWindbgDump.model_json_schema()
            if enable_upload_tools
            else OpenWindbgDumpStdioParams.model_json_schema()
        )
        run_cmd_schema = (
            RunWindbgCmdParams.model_json_schema()
            if enable_upload_tools
            else RunWindbgCmdStdioParams.model_json_schema()
        )
        open_dump_description = """
                Analyze a Windows crash dump file using WinDbg/CDB.
                This tool executes common WinDbg commands to analyze the crash dump and returns the results.
                """
        if enable_upload_tools:
            open_dump_description = """
                Analyze a Windows crash dump file using WinDbg/CDB.
                Accepts either a local dump_path or an uploaded session_id.
                This tool executes common WinDbg commands to analyze the crash dump and returns the results.
                """

        run_windbg_cmd_description = """
                Execute a specific WinDbg command.
                Exactly one of dump_path or connection_string must be provided.
                """
        if enable_upload_tools:
            run_windbg_cmd_description = """
                Execute a specific WinDbg command.
                Exactly one of dump_path, connection_string, or session_id must be provided.
                Use session_id to reuse an uploaded dump session without re-uploading.
                """

        close_dump_schema = (
            CloseWindbgDumpParams.model_json_schema()
            if enable_upload_tools
            else CloseWindbgDumpStdioParams.model_json_schema()
        )
        close_dump_description = """
                Unload a crash dump and release resources.
                Use this tool when you're done analyzing a crash dump to free up resources.
                """
        if enable_upload_tools:
            close_dump_description = """
                Unload a crash dump and release resources.
                Accepts either a local dump_path or an uploaded session_id.
                Use this tool when you're done analyzing a crash dump to free up resources.
                """

        tools = [
            Tool(
                name="open_windbg_dump",
                description=open_dump_description,
                inputSchema=open_dump_schema,
            ),
            Tool(
                name="open_windbg_remote",
                description="""
                Connect to a remote debugging session using WinDbg/CDB.
                This tool establishes a remote debugging connection and allows you to analyze the target process.
                """,
                inputSchema=OpenWindbgRemote.model_json_schema(),
            ),
            Tool(
                name="run_windbg_cmd",
                description=run_windbg_cmd_description,
                inputSchema=run_cmd_schema,
            ),
            Tool(
                name="send_ctrl_break",
                description="""
                Send a CTRL+BREAK event to the active CDB/WinDbg session, causing it to break in.
                Useful for interrupting a running target or breaking into a remote session.
                """,
                inputSchema=SendCtrlBreakParams.model_json_schema(),
            ),
            Tool(
                name="close_windbg_dump",
                description=close_dump_description,
                inputSchema=close_dump_schema,
            ),
            Tool(
                name="close_windbg_remote",
                description="""
                Close a remote debugging connection and release resources.
                Use this tool when you're done with a remote debugging session to free up resources.
                """,
                inputSchema=CloseWindbgRemoteParams.model_json_schema(),
            ),
            Tool(
                name="list_windbg_dumps",
                description="""
                List Windows crash dump files in the specified directory.
                This tool helps you discover available crash dumps that can be analyzed.
                """,
                inputSchema=ListWindbgDumpsParams.model_json_schema(),
            ),
        ]
        if enable_upload_tools:
            tools.extend(
                [
                    Tool(
                        name="create_upload_session",
                        description="""
                        Create a server-side upload session for a supported crash dump file (*.dmp, *.mdmp, *.hdmp).
                        Returns session_id/upload_path and upload constraints for HTTP PUT binary upload over streamable-http.
                        upload_path is the server HTTP path for the binary PUT request and must be combined with the reachable base URL.
                        Workflow: create_upload_session -> PUT upload_path with raw dump bytes -> open_windbg_dump(session_id).
                        """,
                        inputSchema=CreateUploadSessionParams.model_json_schema(),
                    ),
                ]
            )
        return tools

    @server.call_tool()
    async def call_tool(name, arguments: dict) -> list[TextContent]:
        try:
            open_windbg_dump_model = OpenWindbgDump if enable_upload_tools else OpenWindbgDumpStdioParams
            run_windbg_cmd_model = RunWindbgCmdParams if enable_upload_tools else RunWindbgCmdStdioParams
            close_windbg_dump_model = CloseWindbgDumpParams if enable_upload_tools else CloseWindbgDumpStdioParams

            if name == "open_windbg_dump":
                # Provide local dump discovery hints only when no target was supplied.
                if not arguments.get("dump_path") and not arguments.get("session_id"):
                    local_dumps_path = get_local_dumps_path()
                    dumps_found_text = ""
                    upload_hint = ""

                    if local_dumps_path:
                        # Find dump files in the local dumps directory
                        search_pattern = os.path.join(local_dumps_path, "*.*dmp")
                        dump_files = glob.glob(search_pattern)

                        if dump_files:
                            dumps_found_text = f"\n\nI found {len(dump_files)} crash dump(s) in {local_dumps_path}:\n\n"
                            for i, dump_file in enumerate(dump_files[:10]):  # Limit to 10 dumps to avoid clutter
                                try:
                                    size_mb = round(os.path.getsize(dump_file) / (1024 * 1024), 2)
                                except (OSError, IOError):
                                    size_mb = "unknown"

                                dumps_found_text += f"{i+1}. {dump_file} ({size_mb} MB)\n"

                            if len(dump_files) > 10:
                                dumps_found_text += f"\n... and {len(dump_files) - 10} more dump files.\n"

                            dumps_found_text += "\nYou can analyze one of these dumps by specifying its path."

                    if enable_upload_tools:
                        upload_hint = (
                            "\n\nIf the dump is local to the HTTP client, use "
                            "'create_upload_session', upload the raw bytes to the returned "
                            "'upload_path', and then call 'open_windbg_dump' with 'session_id'."
                        )

                    return [TextContent(
                        type="text",
                        text=f"Please provide a path to a crash dump file to analyze.{dumps_found_text}\n\n"
                              f"You can use the 'list_windbg_dumps' tool to discover available crash dumps."
                              f"{upload_hint}"
                    )]

                args = open_windbg_dump_model(**arguments)
                with debugger_session_for_tool(
                    dump_path=getattr(args, "dump_path", None),
                    session_id=getattr(args, "session_id", None),
                    cdb_path=cdb_path,
                    symbols_path=symbols_path,
                    timeout=timeout,
                    verbose=verbose,
                ) as session:
                    results = []

                    crash_info = session.send_command(".lastevent")
                    results.append("### Crash Information\n```\n" + "\n".join(crash_info) + "\n```\n\n")

                    # Run !analyze -v
                    analysis = session.send_command("!analyze -v")
                    results.append("### Crash Analysis\n```\n" + "\n".join(analysis) + "\n```\n\n")

                    # Optional
                    if args.include_stack_trace:
                        stack = session.send_command("kb")
                        results.append("### Stack Trace\n```\n" + "\n".join(stack) + "\n```\n\n")

                    if args.include_modules:
                        modules = session.send_command("lm")
                        results.append("### Loaded Modules\n```\n" + "\n".join(modules) + "\n```\n\n")

                    if args.include_threads:
                        threads = session.send_command("~")
                        results.append("### Threads\n```\n" + "\n".join(threads) + "\n```\n\n")

                    return [TextContent(type="text", text="".join(results))]

            elif name == "open_windbg_remote":
                args = OpenWindbgRemote(**arguments)
                session = get_or_create_session(
                    connection_string=args.connection_string, cdb_path=cdb_path, symbols_path=symbols_path, timeout=timeout, verbose=verbose
                )

                results = []

                # Get target information for remote debugging
                target_info = session.send_command("!peb")
                results.append("### Target Process Information\n```\n" + "\n".join(target_info) + "\n```\n\n")

                # Get current state
                current_state = session.send_command("r")
                results.append("### Current Registers\n```\n" + "\n".join(current_state) + "\n```\n\n")

                # Optional
                if args.include_stack_trace:
                    stack = session.send_command("kb")
                    results.append("### Stack Trace\n```\n" + "\n".join(stack) + "\n```\n\n")

                if args.include_modules:
                    modules = session.send_command("lm")
                    results.append("### Loaded Modules\n```\n" + "\n".join(modules) + "\n```\n\n")

                if args.include_threads:
                    threads = session.send_command("~")
                    results.append("### Threads\n```\n" + "\n".join(threads) + "\n```\n\n")

                return [TextContent(
                    type="text",
                    text="".join(results)
                )]

            elif name == "run_windbg_cmd":
                args = run_windbg_cmd_model(**arguments)
                with debugger_session_for_tool(
                    dump_path=getattr(args, "dump_path", None),
                    connection_string=getattr(args, "connection_string", None),
                    session_id=getattr(args, "session_id", None),
                    cdb_path=cdb_path,
                    symbols_path=symbols_path,
                    timeout=timeout,
                    verbose=verbose,
                ) as session:
                    output = session.send_command(args.command)

                    return [TextContent(
                        type="text",
                        text=f"Command: {args.command}\n\nOutput:\n```\n" + "\n".join(output) + "\n```"
                    )]

            elif name == "create_upload_session" and enable_upload_tools:
                args = CreateUploadSessionParams(**arguments)
                payload = create_upload_session(args.file_name)
                return [TextContent(type="text", text=json.dumps(payload))]

            elif name == "send_ctrl_break":
                args = SendCtrlBreakParams(**arguments)
                session = get_or_create_session(
                    dump_path=args.dump_path,
                    connection_string=args.connection_string,
                    cdb_path=cdb_path,
                    symbols_path=symbols_path,
                    timeout=timeout,
                    verbose=verbose,
                )
                session.send_ctrl_break()
                target = args.dump_path if args.dump_path else f"remote: {args.connection_string}"
                return [TextContent(
                    type="text",
                    text=f"Sent CTRL+BREAK to CDB session ({target})."
                )]

            elif name == "close_windbg_dump":
                args = close_windbg_dump_model(**arguments)
                if getattr(args, "session_id", None):
                    payload = close_upload_session(args.session_id)
                    return [TextContent(type="text", text=json.dumps(payload))]

                success = unload_session(dump_path=args.dump_path)
                if success:
                    return [TextContent(
                        type="text",
                        text=f"Successfully unloaded crash dump: {args.dump_path}"
                    )]
                else:
                    return [TextContent(
                        type="text",
                        text=f"No active session found for crash dump: {args.dump_path}"
                    )]

            elif name == "close_windbg_remote":
                args = CloseWindbgRemoteParams(**arguments)
                success = unload_session(connection_string=args.connection_string)
                if success:
                    return [TextContent(
                        type="text",
                        text=f"Successfully closed remote connection: {args.connection_string}"
                    )]
                else:
                    return [TextContent(
                        type="text",
                        text=f"No active session found for remote connection: {args.connection_string}"
                    )]

            elif name == "list_windbg_dumps":
                args = ListWindbgDumpsParams(**arguments)

                if args.directory_path is None:
                    args.directory_path = get_local_dumps_path()
                    if args.directory_path is None:
                        raise McpError(ErrorData(
                            code=INVALID_PARAMS,
                            message="No directory path specified and no default dump path found in registry."
                        ))

                if not os.path.exists(args.directory_path) or not os.path.isdir(args.directory_path):
                    raise McpError(ErrorData(
                        code=INVALID_PARAMS,
                        message=f"Directory not found: {args.directory_path}"
                    ))

                # Determine search pattern based on recursion flag
                search_pattern = os.path.join(args.directory_path, "**", "*.*dmp") if args.recursive else os.path.join(args.directory_path, "*.*dmp")

                # Find all dump files
                dump_files = glob.glob(search_pattern, recursive=args.recursive)

                # Sort alphabetically for consistent results
                dump_files.sort()

                if not dump_files:
                    return [TextContent(
                        type="text",
                        text=f"No crash dump files (*.*dmp) found in {args.directory_path}"
                    )]

                # Format the results
                result_text = f"Found {len(dump_files)} crash dump file(s) in {args.directory_path}:\n\n"
                for i, dump_file in enumerate(dump_files):
                    # Get file size in MB
                    try:
                        size_mb = round(os.path.getsize(dump_file) / (1024 * 1024), 2)
                    except (OSError, IOError):
                        size_mb = "unknown"

                    result_text += f"{i+1}. {dump_file} ({size_mb} MB)\n"

                return [TextContent(
                    type="text",
                    text=result_text
                )]

            raise McpError(ErrorData(
                code=INVALID_PARAMS,
                message=f"Unknown tool: {name}"
            ))

        except McpError:
            raise
        except Exception as e:
            traceback_str = traceback.format_exc()
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error executing tool {name}: {str(e)}\n{traceback_str}"
            ))

    # Prompt constants
    DUMP_TRIAGE_PROMPT_NAME = "dump-triage"
    DUMP_TRIAGE_PROMPT_TITLE = "Crash Dump Triage Analysis"
    DUMP_TRIAGE_PROMPT_DESCRIPTION = "Comprehensive single crash dump analysis with detailed metadata extraction and structured reporting"

    # Define available prompts for triage analysis
    @server.list_prompts()
    async def list_prompts() -> list[Prompt]:
        return [
            Prompt(
                name=DUMP_TRIAGE_PROMPT_NAME,
                title=DUMP_TRIAGE_PROMPT_TITLE,
                description=DUMP_TRIAGE_PROMPT_DESCRIPTION,
                arguments=[
                    PromptArgument(
                        name="dump_path",
                        description="Path to the Windows crash dump file to analyze (optional - will prompt if not provided)",
                        required=False,
                    ),
                ],
            ),
        ]

    @server.get_prompt()
    async def get_prompt(name: str, arguments: dict | None) -> GetPromptResult:
        if arguments is None:
            arguments = {}

        if name == DUMP_TRIAGE_PROMPT_NAME:
            dump_path = arguments.get("dump_path", "")
            try:
                prompt_content = load_prompt("dump-triage")
            except FileNotFoundError as e:
                raise McpError(ErrorData(
                    code=INTERNAL_ERROR,
                    message=f"Prompt file not found: {e}"
                ))

            # If dump_path is provided, prepend it to the prompt
            if dump_path:
                prompt_text = f"**Dump file to analyze:** {dump_path}\n\n{prompt_content}"
            else:
                prompt_text = prompt_content

            return GetPromptResult(
                description=DUMP_TRIAGE_PROMPT_DESCRIPTION,
                messages=[
                    PromptMessage(
                        role="user",
                        content=TextContent(
                            type="text",
                            text=prompt_text
                        ),
                    ),
                ],
            )

        else:
            raise McpError(ErrorData(
                code=INVALID_PARAMS,
                message=f"Unknown prompt: {name}"
            ))

    return server


# Clean up function to ensure all sessions are closed when the server exits
def cleanup_sessions():
    """Close all active CDB sessions."""
    upload_sessions.cleanup_sessions()


# Register cleanup on module exit
atexit.register(cleanup_sessions)
