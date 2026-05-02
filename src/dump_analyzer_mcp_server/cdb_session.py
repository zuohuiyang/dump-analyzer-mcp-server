import logging
import os
import queue
import subprocess
import threading
import time
import ctypes
from dataclasses import dataclass, field
from ctypes import wintypes
from typing import Callable, Optional

from .logging_utils import (
    bind_context,
    make_context,
    normalize_output_line_for_log,
    sanitize_command,
    sanitize_exception_message,
    sanitize_path,
)

logger = logging.getLogger(__name__)

COMMAND_MARKER_TEXT = "COMMAND_COMPLETED_MARKER"
COMMAND_MARKER = f".echo {COMMAND_MARKER_TEXT}"
MAX_COMMAND_WALL_TIME_HARD_LIMIT_SECONDS = 6 * 60 * 60
MIN_SUPPORTED_WINDOWS_SDK_BUILD = 26100

DEFAULT_CDB_PATHS = [
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe",
    r"C:\Program Files\Debugging Tools for Windows (x64)\cdb.exe",
    r"C:\Program Files\Debugging Tools for Windows (x86)\cdb.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\cdbX64.exe"),
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\cdbX86.exe"),
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\cdbARM64.exe"),
]


class VS_FIXEDFILEINFO(ctypes.Structure):
    _fields_ = [
        ("dwSignature", wintypes.DWORD),
        ("dwStrucVersion", wintypes.DWORD),
        ("dwFileVersionMS", wintypes.DWORD),
        ("dwFileVersionLS", wintypes.DWORD),
        ("dwProductVersionMS", wintypes.DWORD),
        ("dwProductVersionLS", wintypes.DWORD),
        ("dwFileFlagsMask", wintypes.DWORD),
        ("dwFileFlags", wintypes.DWORD),
        ("dwFileOS", wintypes.DWORD),
        ("dwFileType", wintypes.DWORD),
        ("dwFileSubtype", wintypes.DWORD),
        ("dwFileDateMS", wintypes.DWORD),
        ("dwFileDateLS", wintypes.DWORD),
    ]


def resolve_cdb_executable(custom_path: Optional[str] = None) -> Optional[str]:
    if custom_path and os.path.isfile(custom_path):
        return custom_path
    for path in DEFAULT_CDB_PATHS:
        if os.path.isfile(path):
            return path
    return None


def get_binary_file_version(path: str) -> Optional[tuple[int, int, int, int]]:
    try:
        ignored = wintypes.DWORD()
        size = ctypes.windll.version.GetFileVersionInfoSizeW(path, ctypes.byref(ignored))
        if size <= 0:
            return None

        buffer = ctypes.create_string_buffer(size)
        success = ctypes.windll.version.GetFileVersionInfoW(path, 0, size, buffer)
        if not success:
            return None

        version_ptr = ctypes.c_void_p()
        version_len = wintypes.UINT()
        success = ctypes.windll.version.VerQueryValueW(
            buffer,
            "\\",
            ctypes.byref(version_ptr),
            ctypes.byref(version_len),
        )
        if not success or version_len.value == 0:
            return None

        fixed_info = ctypes.cast(version_ptr, ctypes.POINTER(VS_FIXEDFILEINFO)).contents
    except (AttributeError, OSError, ValueError):
        return None

    return (
        (fixed_info.dwFileVersionMS >> 16) & 0xFFFF,
        fixed_info.dwFileVersionMS & 0xFFFF,
        (fixed_info.dwFileVersionLS >> 16) & 0xFFFF,
        fixed_info.dwFileVersionLS & 0xFFFF,
    )


def get_cdb_windows_sdk_build(cdb_path: str) -> Optional[int]:
    version = get_binary_file_version(cdb_path)
    if version is None:
        return None
    return version[2]


def resolve_and_validate_cdb_path(
    custom_path: Optional[str] = None,
    *,
    min_sdk_build: int = MIN_SUPPORTED_WINDOWS_SDK_BUILD,
) -> str:
    cdb_path = resolve_cdb_executable(custom_path)
    if not cdb_path:
        raise CDBError("Could not find cdb.exe. Please provide a valid path.")

    sdk_build = get_cdb_windows_sdk_build(cdb_path)
    if sdk_build is None:
        raise CDBError(
            f"Could not determine the Windows SDK version of cdb.exe: {cdb_path}"
        )
    if sdk_build < min_sdk_build:
        raise CDBError(
            "Unsupported Windows SDK version for cdb.exe: "
            f"detected build {sdk_build}, but build {min_sdk_build} or newer is required."
        )
    return cdb_path


class CDBError(Exception):
    """Custom exception for CDB-related errors."""


@dataclass
class CommandJob:
    job_id: str
    command: str
    created_at: float
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    first_output_at: Optional[float] = None
    last_output_at: Optional[float] = None
    status: str = "queued"
    output_lines: list[str] = field(default_factory=list)
    error_message: Optional[str] = None
    completed_event: threading.Event = field(default_factory=threading.Event, repr=False)


class CDBSession:
    def __init__(
        self,
        dump_path: str,
        cdb_path: Optional[str] = None,
        symbols_path: Optional[str] = None,
        timeout: int = 10,
        verbose: bool = False,
        log_context: Optional[dict[str, str]] = None,
    ):
        if not dump_path:
            raise ValueError("dump_path is required")
        if not os.path.isfile(dump_path):
            raise FileNotFoundError(f"Dump file not found: {dump_path}")

        self.dump_path = dump_path
        self.timeout = timeout
        self.verbose = verbose
        self.log_context = dict(log_context or {})
        self.logger = bind_context(
            logger,
            event="cdb.session",
            request_id=self.log_context.get("request_id"),
            file_id=self.log_context.get("file_id"),
            session_id=self.log_context.get("session_id"),
        )
        self._state_lock = threading.Lock()
        self._request_counter = 0
        self._symbol_diagnostics_enabled = False
        self._active_job: Optional[CommandJob] = None
        self._jobs: dict[str, CommandJob] = {}
        self._job_queue: queue.Queue[CommandJob] = queue.Queue()
        self._shutdown_event = threading.Event()

        self.cdb_path = self._find_cdb_executable(cdb_path)
        if not self.cdb_path:
            self.logger.error(
                "Could not resolve cdb executable",
                extra=make_context(outcome="missing"),
            )
            raise CDBError("Could not find cdb.exe. Please provide a valid path.")

        cmd_args = [self.cdb_path, "-z", self.dump_path]
        if symbols_path:
            cmd_args.extend(["-y", symbols_path])

        try:
            self.process = subprocess.Popen(
                cmd_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=False,
                bufsize=0,
            )
        except Exception as exc:
            self.logger.exception(
                "Failed to start CDB process: %s",
                sanitize_exception_message(str(exc)),
                extra=make_context(outcome="error"),
            )
            raise CDBError(f"Failed to start CDB process: {exc}")

        self.logger.info(
            "Started CDB process for dump=%s cdb=%s symbols=%s",
            sanitize_path(self.dump_path),
            sanitize_path(self.cdb_path),
            sanitize_path(symbols_path),
            extra=make_context(outcome="started"),
        )

        self._reader_thread = threading.Thread(target=self._read_output_bytes, daemon=True)
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._reader_thread.start()
        self._worker_thread.start()

        time.sleep(0.2)
        if self.process.poll() is not None:
            self.shutdown()
            self.logger.error(
                "CDB process exited during initialization",
                extra=make_context(outcome="error"),
            )
            raise CDBError("CDB process exited during initialization")

    def _ensure_logger(self):
        current = getattr(self, "logger", None)
        if current is not None:
            return current
        log_context = getattr(self, "log_context", {}) or {}
        current = bind_context(
            logger,
            event="cdb.session",
            request_id=log_context.get("request_id"),
            file_id=log_context.get("file_id"),
            session_id=log_context.get("session_id"),
        )
        self.logger = current
        return current

    def _find_cdb_executable(self, custom_path: Optional[str] = None) -> Optional[str]:
        return resolve_cdb_executable(custom_path)

    def _next_request_id(self) -> str:
        with self._state_lock:
            self._request_counter += 1
            return str(self._request_counter)

    def _get_job(self, job_id: str) -> CommandJob:
        with self._state_lock:
            job = self._jobs.get(job_id)
        if job is None:
            raise CDBError(f"Unknown command job: {job_id}")
        return job

    def _build_job_result(
        self,
        job: CommandJob,
        *,
        now: Optional[float] = None,
        override_status: Optional[str] = None,
        timed_out: bool = False,
        cancelled: bool = False,
    ) -> dict:
        current = now if now is not None else time.time()
        status = override_status or job.status
        queue_wait_ms = None
        if job.started_at is not None:
            queue_wait_ms = int((job.started_at - job.created_at) * 1000)
        elif current >= job.created_at:
            queue_wait_ms = int((current - job.created_at) * 1000)

        first_output_delay_ms = None
        if job.started_at is not None and job.first_output_at is not None:
            first_output_delay_ms = int((job.first_output_at - job.started_at) * 1000)

        execution_time_ms = 0
        if job.started_at is not None:
            end_time = job.completed_at if job.completed_at is not None else current
            execution_time_ms = int((end_time - job.started_at) * 1000)

        return {
            "request_id": job.job_id,
            "command": job.command,
            "output_lines": job.output_lines.copy(),
            "output_line_count": len(job.output_lines),
            "cancelled": cancelled,
            "timed_out": timed_out,
            "status": status,
            "first_output_delay_ms": first_output_delay_ms,
            "queue_wait_ms": queue_wait_ms,
            "execution_time_ms": execution_time_ms,
            "started": job.started_at is not None,
            "completed": job.completed_event.is_set(),
            "background_running": not job.completed_event.is_set(),
            "error_message": job.error_message,
        }

    def _submit_job(self, command: str) -> CommandJob:
        if not self.process or not self.process.stdin:
            raise CDBError("CDB process is not running")
        job = CommandJob(job_id=self._next_request_id(), command=command, created_at=time.time())
        with self._state_lock:
            self._jobs[job.job_id] = job
        self._job_queue.put(job)
        self._ensure_logger().info(
            "Queued CDB command",
            extra=make_context(
                event="cdb.command",
                outcome="queued",
                request_id=job.job_id,
                command_preview=sanitize_command(job.command),
            ),
        )
        return job

    def _emit_line(self, text: str) -> None:
        session_logger = self._ensure_logger()
        log_message = None
        log_context = None
        with self._state_lock:
            job = self._active_job
            if job is None:
                return
            if COMMAND_MARKER_TEXT in text:
                if job.status in {"queued", "running"}:
                    job.status = "completed"
                job.completed_at = time.time()
                job.completed_event.set()
                log_message = "Detected command completion marker"
                log_context = make_context(
                    event="cdb.command",
                    outcome="marker_detected",
                    request_id=job.job_id,
                    command_preview=sanitize_command(job.command),
                )
            else:
                now = time.time()
                first_output = job.first_output_at is None
                if first_output:
                    job.first_output_at = now
                    session_logger.info(
                        "First output received for CDB command",
                        extra=make_context(
                            event="cdb.command",
                            outcome="first_output",
                            request_id=job.job_id,
                            command_preview=sanitize_command(job.command),
                        ),
                    )
                job.last_output_at = now
                job.output_lines.append(text)
                log_message = normalize_output_line_for_log(text)
                log_context = make_context(
                    event="cdb.output",
                    outcome="line",
                    request_id=job.job_id,
                    command_preview=sanitize_command(job.command),
                )
        if log_message is not None and log_context is not None:
            session_logger.info(log_message, extra=log_context)

    def _read_output_bytes(self) -> None:
        if not self.process or not self.process.stdout:
            return
        buffer = bytearray()
        skip_next_lf = False
        try:
            while not self._shutdown_event.is_set():
                chunk = self.process.stdout.read(1)
                if not chunk:
                    break
                if skip_next_lf and chunk == b"\n":
                    skip_next_lf = False
                    continue
                skip_next_lf = False
                if chunk in (b"\r", b"\n"):
                    if chunk == b"\r":
                        skip_next_lf = True
                    line = buffer.decode("utf-8", errors="replace")
                    buffer.clear()
                    self._emit_line(line)
                    continue
                buffer.extend(chunk)
        except (IOError, ValueError) as exc:
            if self.verbose:
                self.logger.warning(
                    "CDB output reader error: %s",
                    sanitize_exception_message(str(exc)),
                    extra=make_context(event="cdb.output", outcome="error"),
                )
        finally:
            if buffer:
                self._emit_line(buffer.decode("utf-8", errors="replace"))

    def _finalize_active_job(self, *, status: str, error_message: Optional[str] = None) -> None:
        with self._state_lock:
            job = self._active_job
            if job is None:
                return
            job.status = status
            job.error_message = error_message
            job.completed_at = time.time()
            job.completed_event.set()

    def _worker_loop(self) -> None:
        while not self._shutdown_event.is_set():
            try:
                job = self._job_queue.get(timeout=0.1)
            except queue.Empty:
                continue

            if self._shutdown_event.is_set():
                break

            session_logger = self._ensure_logger()
            command_preview = sanitize_command(job.command)
            with self._state_lock:
                self._active_job = job
                job.started_at = time.time()
                job.status = "running"

            session_logger.info(
                "Executing CDB command",
                extra=make_context(
                    event="cdb.command",
                    outcome="started",
                    request_id=job.job_id,
                    command_preview=command_preview,
                ),
            )

            try:
                self.process.stdin.write(f"{job.command}\n{COMMAND_MARKER}\n".encode("utf-8"))
                self.process.stdin.flush()
            except IOError as exc:
                session_logger.exception(
                    "Failed to send command to CDB: %s",
                    sanitize_exception_message(str(exc)),
                    extra=make_context(
                        event="cdb.command",
                        outcome="error",
                        request_id=job.job_id,
                        command_preview=command_preview,
                    ),
                )
                self._finalize_active_job(status="failed", error_message=f"Failed to send command: {exc}")
            else:
                deadline = time.time() + MAX_COMMAND_WALL_TIME_HARD_LIMIT_SECONDS
                while not self._shutdown_event.is_set() and not job.completed_event.wait(timeout=0.2):
                    if self.process and self.process.poll() is not None:
                        self._finalize_active_job(status="failed", error_message="CDB process exited during command execution")
                        break
                    if time.time() > deadline:
                        self._finalize_active_job(
                            status="failed",
                            error_message=f"Command exceeded max wall time after {MAX_COMMAND_WALL_TIME_HARD_LIMIT_SECONDS} seconds: {job.command}",
                        )
                        break
                if job.completed_event.is_set() and job.command.strip().lower() == "!sym noisy" and job.status == "completed":
                    with self._state_lock:
                        self._symbol_diagnostics_enabled = True

            session_logger.info(
                "CDB command finished with status=%s in %sms with %s output lines",
                job.status,
                self._build_job_result(job)["execution_time_ms"],
                len(job.output_lines),
                extra=make_context(
                    event="cdb.command",
                    outcome="success" if job.status == "completed" else job.status,
                    request_id=job.job_id,
                    command_preview=command_preview,
                ),
            )

            with self._state_lock:
                self._active_job = None

    def has_pending_command(self) -> bool:
        with self._state_lock:
            if self._active_job and not self._active_job.completed_event.is_set():
                return True
            return any(not job.completed_event.is_set() for job in self._jobs.values())

    def get_pending_command(self) -> Optional[dict]:
        with self._state_lock:
            if self._active_job and not self._active_job.completed_event.is_set():
                return self._build_job_result(self._active_job)
            for job in self._jobs.values():
                if not job.completed_event.is_set():
                    return self._build_job_result(job)
        return None

    def start_async_command(self, command: str) -> dict:
        job = self._submit_job(command)
        return self._build_job_result(job)

    def get_command_status(self, job_id: str) -> dict:
        return self._build_job_result(self._get_job(job_id))

    def wait_for_command_result(
        self,
        job_id: str,
        wait_timeout: float = 0,
        on_output: Optional[Callable[[str], None]] = None,
        on_heartbeat: Optional[Callable[[], None]] = None,
        heartbeat_interval: float = 5.0,
        cancel_event: Optional[threading.Event] = None,
    ) -> dict:
        job = self._get_job(job_id)
        wait_started_at = time.time()
        last_heartbeat_at = wait_started_at
        next_output_index = 0

        while True:
            with self._state_lock:
                new_lines = job.output_lines[next_output_index:]
                completed = job.completed_event.is_set()
            for line in new_lines:
                if on_output:
                    on_output(line)
            next_output_index += len(new_lines)

            if completed:
                result = self._build_job_result(job)
                if result["status"] == "failed" and job.error_message:
                    raise CDBError(job.error_message)
                return result

            if cancel_event and cancel_event.is_set():
                return self._build_job_result(job, override_status="cancelled", cancelled=True)

            if wait_timeout > 0 and (time.time() - wait_started_at) >= wait_timeout:
                self._ensure_logger().warning(
                    "Foreground wait timed out; command continues in background",
                    extra=make_context(
                        event="cdb.command",
                        outcome="timeout",
                        request_id=job.job_id,
                        command_preview=sanitize_command(job.command),
                    ),
                )
                return self._build_job_result(job, override_status="timeout", timed_out=True)

            if on_heartbeat and heartbeat_interval > 0 and (time.time() - last_heartbeat_at) >= heartbeat_interval:
                on_heartbeat()
                last_heartbeat_at = time.time()

            time.sleep(0.2)

    def ensure_symbol_diagnostics(self, timeout: Optional[int] = None) -> dict:
        with self._state_lock:
            if self._symbol_diagnostics_enabled:
                return {
                    "request_id": "0",
                    "command": "!sym noisy",
                    "output_lines": [],
                    "output_line_count": 0,
                    "cancelled": False,
                    "timed_out": False,
                    "status": "completed",
                    "first_output_delay_ms": None,
                    "queue_wait_ms": 0,
                    "execution_time_ms": 0,
                    "started": True,
                    "completed": True,
                    "background_running": False,
                    "error_message": None,
                }
        result = self.execute_command("!sym noisy", timeout=timeout)
        if result["status"] != "completed":
            raise CDBError("Failed to enable symbol diagnostics")
        return result

    def send_command(self, command: str, timeout: Optional[int] = None) -> list[str]:
        if not self.process:
            raise CDBError("CDB process is not running")
        return self.execute_command(command, timeout=timeout)["output_lines"]

    def execute_command(
        self,
        command: str,
        timeout: Optional[int] = None,
        on_output: Optional[Callable[[str], None]] = None,
        on_heartbeat: Optional[Callable[[], None]] = None,
        heartbeat_interval: float = 5.0,
        cancel_event: Optional[threading.Event] = None,
    ) -> dict:
        job = self._submit_job(command)
        return self.wait_for_command_result(
            job.job_id,
            wait_timeout=float(timeout or self.timeout),
            on_output=on_output,
            on_heartbeat=on_heartbeat,
            heartbeat_interval=heartbeat_interval,
            cancel_event=cancel_event,
        )

    def shutdown(self):
        session_logger = self._ensure_logger()
        self._shutdown_event.set()
        try:
            if self.process and self.process.poll() is None:
                try:
                    self.process.stdin.write("q\n")
                    self.process.stdin.flush()
                    self.process.wait(timeout=1)
                except Exception:
                    pass
                if self.process.poll() is None:
                    self.process.terminate()
                    self.process.wait(timeout=3)
        except Exception as exc:
            session_logger.exception(
                "Error during CDB shutdown: %s",
                sanitize_exception_message(str(exc)),
                extra=make_context(event="cdb.session", outcome="error"),
            )
        finally:
            with self._state_lock:
                active_job = self._active_job
                self.process = None
            if active_job and not active_job.completed_event.is_set():
                active_job.status = "failed"
                active_job.error_message = "CDB session was shut down before the command completed"
                active_job.completed_at = time.time()
                active_job.completed_event.set()
            session_logger.info(
                "CDB session shutdown completed",
                extra=make_context(event="cdb.session", outcome="stopped"),
            )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()
