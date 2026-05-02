import io
import logging
import os
import queue
import threading
import time
from types import SimpleNamespace
import pytest

import dump_analyzer_mcp_server.cdb_session as cdb_session_module
from dump_analyzer_mcp_server.cdb_session import CDBSession, COMMAND_MARKER_TEXT
from dump_analyzer_mcp_server.logging_utils import bind_context
from tests.test_support import has_available_cdb

# Path to the test dump file
TEST_DUMP_PATH = os.path.join(os.path.dirname(__file__), "dumps", "DemoCrash1.exe.7088.dmp")

def setup_cdb_session():
    """Helper function to create a CDB session"""
    if not os.path.exists(TEST_DUMP_PATH):
        pytest.skip("Test dump file not found")

    if not has_available_cdb():
        pytest.skip("CDB executable not found")

    return CDBSession(
        dump_path=TEST_DUMP_PATH,
        timeout=20,
        verbose=True
    )

def test_basic_cdb_command():
    """Test basic CDB command execution"""
    session = setup_cdb_session()
    try:
        output = session.send_command("version")
        assert len(output) > 0
        assert any("Microsoft (R) Windows Debugger" in line for line in output)
    finally:
        session.shutdown()


def _build_fake_session(write_handler):
    session = object.__new__(CDBSession)
    session.timeout = 1
    session.verbose = False
    session.log_context = {"file_id": "file-1", "session_id": "session-1"}
    session.logger = bind_context(
        logging.getLogger("dump_analyzer_mcp_server.cdb_session"),
        event="cdb.session",
        file_id="file-1",
        session_id="session-1",
    )
    session._state_lock = threading.Lock()
    session._request_counter = 0
    session._symbol_diagnostics_enabled = False
    session._active_job = None
    session._jobs = {}
    session._job_queue = queue.Queue()
    session._shutdown_event = threading.Event()
    session.process = SimpleNamespace(
        stdin=SimpleNamespace(write=lambda payload: write_handler(session, payload), flush=lambda: None),
        poll=lambda: None,
    )
    session._worker_thread = threading.Thread(target=session._worker_loop, daemon=True)
    session._worker_thread.start()
    return session


def test_send_command_serializes_concurrent_calls():
    """Concurrent callers should not interleave commands on one CDB process."""
    active_writes = 0
    max_active_writes = 0
    state_lock = threading.Lock()
    first_command_entered = threading.Event()
    allow_first_command_to_finish = threading.Event()
    commands_seen = []

    def write_handler(session, payload: bytes) -> None:
        nonlocal active_writes, max_active_writes
        command = payload.decode("utf-8").splitlines()[0]
        commands_seen.append(command)
        with state_lock:
            active_writes += 1
            max_active_writes = max(max_active_writes, active_writes)

        def complete():
            if command == "r":
                first_command_entered.set()
                allow_first_command_to_finish.wait(timeout=1)
            session._emit_line(f"out:{command}")
            session._emit_line(COMMAND_MARKER_TEXT)
            with state_lock:
                nonlocal active_writes
                active_writes -= 1

        threading.Thread(target=complete, daemon=True).start()

    session = _build_fake_session(write_handler)

    results = {}

    def run_command(key: str, command: str) -> None:
        results[key] = session.send_command(command)

    first = threading.Thread(target=run_command, args=("first", "r"))
    second = threading.Thread(target=run_command, args=("second", "kb"))

    first.start()
    assert first_command_entered.wait(timeout=1)
    second.start()
    time.sleep(0.05)
    allow_first_command_to_finish.set()

    first.join(timeout=1)
    second.join(timeout=1)

    assert results["first"] == ["out:r"]
    assert results["second"] == ["out:kb"]
    assert commands_seen == ["r", "kb"]
    assert max_active_writes == 1
    session._shutdown_event.set()


def test_find_cdb_executable_prefers_custom_path(monkeypatch):
    monkeypatch.setattr(cdb_session_module.os.path, "isfile", lambda path: path == r"C:\custom\cdb.exe")

    session = object.__new__(CDBSession)

    assert session._find_cdb_executable(r"C:\custom\cdb.exe") == r"C:\custom\cdb.exe"


def test_execute_command_heartbeat_callback_invoked():
    def write_handler(session, _payload: bytes) -> None:
        def _complete_later():
            time.sleep(0.35)
            session._emit_line("line")
            session._emit_line(COMMAND_MARKER_TEXT)

        threading.Thread(target=_complete_later, daemon=True).start()

    session = _build_fake_session(write_handler)
    heartbeats = []
    result = session.execute_command("kb", timeout=1, on_heartbeat=lambda: heartbeats.append("hb"), heartbeat_interval=0.01)
    assert result["output_lines"] == ["line"]
    assert len(heartbeats) >= 1
    session._shutdown_event.set()


def test_execute_command_timeout_returns_while_background_job_keeps_running():
    allow_completion = threading.Event()

    def write_handler(session, _payload: bytes) -> None:
        def _complete_later():
            allow_completion.wait(timeout=1)
            session._emit_line("late-line")
            session._emit_line(COMMAND_MARKER_TEXT)

        threading.Thread(target=_complete_later, daemon=True).start()

    session = _build_fake_session(write_handler)
    heartbeats = []

    result = session.execute_command(
        "kb",
        timeout=0.05,
        on_heartbeat=lambda: heartbeats.append("hb"),
        heartbeat_interval=0.01,
    )

    assert result["status"] == "timeout"
    assert result["timed_out"] is True
    assert result["background_running"] is True
    pending = session.get_pending_command()
    assert pending is not None
    allow_completion.set()
    final_result = session.wait_for_command_result(result["request_id"], wait_timeout=1)
    assert final_result["status"] == "completed"
    assert "late-line" in final_result["output_lines"]
    session._shutdown_event.set()


def test_queued_command_reports_queue_wait_time():
    first_can_finish = threading.Event()
    first_started = threading.Event()

    def write_handler(session, payload: bytes) -> None:
        command = payload.decode("utf-8").splitlines()[0]

        def _complete_later():
            if command == "first":
                first_started.set()
                first_can_finish.wait(timeout=1)
            session._emit_line(f"line:{command}")
            session._emit_line(COMMAND_MARKER_TEXT)

        threading.Thread(target=_complete_later, daemon=True).start()

    session = _build_fake_session(write_handler)
    first_job = session.start_async_command("first")
    assert first_started.wait(timeout=1)
    second_job = session.start_async_command("second")
    time.sleep(0.1)
    first_can_finish.set()
    result = session.wait_for_command_result(second_job["request_id"], wait_timeout=1)
    assert result["status"] == "completed"
    assert result["queue_wait_ms"] is not None
    assert result["queue_wait_ms"] > 0
    assert result["execution_time_ms"] >= 0
    session._shutdown_event.set()


def test_execute_command_logs_request_context(caplog):
    def write_handler(session, _payload: bytes) -> None:
        session._emit_line("out:kb")
        session._emit_line(COMMAND_MARKER_TEXT)

    session = _build_fake_session(write_handler)

    with caplog.at_level(logging.INFO, logger="dump_analyzer_mcp_server.cdb_session"):
        result = session.execute_command("kb", timeout=1)

    assert result["request_id"] == "1"
    command_records = [record for record in caplog.records if getattr(record, "event", "") == "cdb.command"]
    assert command_records
    assert any(getattr(record, "request_id", "") == "1" for record in command_records)
    assert all(getattr(record, "session_id", "") == "session-1" for record in command_records)
    session._shutdown_event.set()


def test_verbose_reader_logs_truncated_output(caplog):
    session = object.__new__(CDBSession)
    session.process = SimpleNamespace(stdout=io.BytesIO((b"A" * 450) + b"\n"))
    session.timeout = 1
    session.verbose = True
    session._state_lock = threading.Lock()
    session._active_job = None
    session._request_counter = 0
    session.log_context = {"file_id": "file-1", "session_id": "session-1"}
    session.logger = bind_context(
        logging.getLogger("dump_analyzer_mcp_server.cdb_session"),
        event="cdb.session",
        file_id="file-1",
        session_id="session-1",
    )
    session._shutdown_event = threading.Event()

    with caplog.at_level(logging.DEBUG, logger="dump_analyzer_mcp_server.cdb_session"):
        session._read_output_bytes()

    messages = "\n".join(record.getMessage() for record in caplog.records)
    assert "<truncated>" in messages
    assert "A" * 430 not in messages

if __name__ == "__main__":
    pytest.main(["-v", __file__])
