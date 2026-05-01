import os
import threading
import time
from types import SimpleNamespace
import pytest

import dump_analyzer_mcp_server.cdb_session as cdb_session_module
from dump_analyzer_mcp_server.cdb_session import CDBSession
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


def test_send_command_serializes_concurrent_calls():
    """Concurrent callers should not interleave commands on one CDB process."""
    session = object.__new__(CDBSession)
    session.process = SimpleNamespace()
    session.timeout = 1
    session.verbose = False
    session.command_lock = threading.Lock()
    session._state_lock = threading.Lock()
    session._active_execution = None
    session._request_counter = 0

    active_writes = 0
    max_active_writes = 0
    state_lock = threading.Lock()
    first_command_entered = threading.Event()
    allow_first_command_to_finish = threading.Event()
    commands_seen = []

    class FakeStdin:
        def write(self, payload: bytes) -> None:
            nonlocal active_writes, max_active_writes
            command = payload.decode("utf-8").splitlines()[0]
            commands_seen.append(command)
            with state_lock:
                active_writes += 1
                max_active_writes = max(max_active_writes, active_writes)

            if command == "r":
                first_command_entered.set()
                allow_first_command_to_finish.wait(timeout=1)

            execution = session._active_execution
            execution.output_lines.append(f"out:{command}")
            execution.completed = True
            execution.done_event.set()

            with state_lock:
                active_writes -= 1

        def flush(self) -> None:
            return None

    session.process.stdin = FakeStdin()

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


def test_find_cdb_executable_prefers_custom_path(monkeypatch):
    monkeypatch.setattr(cdb_session_module.os.path, "isfile", lambda path: path == r"C:\custom\cdb.exe")

    session = object.__new__(CDBSession)

    assert session._find_cdb_executable(r"C:\custom\cdb.exe") == r"C:\custom\cdb.exe"


def test_execute_command_heartbeat_callback_invoked():
    session = object.__new__(CDBSession)
    session.process = SimpleNamespace()
    session.timeout = 1
    session.verbose = False
    session.command_lock = threading.Lock()
    session._state_lock = threading.Lock()
    session._active_execution = None
    session._request_counter = 0

    class FakeStdin:
        def write(self, payload: bytes) -> None:
            execution = session._active_execution
            def _complete_later():
                # Sleep longer than execute_command queue poll timeout (0.2s)
                # to make heartbeat callback deterministic.
                time.sleep(0.35)
                execution.output_lines.append("line")
                execution.completed = True
                execution.done_event.set()

            threading.Thread(target=_complete_later, daemon=True).start()

        def flush(self) -> None:
            return None

    session.process.stdin = FakeStdin()
    heartbeats = []
    result = session.execute_command("kb", timeout=1, on_heartbeat=lambda: heartbeats.append("hb"), heartbeat_interval=0.01)
    assert result["output_lines"] == ["line"]
    assert len(heartbeats) >= 1

if __name__ == "__main__":
    pytest.main(["-v", __file__])
