import os
import threading
import time
from types import SimpleNamespace
import pytest

import mcp_windbg.cdb_session as cdb_session_module
from mcp_windbg.cdb_session import CDBSession, CDBError
from mcp_windbg.tests.test_support import has_available_cdb

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

def test_command_sequence():
    """Test multiple commands in sequence"""
    session = setup_cdb_session()
    try:
        # Basic command sequence
        commands = ["version", ".sympath", "!analyze -v", "lm", "~"]
        results = []

        for cmd in commands:
            output = session.send_command(cmd)
            results.append((cmd, output))
            assert len(output) > 0

        # Check expected output patterns
        assert any("Microsoft (R) Windows Debugger" in line for line in results[0][1])
        assert any("Symbol search path is:" in line for line in results[1][1])
        assert any("start" in line.lower() for line in results[3][1])
    finally:
        session.shutdown()

def test_module_inspection():
    """Test module inspection capabilities"""
    session = setup_cdb_session()
    try:
        # Get module list
        modules_output = session.send_command("lm")

        # Find a common Windows module
        target_modules = ['ntdll', 'kernel32']
        module_name = None

        for target in target_modules:
            for line in modules_output:
                if target in line.lower():
                    parts = line.split()
                    for part in parts:
                        if target in part.lower():
                            module_name = part
                            break
                    if module_name:
                        break
            if module_name:
                break

        assert module_name is not None

        # Get module details
        module_info = session.send_command(f"lmv m {module_name}")
        assert len(module_info) > 0
        assert any(module_name.lower() in line.lower() for line in module_info)

        # Get stack info
        stack_info = session.send_command("k 5")
        assert len(stack_info) > 0
    finally:
        session.shutdown()

def test_thread_context():
    """Test thread context operations"""
    session = setup_cdb_session()
    try:
        # Get thread list
        thread_list = session.send_command("~")

        # Select first thread
        thread_id = "0"
        for line in thread_list:
            if line.strip().startswith("#"):
                parts = line.split()
                if len(parts) > 1:
                    thread_id = parts[1].strip(":")
                    break

        # Switch to thread and check registers
        session.send_command(f"~{thread_id}s")
        registers = session.send_command("r")
        assert len(registers) > 0
        assert any("eax" in line.lower() or "rax" in line.lower() for line in registers)

        # Check stack trace
        stack = session.send_command("k")
        assert len(stack) > 0
    finally:
        session.shutdown()


def test_send_command_serializes_concurrent_calls():
    """Concurrent callers should not interleave commands on one CDB process."""
    session = object.__new__(CDBSession)
    session.process = SimpleNamespace()
    session.timeout = 1
    session.verbose = False
    session.output_lines = []
    session.lock = threading.Lock()
    session.command_lock = threading.Lock()
    session.ready_event = threading.Event()

    active_writes = 0
    max_active_writes = 0
    state_lock = threading.Lock()
    first_command_entered = threading.Event()
    allow_first_command_to_finish = threading.Event()
    commands_seen = []

    class FakeStdin:
        def write(self, payload: str) -> None:
            nonlocal active_writes, max_active_writes
            command = payload.splitlines()[0]
            commands_seen.append(command)
            with state_lock:
                active_writes += 1
                max_active_writes = max(max_active_writes, active_writes)

            if command == "r":
                first_command_entered.set()
                allow_first_command_to_finish.wait(timeout=1)

            session.output_lines = [f"out:{command}"]
            session.ready_event.set()

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


def test_find_cdb_executable_prefers_cdb_path_env(monkeypatch):
    monkeypatch.setenv("CDB_PATH", r"C:\custom\cdb.exe")
    monkeypatch.setattr(cdb_session_module.os.path, "isfile", lambda path: path == r"C:\custom\cdb.exe")

    session = object.__new__(CDBSession)

    assert session._find_cdb_executable() == r"C:\custom\cdb.exe"

if __name__ == "__main__":
    pytest.main(["-v", __file__])
