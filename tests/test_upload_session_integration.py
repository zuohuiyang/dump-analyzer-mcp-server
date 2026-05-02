import asyncio
import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp.types import CallToolRequest

from dump_analyzer_mcp_server import server


pytestmark = pytest.mark.usefixtures("restore_upload_runtime_state")


class _FakeSession:
    created = 0
    shutdown_count = 0
    last_instance = None

    def __init__(self, dump_path=None, **_kwargs):
        type(self).created += 1
        type(self).last_instance = self
        self.dump_path = dump_path
        self.commands = []
        self.symbol_diagnostics_enabled = False
        self.jobs = {}
        self.next_job_id = 1
        self.pending_job_id = None

    def send_command(self, command):
        self.commands.append(command)
        return [f"fake:{command}"]

    def execute_command(self, command, _timeout=None, on_output=None, on_heartbeat=None, _heartbeat_interval=None, cancel_event=None):
        self.commands.append(command)
        if command == "!sym noisy":
            self.symbol_diagnostics_enabled = True
        if on_output:
            on_output(f"fake:{command}")
        if on_heartbeat:
            on_heartbeat()
        if command == "timeout_no_output":
            return {
                "request_id": "1",
                "command": command,
                "output_lines": [],
                "output_line_count": 0,
                "cancelled": False,
                "timed_out": True,
                "status": "timeout",
                "first_output_delay_ms": None,
                "queue_wait_ms": 0,
                "execution_time_ms": 10,
                "started": True,
                "completed": False,
                "background_running": True,
                "error_message": None,
            }
        return {
            "request_id": "1",
            "command": command,
            "output_lines": [f"fake:{command}"],
            "output_line_count": 1,
            "cancelled": bool(cancel_event and cancel_event.is_set()),
            "timed_out": False,
            "status": "cancelled" if bool(cancel_event and cancel_event.is_set()) else "completed",
            "first_output_delay_ms": 1,
            "queue_wait_ms": 0,
            "execution_time_ms": 10,
            "started": True,
            "completed": True,
            "background_running": False,
            "error_message": None,
        }

    def ensure_symbol_diagnostics(self, timeout=None):
        if self.symbol_diagnostics_enabled:
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
        return self.execute_command("!sym noisy", timeout)

    def start_async_command(self, command):
        self.commands.append(command)
        command_id = str(self.next_job_id)
        self.next_job_id += 1
        self.jobs[command_id] = {
            "request_id": command_id,
            "command": command,
            "output_lines": [f"fake:{command}"],
            "output_line_count": 1,
            "cancelled": False,
            "timed_out": False,
            "status": "running" if command == ".reload /f" else "completed",
            "first_output_delay_ms": 1,
            "queue_wait_ms": 0,
            "execution_time_ms": 10,
            "started": True,
            "completed": command != ".reload /f",
            "background_running": command == ".reload /f",
            "error_message": None,
        }
        if command == ".reload /f":
            self.pending_job_id = command_id
        return self.jobs[command_id]

    def get_command_status(self, command_id):
        return dict(self.jobs[command_id])

    def wait_for_command_result(
        self,
        command_id,
        wait_timeout=0,
        on_output=None,
        on_heartbeat=None,
        _heartbeat_interval=5.0,
        cancel_event=None,
    ):
        job = dict(self.jobs[command_id])
        if on_output:
            for line in job["output_lines"]:
                on_output(line)
        if on_heartbeat:
            on_heartbeat()
        if cancel_event and cancel_event.is_set():
            job["cancelled"] = True
            job["status"] = "cancelled"
            return job
        if job["status"] == "running" and wait_timeout <= 0:
            return job
        if job["status"] == "running":
            job["status"] = "completed"
            job["completed"] = True
            job["background_running"] = False
            self.jobs[command_id] = job
            if self.pending_job_id == command_id:
                self.pending_job_id = None
        return job

    def get_pending_command(self):
        if self.pending_job_id is None:
            return None
        return dict(self.jobs[self.pending_job_id])

    def has_pending_command(self):
        return self.pending_job_id is not None

    def shutdown(self):
        type(self).shutdown_count += 1


@pytest.fixture(autouse=True)
def upload_integration_env(configure_upload_runtime, monkeypatch):
    configure_upload_runtime(max_upload_mb=2)
    server.configure_public_base_url(explicit_base_url="http://debug.example.com:8080")
    _FakeSession.created = 0
    _FakeSession.shutdown_count = 0
    _FakeSession.last_instance = None
    monkeypatch.setattr(server, "CDBSession", _FakeSession)


def _mark_uploaded_dump(file_name: str):
    payload = server.create_upload_session(file_name, 8)
    metadata = server.session_registry.upload_sessions[payload["file_id"]]
    Path(metadata.temp_file_path).write_bytes(b"MDMPxxxx")
    metadata.status = server.UploadSessionStatus.UPLOADED
    return payload, metadata


class _FakeRequestSession:
    async def send_progress_notification(self, **_kwargs):
        return None


def test_start_analysis_session_creates_reusable_session():
    payload, _metadata = _mark_uploaded_dump("uploaded.dmp")

    app_server = server._create_server()
    handler = app_server.request_handlers[CallToolRequest]
    request = CallToolRequest(
        method="tools/call",
        params={
            "name": "start_analysis_session",
            "arguments": {
                "file_id": payload["file_id"],
            },
        },
    )

    result = asyncio.run(handler(request)).root

    assert result.isError is False
    payload = json.loads(result.content[0].text)
    assert payload["status"] == "ready"
    assert payload["session_id"]
    assert _FakeSession.created == 1
    assert _FakeSession.last_instance is not None
    assert _FakeSession.last_instance.symbol_diagnostics_enabled is True
    assert _FakeSession.last_instance.commands == ["!sym noisy"]


def test_start_analysis_session_can_disable_sym_noisy():
    payload, _metadata = _mark_uploaded_dump("uploaded.dmp")

    app_server = server._create_server()
    handler = app_server.request_handlers[CallToolRequest]
    request = CallToolRequest(
        method="tools/call",
        params={
            "name": "start_analysis_session",
            "arguments": {
                "file_id": payload["file_id"],
                "sym_noisy": False,
            },
        },
    )

    result = asyncio.run(handler(request)).root

    assert result.isError is False
    payload = json.loads(result.content[0].text)
    assert payload["status"] == "ready"
    assert _FakeSession.last_instance is not None
    assert _FakeSession.last_instance.symbol_diagnostics_enabled is False
    assert _FakeSession.last_instance.commands == []


def test_execute_windbg_command_uses_uploaded_session():
    payload, _metadata = _mark_uploaded_dump("command.dmp")
    app_server = server._create_server()
    handler = app_server.request_handlers[CallToolRequest]
    start_request = CallToolRequest(
        method="tools/call",
        params={"name": "start_analysis_session", "arguments": {"file_id": payload["file_id"]}},
    )
    start_result = asyncio.run(handler(start_request)).root
    session_id = json.loads(start_result.content[0].text)["session_id"]

    request = CallToolRequest(
        method="tools/call",
        params={
            "name": "execute_windbg_command",
            "arguments": {
                "session_id": session_id,
                "command": "kb",
            },
        },
    )

    result = asyncio.run(handler(request)).root

    assert result.isError is False
    payload = json.loads(result.content[0].text)
    assert payload["success"] is True
    assert payload["status"] == "completed"
    assert payload["timed_out"] is False
    assert payload["first_output_delay_ms"] == 1
    assert "fake:kb" in payload["output"]
    assert _FakeSession.created == 1


def test_execute_windbg_command_returns_structured_timeout_result():
    payload, _metadata = _mark_uploaded_dump("timeout.dmp")
    app_server = server._create_server()
    handler = app_server.request_handlers[CallToolRequest]
    start_request = CallToolRequest(
        method="tools/call",
        params={"name": "start_analysis_session", "arguments": {"file_id": payload["file_id"]}},
    )
    start_result = asyncio.run(handler(start_request)).root
    session_id = json.loads(start_result.content[0].text)["session_id"]

    request = CallToolRequest(
        method="tools/call",
        params={
            "name": "execute_windbg_command",
            "arguments": {
                "session_id": session_id,
                "command": "timeout_no_output",
            },
        },
    )

    result = asyncio.run(handler(request)).root

    assert result.isError is False
    payload = json.loads(result.content[0].text)
    assert payload["success"] is False
    assert payload["status"] == "timeout"
    assert payload["timed_out"] is True
    assert payload["first_output_delay_ms"] is None
    assert payload["suggested_next_step"]
    assert payload["queue_wait_ms"] == 0


def test_execute_windbg_command_timeout_logs_background_running(caplog, monkeypatch):
    payload, _metadata = _mark_uploaded_dump("timeout-log.dmp")
    app_server = server._create_server()
    monkeypatch.setattr(
        server,
        "_try_get_request_context",
        lambda _server: SimpleNamespace(request_id="req-timeout", session=_FakeRequestSession()),
    )
    handler = app_server.request_handlers[CallToolRequest]
    start_request = CallToolRequest(
        method="tools/call",
        params={"name": "start_analysis_session", "arguments": {"file_id": payload["file_id"]}},
    )
    start_result = asyncio.run(handler(start_request)).root
    session_id = json.loads(start_result.content[0].text)["session_id"]

    request = CallToolRequest(
        method="tools/call",
        params={
            "name": "execute_windbg_command",
            "arguments": {
                "session_id": session_id,
                "command": "timeout_no_output",
            },
        },
    )

    with caplog.at_level(logging.WARNING):
        result = asyncio.run(handler(request)).root

    assert result.isError is False
    assert any(
        getattr(record, "request_id", "") == "req-timeout"
        and getattr(record, "outcome", "") == "background_running"
        for record in caplog.records
    )


def test_start_async_windbg_command_returns_command_id():
    payload, _metadata = _mark_uploaded_dump("async-start.dmp")
    app_server = server._create_server()
    handler = app_server.request_handlers[CallToolRequest]
    start_request = CallToolRequest(
        method="tools/call",
        params={"name": "start_analysis_session", "arguments": {"file_id": payload["file_id"]}},
    )
    start_result = asyncio.run(handler(start_request)).root
    session_id = json.loads(start_result.content[0].text)["session_id"]

    request = CallToolRequest(
        method="tools/call",
        params={
            "name": "start_async_windbg_command",
            "arguments": {"session_id": session_id, "command": ".reload /f"},
        },
    )

    result = asyncio.run(handler(request)).root
    payload = json.loads(result.content[0].text)
    assert payload["command_id"]
    assert payload["status"] == "running"


def test_get_async_windbg_command_status_returns_running_state():
    payload, _metadata = _mark_uploaded_dump("async-status.dmp")
    app_server = server._create_server()
    handler = app_server.request_handlers[CallToolRequest]
    start_request = CallToolRequest(
        method="tools/call",
        params={"name": "start_analysis_session", "arguments": {"file_id": payload["file_id"]}},
    )
    start_result = asyncio.run(handler(start_request)).root
    session_id = json.loads(start_result.content[0].text)["session_id"]
    async_request = CallToolRequest(
        method="tools/call",
        params={
            "name": "start_async_windbg_command",
            "arguments": {"session_id": session_id, "command": ".reload /f"},
        },
    )
    async_result = asyncio.run(handler(async_request)).root
    command_id = json.loads(async_result.content[0].text)["command_id"]

    status_request = CallToolRequest(
        method="tools/call",
        params={
            "name": "get_async_windbg_command_status",
            "arguments": {"session_id": session_id, "command_id": command_id},
        },
    )
    status_result = asyncio.run(handler(status_request)).root
    status_payload = json.loads(status_result.content[0].text)

    assert status_payload["status"] == "running"
    assert status_payload["completed"] is False


def test_get_async_windbg_command_result_can_complete_running_job():
    payload, _metadata = _mark_uploaded_dump("async-result.dmp")
    app_server = server._create_server()
    handler = app_server.request_handlers[CallToolRequest]
    start_request = CallToolRequest(
        method="tools/call",
        params={"name": "start_analysis_session", "arguments": {"file_id": payload["file_id"]}},
    )
    start_result = asyncio.run(handler(start_request)).root
    session_id = json.loads(start_result.content[0].text)["session_id"]
    async_request = CallToolRequest(
        method="tools/call",
        params={
            "name": "start_async_windbg_command",
            "arguments": {"session_id": session_id, "command": ".reload /f"},
        },
    )
    async_result = asyncio.run(handler(async_request)).root
    command_id = json.loads(async_result.content[0].text)["command_id"]

    result_request = CallToolRequest(
        method="tools/call",
        params={
            "name": "get_async_windbg_command_result",
            "arguments": {"session_id": session_id, "command_id": command_id, "wait_timeout": 1},
        },
    )
    result = asyncio.run(handler(result_request)).root
    payload = json.loads(result.content[0].text)

    assert payload["status"] == "completed"
    assert payload["command_id"] == command_id
    assert "fake:.reload /f" in payload["output"]


def test_execute_windbg_command_returns_busy_when_async_command_is_running():
    payload, _metadata = _mark_uploaded_dump("busy.dmp")
    app_server = server._create_server()
    handler = app_server.request_handlers[CallToolRequest]
    start_request = CallToolRequest(
        method="tools/call",
        params={"name": "start_analysis_session", "arguments": {"file_id": payload["file_id"]}},
    )
    start_result = asyncio.run(handler(start_request)).root
    session_id = json.loads(start_result.content[0].text)["session_id"]
    async_request = CallToolRequest(
        method="tools/call",
        params={
            "name": "start_async_windbg_command",
            "arguments": {"session_id": session_id, "command": ".reload /f"},
        },
    )
    asyncio.run(handler(async_request)).root

    request = CallToolRequest(
        method="tools/call",
        params={
            "name": "execute_windbg_command",
            "arguments": {"session_id": session_id, "command": "kb"},
        },
    )
    result = asyncio.run(handler(request)).root
    payload = json.loads(result.content[0].text)

    assert payload["status"] == "busy"
    assert payload["running_command"] == ".reload /f"


def test_start_analysis_session_rejects_when_upload_not_completed():
    payload = server.create_upload_session("pending.dmp", 8)

    app_server = server._create_server()
    handler = app_server.request_handlers[CallToolRequest]
    request = CallToolRequest(
        method="tools/call",
        params={
            "name": "start_analysis_session",
            "arguments": {
                "file_id": payload["file_id"],
            },
        },
    )

    result = asyncio.run(handler(request)).root

    assert result.isError is True
    assert server.UPLOAD_ERROR_INVALID_STATE in result.content[0].text


def test_prepare_dump_upload_tool_returns_structured_error_for_unusable_upload_url():
    server.configure_public_base_url(explicit_base_url="http://0.0.0.0:8000")

    app_server = server._create_server()
    handler = app_server.request_handlers[CallToolRequest]
    request = CallToolRequest(
        method="tools/call",
        params={
            "name": "prepare_dump_upload",
            "arguments": {
                "file_size": 8,
                "file_name": "pending.dmp",
            },
        },
    )

    result = asyncio.run(handler(request)).root

    assert result.isError is True
    error_payload = json.loads(result.content[0].text)["error"]
    assert error_payload["code"] == server.UPLOAD_ERROR_URL_UNAVAILABLE
    assert "public-base-url" in error_payload["remediation"]


def test_execute_windbg_command_blocks_dangerous_command():
    payload, _metadata = _mark_uploaded_dump("dangerous.dmp")
    app_server = server._create_server()
    handler = app_server.request_handlers[CallToolRequest]
    start_request = CallToolRequest(
        method="tools/call",
        params={"name": "start_analysis_session", "arguments": {"file_id": payload["file_id"]}},
    )
    start_result = asyncio.run(handler(start_request)).root
    session_id = json.loads(start_result.content[0].text)["session_id"]

    request = CallToolRequest(
        method="tools/call",
        params={
            "name": "execute_windbg_command",
            "arguments": {
                "session_id": session_id,
                "command": ".shell whoami",
            },
        },
    )

    result = asyncio.run(handler(request)).root

    assert result.isError is True
    assert "DANGEROUS_COMMAND_BLOCKED" in result.content[0].text


def test_blocked_dangerous_command_logs_masked_preview(caplog, monkeypatch):
    payload, _metadata = _mark_uploaded_dump("dangerous-log.dmp")
    app_server = server._create_server()
    monkeypatch.setattr(
        server,
        "_try_get_request_context",
        lambda _server: SimpleNamespace(request_id="req-123", session=_FakeRequestSession()),
    )
    handler = app_server.request_handlers[CallToolRequest]
    start_request = CallToolRequest(
        method="tools/call",
        params={"name": "start_analysis_session", "arguments": {"file_id": payload["file_id"]}},
    )
    start_result = asyncio.run(handler(start_request)).root
    session_id = json.loads(start_result.content[0].text)["session_id"]

    request = CallToolRequest(
        method="tools/call",
        params={
            "name": "execute_windbg_command",
            "arguments": {
                "session_id": session_id,
                "command": ".shell whoami /all",
            },
        },
    )

    with caplog.at_level(logging.WARNING):
        result = asyncio.run(handler(request)).root

    assert result.isError is True
    blocked_records = [record for record in caplog.records if getattr(record, "outcome", "") == "blocked"]
    assert blocked_records
    assert any(getattr(record, "command_preview", "") == "<blocked:.shell>" for record in blocked_records)
    assert all(".shell whoami /all" not in getattr(record, "command_preview", "") for record in blocked_records)


def test_execute_command_logs_correlated_ids(caplog, monkeypatch):
    payload, _metadata = _mark_uploaded_dump("correlated.dmp")
    app_server = server._create_server()
    monkeypatch.setattr(
        server,
        "_try_get_request_context",
        lambda _server: SimpleNamespace(request_id="req-456", session=_FakeRequestSession()),
    )
    handler = app_server.request_handlers[CallToolRequest]

    with caplog.at_level(logging.INFO):
        start_request = CallToolRequest(
            method="tools/call",
            params={"name": "start_analysis_session", "arguments": {"file_id": payload["file_id"]}},
        )
        start_result = asyncio.run(handler(start_request)).root
        session_id = json.loads(start_result.content[0].text)["session_id"]

        execute_request = CallToolRequest(
            method="tools/call",
            params={
                "name": "execute_windbg_command",
                "arguments": {"session_id": session_id, "command": "kb"},
            },
        )
        execute_result = asyncio.run(handler(execute_request)).root

    assert execute_result.isError is False
    assert any(
        getattr(record, "request_id", "") == "req-456"
        and getattr(record, "file_id", "") == payload["file_id"]
        and getattr(record, "session_id", "") == session_id
        for record in caplog.records
    )


def test_close_analysis_session_closes_uploaded_session_and_removes_temp_file():
    payload, metadata = _mark_uploaded_dump("close.dmp")

    app_server = server._create_server()
    handler = app_server.request_handlers[CallToolRequest]
    start_request = CallToolRequest(
        method="tools/call",
        params={"name": "start_analysis_session", "arguments": {"file_id": payload["file_id"]}},
    )
    start_result = asyncio.run(handler(start_request)).root
    session_id = json.loads(start_result.content[0].text)["session_id"]

    close_request = CallToolRequest(
        method="tools/call",
        params={"name": "close_analysis_session", "arguments": {"session_id": session_id}},
    )
    close_result = asyncio.run(handler(close_request)).root
    close_payload = json.loads(close_result.content[0].text)

    assert close_payload["status"] == "closed"
    assert close_payload["session_id"] == session_id
    assert _FakeSession.shutdown_count == 1
    assert payload["file_id"] not in server.session_registry.upload_sessions
    assert not Path(metadata.temp_file_path).exists()


def test_close_analysis_session_rejects_while_async_command_is_running():
    payload, _metadata = _mark_uploaded_dump("close-busy.dmp")
    app_server = server._create_server()
    handler = app_server.request_handlers[CallToolRequest]
    start_request = CallToolRequest(
        method="tools/call",
        params={"name": "start_analysis_session", "arguments": {"file_id": payload["file_id"]}},
    )
    start_result = asyncio.run(handler(start_request)).root
    session_id = json.loads(start_result.content[0].text)["session_id"]
    async_request = CallToolRequest(
        method="tools/call",
        params={
            "name": "start_async_windbg_command",
            "arguments": {"session_id": session_id, "command": ".reload /f"},
        },
    )
    asyncio.run(handler(async_request)).root

    close_request = CallToolRequest(
        method="tools/call",
        params={"name": "close_analysis_session", "arguments": {"session_id": session_id}},
    )
    close_result = asyncio.run(handler(close_request)).root

    assert close_result.isError is True
    assert "busy" in close_result.content[0].text.lower()
