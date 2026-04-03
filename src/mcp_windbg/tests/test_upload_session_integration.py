import asyncio
from pathlib import Path

import pytest
from mcp.types import CallToolRequest

from mcp_windbg import server


pytestmark = pytest.mark.usefixtures("restore_upload_runtime_state")


class _FakeSession:
    created = 0
    shutdown_count = 0

    def __init__(self, dump_path=None, remote_connection=None, **_kwargs):
        type(self).created += 1
        self.dump_path = dump_path
        self.remote_connection = remote_connection
        self.commands = []

    def send_command(self, command):
        self.commands.append(command)
        return [f"fake:{command}"]

    def shutdown(self):
        type(self).shutdown_count += 1


@pytest.fixture(autouse=True)
def upload_integration_env(configure_upload_runtime, monkeypatch):
    configure_upload_runtime()
    _FakeSession.created = 0
    _FakeSession.shutdown_count = 0
    monkeypatch.setattr(server, "CDBSession", _FakeSession)


def _mark_uploaded_dump(file_name: str):
    payload = server.create_upload_session(file_name)
    metadata = server.session_registry.upload_sessions[payload["session_id"]]
    Path(metadata.temp_file_path).write_bytes(b"MDMPxxxx")
    metadata.mark_status(server.UploadSessionStatus.UPLOADED)
    return payload, metadata


def test_open_windbg_dump_tool_uses_uploaded_session():
    payload, _metadata = _mark_uploaded_dump("uploaded.dmp")

    app_server = server._create_server(enable_upload_tools=True)
    handler = app_server.request_handlers[CallToolRequest]
    request = CallToolRequest(
        method="tools/call",
        params={
            "name": "open_windbg_dump",
            "arguments": {
                "session_id": payload["session_id"],
                "include_stack_trace": True,
                "include_modules": False,
                "include_threads": False,
            },
        },
    )

    result = asyncio.run(handler(request)).root

    assert result.isError is False
    assert "### Crash Information" in result.content[0].text
    assert "### Crash Analysis" in result.content[0].text
    assert "### Stack Trace" in result.content[0].text
    assert _FakeSession.created == 1


def test_run_windbg_cmd_uses_uploaded_session():
    payload, _metadata = _mark_uploaded_dump("command.dmp")

    app_server = server._create_server(enable_upload_tools=True)
    handler = app_server.request_handlers[CallToolRequest]
    request = CallToolRequest(
        method="tools/call",
        params={
            "name": "run_windbg_cmd",
            "arguments": {
                "session_id": payload["session_id"],
                "command": "kb",
            },
        },
    )

    result = asyncio.run(handler(request)).root

    assert result.isError is False
    assert "fake:kb" in result.content[0].text
    assert _FakeSession.created == 1


def test_close_windbg_dump_closes_uploaded_session_and_removes_temp_file():
    payload, metadata = _mark_uploaded_dump("close.dmp")

    analysis_metadata = server.acquire_uploaded_session_for_tool(payload["session_id"])
    try:
        session = server.get_or_create_uploaded_session(analysis_metadata)
        session.send_command("r")
    finally:
        server.upload_sessions.release_uploaded_session_after_analysis(
            analysis_metadata,
            server.upload_runtime_config.session_ttl_seconds,
        )

    close_payload = server.close_windbg_dump(session_id=payload["session_id"])

    assert close_payload["status"] == "closed"
    assert close_payload["session_id"] == payload["session_id"]
    assert _FakeSession.shutdown_count == 1
    assert payload["session_id"] not in server.session_registry.upload_sessions
    assert not Path(metadata.temp_file_path).exists()
