from __future__ import annotations

import json

import pytest

from tests.e2e.client import MCPHTTPClient
from tests.e2e.conftest import (
    assert_tool_success,
    format_mcp_failure_details,
    parse_tool_text_payload,
    upload_dump,
)
from tests.e2e.config import E2EConfig


pytestmark = [pytest.mark.e2e]


def _prepare_upload(client: MCPHTTPClient, file_name: str, payload: bytes) -> dict:
    arguments = {"file_name": file_name, "file_size": len(payload)}
    call_result = client.call_tool(
        "prepare_dump_upload",
        arguments,
    )
    parsed = assert_tool_success(
        client=client,
        tool_name="prepare_dump_upload",
        arguments=arguments,
        call_result=call_result,
    )
    assert isinstance(parsed, dict)
    return parsed


def _start_session(client: MCPHTTPClient, file_id: str) -> tuple[bool, dict | str]:
    arguments = {"file_id": file_id}
    result = client.call_tool("start_analysis_session", arguments)
    return parse_tool_text_payload(result)


def _execute_command(client: MCPHTTPClient, session_id: str, command: str, timeout: int = 300) -> tuple[bool, dict | str]:
    result = client.call_tool(
        "execute_windbg_command",
        {"session_id": session_id, "command": command, "timeout": timeout},
    )
    return parse_tool_text_payload(result)


def _execute_command_with_progress(
    client: MCPHTTPClient, session_id: str, command: str, timeout: int = 300
) -> tuple[bool, dict | str, list[dict]]:
    arguments = {"session_id": session_id, "command": command, "timeout": timeout}
    result, progress_events = client.call_tool_with_progress(
        "execute_windbg_command",
        arguments,
    )
    is_error, payload = parse_tool_text_payload(result)
    return is_error, payload, progress_events


def _close_session(client: MCPHTTPClient, session_id: str) -> tuple[bool, dict | str]:
    result = client.call_tool("close_analysis_session", {"session_id": session_id})
    return parse_tool_text_payload(result)


def test_e2e_happy_path_small_dump(mcp_client: MCPHTTPClient, e2e_config: E2EConfig, dump_bytes: bytes):
    upload_info = _prepare_upload(mcp_client, "DemoCrash1.exe.7088.dmp", dump_bytes)
    assert "file_id" in upload_info
    assert "upload_url" in upload_info

    status_code, upload_resp = upload_dump(upload_info["upload_url"], dump_bytes, e2e_config.timeout_seconds)
    assert status_code == 201
    assert upload_resp["status"] == "uploaded"

    start_error, start_payload = _start_session(mcp_client, upload_info["file_id"])
    assert start_error is False
    assert isinstance(start_payload, dict)
    session_id = start_payload["session_id"]

    exec_error, exec_payload, progress_events = _execute_command_with_progress(
        mcp_client, session_id, "version", timeout=120
    )
    if exec_error:
        failure = format_mcp_failure_details(
            client=mcp_client,
            tool_name="execute_windbg_command",
            arguments={"session_id": session_id, "command": "version", "timeout": 120},
            call_result={"isError": exec_error, "content": [{"type": "text", "text": str(exec_payload)}]},
            parsed_payload=exec_payload,
            progress_events=progress_events,
        )
        pytest.fail(f"version command failed\n{failure}")
    assert exec_error is False
    assert isinstance(exec_payload, dict)
    assert exec_payload["success"] is True
    assert "Microsoft (R) Windows Debugger" in exec_payload["output"]
    assert any(str(event.get("phase", "")).lower() == "completed" for event in progress_events)

    close_error, close_payload = _close_session(mcp_client, session_id)
    assert close_error is False
    assert isinstance(close_payload, dict)
    assert close_payload.get("status") == "closed"

    post_close_error, post_close_payload = _execute_command(mcp_client, session_id, "version", timeout=30)
    assert post_close_error is True
    text = post_close_payload if isinstance(post_close_payload, str) else json.dumps(post_close_payload, ensure_ascii=False)
    assert "UPLOAD_SESSION_NOT_FOUND" in text


def test_e2e_reject_invalid_dump_payload(mcp_client: MCPHTTPClient, e2e_config: E2EConfig):
    invalid_payload = b"NOTDUMP"
    upload_info = _prepare_upload(mcp_client, "invalid.dmp", invalid_payload)

    status_code, upload_resp = upload_dump(upload_info["upload_url"], invalid_payload, e2e_config.timeout_seconds)
    assert status_code == 400
    assert upload_resp["error"]["code"] == "INVALID_DUMP_FORMAT"

    start_error, start_payload = _start_session(mcp_client, upload_info["file_id"])
    assert start_error is True
    text = start_payload if isinstance(start_payload, str) else json.dumps(start_payload, ensure_ascii=False)
    assert "UPLOAD_SESSION_INVALID_STATE" in text


def test_e2e_start_before_upload_completed(mcp_client: MCPHTTPClient, dump_bytes: bytes):
    upload_info = _prepare_upload(mcp_client, "pending.dmp", dump_bytes)

    start_error, start_payload = _start_session(mcp_client, upload_info["file_id"])
    assert start_error is True
    text = start_payload if isinstance(start_payload, str) else json.dumps(start_payload, ensure_ascii=False)
    assert "UPLOAD_SESSION_INVALID_STATE" in text


def test_e2e_block_dangerous_command(mcp_client: MCPHTTPClient, e2e_config: E2EConfig, dump_bytes: bytes):
    upload_info = _prepare_upload(mcp_client, "dangerous.dmp", dump_bytes)
    status_code, upload_resp = upload_dump(upload_info["upload_url"], dump_bytes, e2e_config.timeout_seconds)
    assert status_code == 201
    assert upload_resp["status"] == "uploaded"

    start_error, start_payload = _start_session(mcp_client, upload_info["file_id"])
    assert start_error is False
    assert isinstance(start_payload, dict)
    session_id = start_payload["session_id"]

    blocked_error, blocked_payload = _execute_command(mcp_client, session_id, ".shell whoami", timeout=30)
    assert blocked_error is True
    text = blocked_payload if isinstance(blocked_payload, str) else json.dumps(blocked_payload, ensure_ascii=False)
    assert "DANGEROUS_COMMAND_BLOCKED" in text

    _close_session(mcp_client, session_id)


def test_e2e_session_close_idempotency_or_consistent_error(
    mcp_client: MCPHTTPClient, e2e_config: E2EConfig, dump_bytes: bytes
):
    upload_info = _prepare_upload(mcp_client, "close.dmp", dump_bytes)
    status_code, upload_resp = upload_dump(upload_info["upload_url"], dump_bytes, e2e_config.timeout_seconds)
    assert status_code == 201
    assert upload_resp["status"] == "uploaded"

    start_error, start_payload = _start_session(mcp_client, upload_info["file_id"])
    assert start_error is False
    assert isinstance(start_payload, dict)
    session_id = start_payload["session_id"]

    first_error, first_payload = _close_session(mcp_client, session_id)
    assert first_error is False
    assert isinstance(first_payload, dict)
    assert first_payload.get("status") == "closed"

    second_error, second_payload = _close_session(mcp_client, session_id)
    if second_error:
        text = second_payload if isinstance(second_payload, str) else json.dumps(second_payload, ensure_ascii=False)
        assert "not_found" in text.lower() or "session" in text.lower()
    else:
        assert isinstance(second_payload, dict)
        assert second_payload.get("status") in {"closed", "already_closed"}
