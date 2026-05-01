from __future__ import annotations

import re
from datetime import datetime

import pytest

from tests.e2e.client import MCPHTTPClient
from tests.e2e.conftest import (
    assert_tool_success,
    format_mcp_failure_details,
    parse_tool_text_payload,
    upload_dump,
)
from tests.e2e.config import E2EConfig


pytestmark = [pytest.mark.e2e, pytest.mark.e2e_symbol_heavy]


def _timestamped_print(message: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"[{timestamp}] {message}")


def _require_symbol_heavy_asset(config: E2EConfig) -> bytes:
    if config.symbol_heavy_dump_path is None:
        pytest.fail("Missing symbol_heavy dump path; the symbol_heavy scenario must not be skipped")
    if not config.symbol_heavy_dump_path.exists():
        pytest.fail(f"Symbol-heavy scenario dump does not exist: {config.symbol_heavy_dump_path}")
    return config.symbol_heavy_dump_path.read_bytes()


def _prepare_and_start(client: MCPHTTPClient, config: E2EConfig, dump_payload: bytes) -> str:
    file_name = config.symbol_heavy_dump_path.name if config.symbol_heavy_dump_path else "symbol-heavy.dmp"
    prepare_arguments = {"file_name": file_name, "file_size": len(dump_payload)}
    prep_result = client.call_tool(
        "prepare_dump_upload",
        prepare_arguments,
    )
    prep_payload = assert_tool_success(
        client=client,
        tool_name="prepare_dump_upload",
        arguments=prepare_arguments,
        call_result=prep_result,
    )
    assert isinstance(prep_payload, dict)

    status_code, upload_resp = upload_dump(prep_payload["upload_url"], dump_payload, config.timeout_seconds)
    assert status_code == 201
    assert upload_resp["status"] == "uploaded"

    start_arguments = {"file_id": prep_payload["file_id"]}
    start_result = client.call_tool("start_analysis_session", start_arguments)
    start_error, start_payload = parse_tool_text_payload(start_result)
    assert start_error is False
    assert isinstance(start_payload, dict)
    return start_payload["session_id"]


def _execute(client: MCPHTTPClient, session_id: str, command: str, timeout: int) -> dict:
    _timestamped_print(f"[symbol_heavy] run command: {command}")
    arguments = {"session_id": session_id, "command": command, "timeout": timeout}
    result = client.call_tool("execute_windbg_command", arguments)
    is_error, payload = parse_tool_text_payload(result)
    if is_error:
        failure = format_mcp_failure_details(
            client=client,
            tool_name="execute_windbg_command",
            arguments=arguments,
            call_result=result,
            parsed_payload=payload,
        )
        pytest.fail(f"symbol_heavy command failed: {command}\n{failure}")
    assert is_error is False
    assert isinstance(payload, dict)
    assert payload["success"] is True
    _timestamped_print(f"[symbol_heavy] done command: {command}, cost_ms={payload.get('execution_time_ms')}")
    return payload


def _execute_with_progress(
    client: MCPHTTPClient, session_id: str, command: str, timeout: int
) -> tuple[dict, list[dict]]:
    _timestamped_print(f"[symbol_heavy] run command (stream): {command}")
    arguments = {"session_id": session_id, "command": command, "timeout": timeout}
    result, progress_events = client.call_tool_with_progress("execute_windbg_command", arguments)
    is_error, payload = parse_tool_text_payload(result)
    if is_error:
        failure = format_mcp_failure_details(
            client=client,
            tool_name="execute_windbg_command",
            arguments=arguments,
            call_result=result,
            parsed_payload=payload,
            progress_events=progress_events,
        )
        pytest.fail(f"symbol_heavy streaming command failed: {command}\n{failure}")
    assert is_error is False
    assert isinstance(payload, dict)
    assert payload["success"] is True
    _timestamped_print(
        f"[symbol_heavy] done command (stream): {command}, cost_ms={payload.get('execution_time_ms')}, "
        f"progress_events={len(progress_events)}"
    )
    return payload, progress_events


def test_e2e_symbol_heavy_cold_cache(mcp_client: MCPHTTPClient, e2e_config: E2EConfig):
    dump_payload = _require_symbol_heavy_asset(e2e_config)
    session_id = _prepare_and_start(mcp_client, e2e_config, dump_payload)
    try:
        _execute(mcp_client, session_id, "!sym noisy", timeout=e2e_config.timeout_seconds)
        reload_result, reload_progress = _execute_with_progress(
            mcp_client, session_id, ".reload /f", timeout=e2e_config.timeout_seconds
        )
        _execute(mcp_client, session_id, "!sym quiet", timeout=e2e_config.timeout_seconds)
        module_result = _execute(mcp_client, session_id, "lmv m electron*", timeout=e2e_config.timeout_seconds)
        kv_result = _execute(mcp_client, session_id, ".ecxr;kv", timeout=e2e_config.timeout_seconds)

        assert reload_result["execution_time_ms"] >= 0
        progress_text = "\n".join(
            str(e.get("message", ""))
            for e in reload_progress
            if str(e.get("event", "")).lower() != "heartbeat" and "message" in e
        )
        assert any(str(e.get("phase", "")).lower() == "running" for e in reload_progress)
        assert any(str(e.get("phase", "")).lower() == "completed" for e in reload_progress)
        assert any(str(e.get("event", "")).lower() == "output" for e in reload_progress)
        assert any(token in progress_text.upper() for token in ("SYMSRV", "DBGHELP", "PDB", "SYMBOL"))
        assert module_result["output"]
        assert "electron" in module_result["output"].lower()

        stack_output = kv_result["output"]
        assert stack_output

        # 1) The electron module symbol must be visible, which implies PDB symbol resolution reached function names.
        assert "electron!electron::ElectronBindings::Crash" in stack_output

        # 2) The first valid stack frame must resolve to ElectronBindings::Crash.
        lines = stack_output.splitlines()
        stack_text_index = next(
            (
                i
                for i, line in enumerate(lines)
                if line.strip() == "STACK_TEXT:" or "Child-SP" in line and "Call Site" in line
            ),
            -1,
        )
        frame0_line = ""
        if stack_text_index >= 0:
            frame0_line = next(
                (
                    line
                    for line in lines[stack_text_index + 1 :]
                    if line.strip() and re.match(r"^[0-9a-fA-F`]+(?:\s+[0-9a-fA-F`-]+)+\s+:", line.strip())
                ),
                "",
            )

        assert "electron!electron::ElectronBindings::Crash" in frame0_line
        _timestamped_print(f"[symbol_heavy] frame0={frame0_line}")

    finally:
        mcp_client.call_tool("close_analysis_session", {"session_id": session_id})


def test_e2e_symbol_heavy_warm_cache(mcp_client: MCPHTTPClient, e2e_config: E2EConfig):
    dump_payload = _require_symbol_heavy_asset(e2e_config)
    session_id = _prepare_and_start(mcp_client, e2e_config, dump_payload)
    try:
        first = _execute(mcp_client, session_id, "!analyze -v", timeout=e2e_config.timeout_seconds)
        second = _execute(mcp_client, session_id, "!analyze -v", timeout=e2e_config.timeout_seconds)

        first_ms = int(first["execution_time_ms"])
        second_ms = int(second["execution_time_ms"])
        # Warm cache is usually faster; allow some variance to avoid false positives from environment noise.
        assert second_ms <= int(first_ms * 1.5)
    finally:
        mcp_client.call_tool("close_analysis_session", {"session_id": session_id})
