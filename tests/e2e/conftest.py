from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Iterator
from urllib import request

import pytest

from tests.e2e.client import MCPHTTPClient, MCPHTTPError
from tests.e2e.config import E2EConfig, load_e2e_config


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def e2e_config() -> E2EConfig:
    return load_e2e_config(_repo_root())


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    skip_remote = pytest.mark.skip(reason="远端 E2E 未启用：请先设置 DUMP_E2E_BASE_URL 并启动目标服务")
    for item in items:
        if "tests/e2e/" in str(item.fspath).replace("\\", "/"):
            item.add_marker(pytest.mark.e2e_remote)
            if not os.getenv("DUMP_E2E_BASE_URL", "").strip():
                item.add_marker(skip_remote)


def _wait_until_ready(base_url: str, timeout_seconds: int) -> None:
    deadline = time.time() + timeout_seconds
    last_error = ""
    while time.time() < deadline:
        client = MCPHTTPClient(base_url, timeout_seconds=10)
        try:
            client.initialize()
            client.list_tools()
            client.delete_session()
            return
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            time.sleep(0.5)
    raise RuntimeError(f"E2E server not ready at {base_url}: {last_error}")


@pytest.fixture(scope="session", autouse=True)
def verify_remote_server_ready(e2e_config: E2EConfig) -> Iterator[None]:
    if not e2e_config.remote_server_configured:
        pytest.skip("远端 E2E 未启用：请先设置 DUMP_E2E_BASE_URL 并启动目标服务")
    _wait_until_ready(e2e_config.base_url, timeout_seconds=30)
    yield


@pytest.fixture
def mcp_client(e2e_config: E2EConfig, verify_remote_server_ready: None) -> Iterator[MCPHTTPClient]:
    client = MCPHTTPClient(e2e_config.base_url, timeout_seconds=e2e_config.timeout_seconds)
    client.initialize()
    yield client
    try:
        # Session cleanup should not block the whole E2E suite when server-side
        # session teardown is slow or transiently stuck.
        client.delete_session(timeout_seconds=10)
    except Exception:
        pass


@pytest.fixture
def dump_bytes(e2e_config: E2EConfig) -> bytes:
    if not e2e_config.dump_path.exists():
        pytest.skip(f"E2E dump file not found: {e2e_config.dump_path}")
    return e2e_config.dump_path.read_bytes()


def upload_dump(upload_url: str, payload: bytes, timeout_seconds: int) -> tuple[int, dict[str, Any]]:
    req = request.Request(
        upload_url,
        data=payload,
        method="PUT",
        headers={"content-type": "application/octet-stream"},
    )
    try:
        with request.urlopen(req, timeout=timeout_seconds) as resp:
            body = resp.read().decode("utf-8")
            return resp.getcode(), json.loads(body)
    except Exception as exc:  # noqa: BLE001
        if hasattr(exc, "code") and hasattr(exc, "read"):
            body = exc.read().decode("utf-8")
            return int(exc.code), json.loads(body)
        raise


def parse_tool_text_payload(call_result: dict[str, Any]) -> tuple[bool, dict[str, Any] | str]:
    is_error = bool(call_result.get("isError"))
    content = call_result.get("content") or []
    if not content:
        return is_error, {}
    text = content[0].get("text", "")
    try:
        return is_error, json.loads(text)
    except Exception:  # noqa: BLE001
        return is_error, text


def format_mcp_failure_details(
    *,
    client: MCPHTTPClient,
    tool_name: str,
    arguments: dict[str, Any],
    call_result: dict[str, Any],
    parsed_payload: dict[str, Any] | str,
    progress_events: list[dict[str, Any]] | None = None,
) -> str:
    exchange = getattr(client, "last_exchange", {})
    details = {
        "tool": tool_name,
        "arguments": arguments,
        "call_result": call_result,
        "parsed_payload": parsed_payload,
        "progress_events": progress_events or [],
        "last_exchange": exchange,
    }
    return json.dumps(details, ensure_ascii=False, indent=2)


def assert_tool_success(
    *,
    client: MCPHTTPClient,
    tool_name: str,
    arguments: dict[str, Any],
    call_result: dict[str, Any],
    progress_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | str:
    is_error, parsed_payload = parse_tool_text_payload(call_result)
    if is_error:
        message = format_mcp_failure_details(
            client=client,
            tool_name=tool_name,
            arguments=arguments,
            call_result=call_result,
            parsed_payload=parsed_payload,
            progress_events=progress_events,
        )
        raise AssertionError(f"Tool call failed: {tool_name}\n{message}")
    return parsed_payload
