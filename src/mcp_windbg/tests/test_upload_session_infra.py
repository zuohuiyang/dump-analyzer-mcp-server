import asyncio

import pytest
from mcp.types import ListToolsRequest

from mcp_windbg import server


pytestmark = pytest.mark.usefixtures("restore_upload_runtime_state")


def _get_tool_map(*, enable_upload_tools: bool = False):
    app_server = server._create_server(enable_upload_tools=enable_upload_tools)
    handler = app_server.request_handlers[ListToolsRequest]
    result = asyncio.run(handler(ListToolsRequest(method="tools/list")))
    return {tool.name: tool for tool in result.root.tools}


def test_stdio_server_does_not_expose_upload_tools():
    tool_map = _get_tool_map()
    tool_names = set(tool_map)

    assert "create_upload_session" not in tool_names
    assert "session_id" not in tool_map["open_windbg_dump"].inputSchema["properties"]
    assert "session_id" not in tool_map["run_windbg_cmd"].inputSchema["properties"]
    assert "session_id" not in tool_map["close_windbg_dump"].inputSchema["properties"]
    assert "session_id" not in tool_map["send_ctrl_break"].inputSchema["properties"]


def test_http_server_exposes_upload_session_support_on_existing_tools():
    tool_map = _get_tool_map(enable_upload_tools=True)
    tool_names = set(tool_map)

    assert "create_upload_session" in tool_names
    assert "session_id" in tool_map["open_windbg_dump"].inputSchema["properties"]
    assert "session_id" in tool_map["run_windbg_cmd"].inputSchema["properties"]
    assert "session_id" in tool_map["close_windbg_dump"].inputSchema["properties"]
    assert "session_id" not in tool_map["send_ctrl_break"].inputSchema["properties"]
