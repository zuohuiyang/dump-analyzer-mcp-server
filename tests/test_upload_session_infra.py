import asyncio

import pytest
from mcp.types import ListToolsRequest

from dump_analyzer_mcp_server import server


pytestmark = pytest.mark.usefixtures("restore_upload_runtime_state")


def _get_tool_map():
    app_server = server._create_server()
    handler = app_server.request_handlers[ListToolsRequest]
    result = asyncio.run(handler(ListToolsRequest(method="tools/list")))
    return {tool.name: tool for tool in result.root.tools}


def test_crashdump_server_exposes_only_new_design_tools():
    tool_map = _get_tool_map()
    tool_names = set(tool_map)
    assert tool_names == {
        "prepare_dump_upload",
        "start_analysis_session",
        "execute_windbg_command",
        "close_analysis_session",
    }


def test_new_tool_schemas_match_expected_params():
    tool_map = _get_tool_map()
    assert "file_size" in tool_map["prepare_dump_upload"].inputSchema["properties"]
    assert "file_name" in tool_map["prepare_dump_upload"].inputSchema["properties"]
    assert "file_id" in tool_map["start_analysis_session"].inputSchema["properties"]
    assert "session_id" in tool_map["execute_windbg_command"].inputSchema["properties"]
    assert "command" in tool_map["execute_windbg_command"].inputSchema["properties"]
    assert "timeout" in tool_map["execute_windbg_command"].inputSchema["properties"]
