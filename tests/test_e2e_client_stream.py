from __future__ import annotations

from tests.e2e.client import MCPHTTPClient


def test_parse_sse_payload_extracts_progress_and_terminal_result():
    payload = (
        'event: message\n'
        'data: {"jsonrpc":"2.0","method":"$/progress","params":{"token":"1","value":{"percent":0,"message":"queued","phase":"queued"}}}\n'
        "\n"
        'event: message\n'
        'data: {"jsonrpc":"2.0","method":"$/progress","params":{"token":"1","value":{"percent":null,"message":"line","phase":"running"}}}\n'
        "\n"
        'event: message\n'
        'data: {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\\"success\\": true}"}]}}\n'
        "\n"
    )

    events = MCPHTTPClient._parse_sse_payload(payload)
    assert len(events) == 3
    assert events[0]["method"] == "$/progress"
    assert events[1]["params"]["value"]["phase"] == "running"
    assert events[2]["id"] == 1
