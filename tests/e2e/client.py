from __future__ import annotations

import json
import os
from dataclasses import dataclass
from itertools import count
from typing import Any
from urllib import error, request

from mcp.types import DEFAULT_NEGOTIATED_VERSION


class MCPHTTPError(RuntimeError):
    pass


@dataclass
class MCPHTTPClient:
    endpoint: str
    timeout_seconds: int = 60
    trace_enabled: bool | None = None
    trace_max_chars: int | None = None

    def __post_init__(self) -> None:
        # Starlette mount endpoint is "/mcp/" and may 307-redirect "/mcp".
        # Use the canonical trailing-slash endpoint to avoid redirect handling issues.
        self._endpoint = self.endpoint.rstrip("/") + "/mcp/"
        self._counter = count(1)
        self._session_id: str | None = None
        self._protocol_version = DEFAULT_NEGOTIATED_VERSION
        self.last_progress_events: list[dict[str, Any]] = []
        self.last_exchange: dict[str, Any] = {}
        if self.trace_enabled is None:
            self.trace_enabled = self._read_bool_env("DUMP_E2E_MCP_TRACE", default=True)
        if self.trace_max_chars is None:
            self.trace_max_chars = self._read_int_env("DUMP_E2E_MCP_TRACE_MAX_CHARS", default=4000)

    def initialize(self) -> dict[str, Any]:
        payload = {
            "jsonrpc": "2.0",
            "id": next(self._counter),
            "method": "initialize",
            "params": {
                "protocolVersion": self._protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "dump-analyzer-e2e", "version": "0.1.0"},
            },
        }
        response, _events = self._post(payload, include_session=False)
        result = self._extract_result(response)
        self._notify_initialized()
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        response, _events = self._post(
            {
                "jsonrpc": "2.0",
                "id": next(self._counter),
                "method": "tools/list",
                "params": {},
            }
        )
        result = self._extract_result(response)
        return list(result.get("tools", []))

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        response, _events = self._post(
            {
                "jsonrpc": "2.0",
                "id": next(self._counter),
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )
        return self._extract_result(response)

    def call_tool_with_progress(self, name: str, arguments: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        response, events = self._post(
            {
                "jsonrpc": "2.0",
                "id": next(self._counter),
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )
        return self._extract_result(response), events

    def delete_session(self, timeout_seconds: int | None = None) -> None:
        if not self._session_id:
            return
        effective_timeout = timeout_seconds if timeout_seconds is not None else self.timeout_seconds
        req = request.Request(
            self._endpoint,
            method="DELETE",
            headers={
                "accept": "application/json",
                "content-type": "application/json",
                "mcp-session-id": self._session_id,
                "mcp-protocol-version": self._protocol_version,
            },
        )
        try:
            with request.urlopen(req, timeout=effective_timeout):
                return
        except error.HTTPError as exc:
            raise MCPHTTPError(f"DELETE /mcp/ failed: {exc.code} {exc.reason}") from exc
        finally:
            # Teardown should not keep using a stale session id after delete attempt.
            self._session_id = None

    def _notify_initialized(self) -> None:
        self._post(
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            }
        )

    def _post(self, payload: dict[str, Any], *, include_session: bool = True) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        self._trace(
            "request",
            {
                "url": self._endpoint,
                "include_session": include_session,
                "session_id": self._session_id,
                "payload": payload,
            },
        )
        headers = {
            "accept": "text/event-stream, application/json",
            "content-type": "application/json",
            "mcp-protocol-version": self._protocol_version,
        }
        if include_session and self._session_id:
            headers["mcp-session-id"] = self._session_id

        req = request.Request(
            self._endpoint,
            method="POST",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
        )
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as resp:
                status_code = resp.getcode()
                if not self._session_id:
                    new_sid = resp.headers.get("mcp-session-id")
                    if new_sid:
                        self._session_id = new_sid
                        self._trace("session", {"event": "created", "session_id": self._session_id})
                content_type = (resp.headers.get("content-type") or "").lower()
                if "text/event-stream" in content_type:
                    raw_lines: list[str] = []
                    events: list[dict[str, Any]] = []
                    progress_events: list[dict[str, Any]] = []
                    response: dict[str, Any] | None = None
                    data_lines: list[str] = []

                    def _flush_data_lines() -> None:
                        nonlocal response
                        if not data_lines:
                            return
                        data = "\n".join(data_lines)
                        data_lines.clear()
                        try:
                            event = json.loads(data)
                        except json.JSONDecodeError:
                            return
                        if not isinstance(event, dict):
                            return
                        events.append(event)
                        method = event.get("method")
                        if method in {"$/progress", "notifications/progress"}:
                            progress = self._normalize_progress_event(method, event.get("params"))
                            if progress is not None:
                                progress_events.append(progress)
                                # 实时逐条刷屏
                                self._trace("progress", progress)
                            return
                        if "id" in event and ("result" in event or "error" in event):
                            response = event

                    while True:
                        raw_line = resp.readline()
                        if not raw_line:
                            break
                        decoded_line = raw_line.decode("utf-8", errors="replace")
                        raw_lines.append(decoded_line)
                        line = decoded_line.rstrip("\r\n")
                        if line.startswith("data:"):
                            data_lines.append(line[5:].lstrip())
                            continue
                        if not line.strip():
                            _flush_data_lines()
                    _flush_data_lines()

                    decoded = "".join(raw_lines)
                    self._trace(
                        "response_raw",
                        {
                            "status_code": status_code,
                            "content_type": content_type,
                            "session_id": self._session_id,
                            "body": decoded,
                        },
                    )
                    if response is None:
                        self._record_exchange(
                            request_payload=payload,
                            response_payload=None,
                            raw_body=decoded,
                            events=events,
                            content_type=content_type,
                        )
                        raise MCPHTTPError(f"SSE stream missing terminal JSON-RPC response: {decoded[:300]}")
                    self.last_progress_events = progress_events
                    self._record_exchange(
                        request_payload=payload,
                        response_payload=response,
                        raw_body=decoded,
                        events=events,
                        content_type=content_type,
                    )
                    self._trace(
                        "response_sse",
                        {
                            "progress_count": len(progress_events),
                            "progress_preview": progress_events[-5:],
                            "terminal_response": response,
                        },
                    )
                    return response, progress_events

                body = resp.read()
                decoded = body.decode("utf-8", errors="replace")
                self._trace(
                    "response_raw",
                    {
                        "status_code": status_code,
                        "content_type": content_type,
                        "session_id": self._session_id,
                        "body": decoded,
                    },
                )
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            self._record_exchange(
                request_payload=payload,
                response_payload=None,
                raw_body=detail,
                events=[],
                content_type=(exc.headers.get("content-type") or "").lower() if exc.headers else "",
            )
            self._trace(
                "http_error",
                {
                    "status_code": exc.code,
                    "reason": exc.reason,
                    "content_type": (exc.headers.get("content-type") or "").lower() if exc.headers else "",
                    "body": detail,
                },
            )
            raise MCPHTTPError(f"POST /mcp/ failed: {exc.code} {detail}") from exc

        if not body:
            self.last_progress_events = []
            self._record_exchange(
                request_payload=payload,
                response_payload={},
                raw_body="",
                events=[],
                content_type=content_type,
            )
            return {}, []

        parsed = json.loads(decoded)
        if not isinstance(parsed, dict):
            self._record_exchange(
                request_payload=payload,
                response_payload=None,
                raw_body=decoded,
                events=[],
                content_type=content_type,
            )
            raise MCPHTTPError(f"Unexpected JSON-RPC response payload: {type(parsed).__name__}")
        self.last_progress_events = []
        self._record_exchange(
            request_payload=payload,
            response_payload=parsed,
            raw_body=decoded,
            events=[],
            content_type=content_type,
        )
        self._trace("response_json", {"response": parsed})
        return parsed, []

    @staticmethod
    def _normalize_progress_event(method: Any, params: Any) -> dict[str, Any] | None:
        if not isinstance(params, dict):
            return None
        if method == "$/progress":
            value = params.get("value")
            if isinstance(value, dict):
                return value
            return None
        message = params.get("message")
        parsed_message: dict[str, Any] = {}
        if isinstance(message, str) and message:
            try:
                loaded = json.loads(message)
                if isinstance(loaded, dict):
                    parsed_message = loaded
            except json.JSONDecodeError:
                parsed_message = {"message": message}
        return {
            "phase": parsed_message.get("phase", "running"),
            "message": parsed_message.get("message", message or ""),
            "percent": parsed_message.get("percent", params.get("progress")),
        }

    def _record_exchange(
        self,
        *,
        request_payload: dict[str, Any],
        response_payload: dict[str, Any] | None,
        raw_body: str,
        events: list[dict[str, Any]],
        content_type: str,
    ) -> None:
        self.last_exchange = {
            "endpoint": self._endpoint,
            "session_id": self._session_id,
            "request_payload": request_payload,
            "response_payload": response_payload,
            "content_type": content_type,
            "raw_body": raw_body,
            "events": events,
            "progress_events": self.last_progress_events,
        }

    def _trace(self, stage: str, payload: dict[str, Any]) -> None:
        if not self.trace_enabled:
            return
        encoded = json.dumps(payload, ensure_ascii=False)
        if self.trace_max_chars and len(encoded) > self.trace_max_chars:
            encoded = encoded[: self.trace_max_chars] + "...<truncated>"
        print(f"[e2e-mcp][{stage}] {encoded}")

    @staticmethod
    def _read_bool_env(name: str, default: bool) -> bool:
        raw = os.getenv(name)
        if raw is None:
            return default
        return raw.strip().lower() not in {"0", "false", "no", "off"}

    @staticmethod
    def _read_int_env(name: str, default: int) -> int:
        raw = os.getenv(name)
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            return default
        return max(256, value)

    @staticmethod
    def _parse_sse_payload(payload: str) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        data_lines: list[str] = []
        for raw_line in payload.splitlines():
            line = raw_line.rstrip("\r")
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
                continue
            if not line.strip():
                if data_lines:
                    data = "\n".join(data_lines)
                    data_lines.clear()
                    try:
                        event = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(event, dict):
                        events.append(event)
        if data_lines:
            data = "\n".join(data_lines)
            try:
                event = json.loads(data)
            except json.JSONDecodeError:
                return events
            if isinstance(event, dict):
                events.append(event)
        return events

    @staticmethod
    def _extract_result(response: dict[str, Any]) -> dict[str, Any]:
        if "error" in response:
            raise MCPHTTPError(f"MCP error: {json.dumps(response['error'], ensure_ascii=False)}")
        result = response.get("result")
        if not isinstance(result, dict):
            return {}
        return result
