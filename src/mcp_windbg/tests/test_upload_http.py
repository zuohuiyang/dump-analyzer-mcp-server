import asyncio
import concurrent.futures
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from mcp_windbg import server


pytestmark = pytest.mark.usefixtures("restore_upload_runtime_state")


@pytest.fixture(autouse=True)
def upload_test_env(configure_upload_runtime):
    configure_upload_runtime(max_upload_mb=1)


def test_create_upload_session_returns_upload_target():
    payload = server.create_upload_session("crash.dmp")

    assert payload["session_id"]
    assert payload["upload_path"].startswith("/uploads/dumps/")
    assert payload["upload_path"].endswith(payload["session_id"])

    metadata = server.session_registry.upload_sessions[payload["session_id"]]
    assert metadata.original_file_name == "crash.dmp"
    assert metadata.status == server.UploadSessionStatus.PENDING


def test_put_upload_dump_succeeds_and_marks_session_uploaded():
    payload = server.create_upload_session("uploaded.dmp")
    app = server.create_http_app()

    with TestClient(app) as client:
        response = client.put(payload["upload_path"], content=b"MDMPxxxx")
        assert response.status_code == 201
        assert response.json()["status"] == "uploaded"

        metadata = server.session_registry.upload_sessions[payload["session_id"]]
        assert metadata.status == server.UploadSessionStatus.UPLOADED
        assert Path(metadata.temp_file_path).read_bytes() == b"MDMPxxxx"


def test_put_upload_dump_rejects_invalid_signature_and_rolls_back():
    payload = server.create_upload_session("bad.dmp")
    metadata = server.session_registry.upload_sessions[payload["session_id"]]
    app = server.create_http_app()

    with TestClient(app) as client:
        response = client.put(payload["upload_path"], content=b"NOTDUMP")

    assert response.status_code == 400
    assert payload["session_id"] not in server.session_registry.upload_sessions
    assert not Path(metadata.temp_file_path).exists()


def test_put_upload_dump_rolls_back_on_cancellation(monkeypatch):
    payload = server.create_upload_session("cancelled.dmp")
    metadata = server.session_registry.upload_sessions[payload["session_id"]]
    app = server.create_http_app()

    async def mock_stream_upload_to_file(*_args, **_kwargs):
        Path(metadata.temp_file_path).write_bytes(b"partial")
        raise asyncio.CancelledError()

    monkeypatch.setattr(server, "_stream_upload_to_file", mock_stream_upload_to_file)

    with TestClient(app) as client:
        with pytest.raises((asyncio.CancelledError, concurrent.futures.CancelledError)):
            client.put(payload["upload_path"], content=b"MDMP")

    assert payload["session_id"] not in server.session_registry.upload_sessions
    assert not Path(metadata.temp_file_path).exists()
