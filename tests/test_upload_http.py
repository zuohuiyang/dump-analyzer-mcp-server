import asyncio
import concurrent.futures
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from dump_analyzer_mcp_server import server


pytestmark = pytest.mark.usefixtures("restore_upload_runtime_state")


@pytest.fixture(autouse=True)
def upload_test_env(configure_upload_runtime):
    configure_upload_runtime(max_upload_mb=1)
    server.configure_public_base_url(explicit_base_url="http://crashdump.local:8000")


def test_prepare_dump_upload_returns_upload_target():
    payload = server.create_upload_session("crash.dmp", 8)

    assert payload["file_id"]
    assert payload["upload_url"] == f"http://crashdump.local:8000{server.build_upload_path(payload['file_id'])}"

    metadata = server.session_registry.upload_sessions[payload["file_id"]]
    assert metadata.original_file_name == "crash.dmp"
    assert metadata.status == server.UploadSessionStatus.PENDING


def test_prepare_dump_upload_rejects_unusable_public_base_url():
    server.configure_public_base_url(explicit_base_url="http://0.0.0.0:8000")

    with pytest.raises(server.UploadWorkflowError) as exc_info:
        server.create_upload_session("crash.dmp", 8)

    assert exc_info.value.code == server.UPLOAD_ERROR_URL_UNAVAILABLE
    assert "public base URL" in exc_info.value.message
    assert not server.session_registry.upload_sessions


def test_put_upload_dump_succeeds_and_marks_session_uploaded():
    payload = server.create_upload_session("uploaded.dmp", 8)
    app = server.create_http_app()

    with TestClient(app) as client:
        response = client.put(server.build_upload_path(payload["file_id"]), content=b"MDMPxxxx")
        assert response.status_code == 201
        assert response.json()["status"] == "uploaded"

        metadata = server.session_registry.upload_sessions[payload["file_id"]]
        assert metadata.status == server.UploadSessionStatus.UPLOADED
        assert Path(metadata.temp_file_path).read_bytes() == b"MDMPxxxx"


def test_put_upload_dump_rejects_invalid_signature_and_rolls_back():
    payload = server.create_upload_session("bad.dmp", 7)
    metadata = server.session_registry.upload_sessions[payload["file_id"]]
    app = server.create_http_app()

    with TestClient(app) as client:
        response = client.put(server.build_upload_path(payload["file_id"]), content=b"NOTDUMP")

    assert response.status_code == 400
    assert response.json()["error"]["code"] == server.UPLOAD_ERROR_INVALID_FORMAT
    assert "Upload the raw bytes" in response.json()["error"]["remediation"]
    assert payload["file_id"] not in server.session_registry.upload_sessions
    assert not Path(metadata.temp_file_path).exists()


def test_put_upload_dump_rejects_size_mismatch():
    payload = server.create_upload_session("wrongsize.dmp", 9)
    metadata = server.session_registry.upload_sessions[payload["file_id"]]
    app = server.create_http_app()

    with TestClient(app) as client:
        response = client.put(server.build_upload_path(payload["file_id"]), content=b"MDMPxxxx")

    assert response.status_code == 400
    assert response.json()["error"]["code"] == server.UPLOAD_ERROR_SIZE_MISMATCH
    assert payload["file_id"] not in server.session_registry.upload_sessions
    assert not Path(metadata.temp_file_path).exists()


def test_put_upload_dump_rolls_back_on_cancellation(monkeypatch):
    payload = server.create_upload_session("cancelled.dmp", 4)
    metadata = server.session_registry.upload_sessions[payload["file_id"]]
    app = server.create_http_app()

    async def mock_stream_upload_to_file(*_args, **_kwargs):
        Path(metadata.temp_file_path).write_bytes(b"partial")
        raise asyncio.CancelledError()

    monkeypatch.setattr(server, "_stream_upload_to_file", mock_stream_upload_to_file)

    with TestClient(app) as client:
        with pytest.raises((asyncio.CancelledError, concurrent.futures.CancelledError)):
            client.put(server.build_upload_path(payload["file_id"]), content=b"MDMP")

    assert payload["file_id"] not in server.session_registry.upload_sessions
    assert not Path(metadata.temp_file_path).exists()
