import pytest

from dump_analyzer_mcp_server import server


@pytest.fixture
def restore_upload_runtime_state():
    original_upload_dir = server.upload_runtime_config.upload_dir
    original_max_upload_mb = server.upload_runtime_config.max_upload_mb
    original_session_ttl = server.upload_runtime_config.session_ttl_seconds
    original_max_active_sessions = server.upload_runtime_config.max_active_sessions
    original_initialized_dir = server.upload_sessions._initialized_upload_dir
    original_public_base_url = server.public_base_url

    server.cleanup_sessions()
    try:
        yield
    finally:
        server.cleanup_sessions()
        server.upload_runtime_config.upload_dir = original_upload_dir
        server.upload_runtime_config.max_upload_mb = original_max_upload_mb
        server.upload_runtime_config.session_ttl_seconds = original_session_ttl
        server.upload_runtime_config.max_active_sessions = original_max_active_sessions
        server.upload_sessions._initialized_upload_dir = original_initialized_dir
        server.public_base_url = original_public_base_url


@pytest.fixture
def configure_upload_runtime(tmp_path, restore_upload_runtime_state):
    def _configure(
        *,
        max_upload_mb=None,
        session_ttl_seconds=None,
        max_active_sessions=None,
    ):
        server.upload_runtime_config.upload_dir = str(tmp_path)
        if max_upload_mb is not None:
            server.upload_runtime_config.max_upload_mb = max_upload_mb
        if session_ttl_seconds is not None:
            server.upload_runtime_config.session_ttl_seconds = session_ttl_seconds
        if max_active_sessions is not None:
            server.upload_runtime_config.max_active_sessions = max_active_sessions
        server.upload_sessions.initialize_upload_storage(server.upload_runtime_config)
        return tmp_path

    return _configure
