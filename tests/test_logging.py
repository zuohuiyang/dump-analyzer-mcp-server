import logging
from pathlib import Path

import pytest

from dump_analyzer_mcp_server.cdb_session import CDBSession, COMMAND_MARKER_TEXT
from dump_analyzer_mcp_server.logging_utils import (
    CappedTimedRotatingFileHandler,
    DEFAULT_LOG_MAX_FILE_SIZE_MB,
    LOG_FILE_NAME,
    configure_logging,
    create_logging_runtime_config,
    get_log_dir_total_size_bytes,
    prune_log_dir_to_size_limit,
    shutdown_logging,
)


def test_create_logging_runtime_config_rejects_non_positive_total_size():
    with pytest.raises(ValueError, match="log_max_total_size_mb"):
        create_logging_runtime_config(log_max_total_size_mb=0)


def test_prune_log_dir_to_size_limit_removes_oldest_rotated_logs(tmp_path: Path):
    active = tmp_path / LOG_FILE_NAME
    old1 = tmp_path / f"{LOG_FILE_NAME}.2026-05-01"
    old2 = tmp_path / f"{LOG_FILE_NAME}.2026-05-02"

    active.write_bytes(b"a" * 40)
    old1.write_bytes(b"b" * 30)
    old2.write_bytes(b"c" * 50)

    old1.touch()
    old2.touch()
    active.touch()

    removed = prune_log_dir_to_size_limit(
        str(tmp_path),
        max_total_size_bytes=70,
        active_log_file=str(active),
    )

    assert str(old1) in removed
    assert str(old2) in removed
    assert active.exists()
    assert not old1.exists()
    assert not old2.exists()
    assert get_log_dir_total_size_bytes(str(tmp_path)) == 40


def test_prune_log_dir_to_size_limit_keeps_active_log_when_it_alone_exceeds_limit(tmp_path: Path):
    active = tmp_path / LOG_FILE_NAME
    rotated = tmp_path / f"{LOG_FILE_NAME}.2026-05-01"

    active.write_bytes(b"a" * 120)
    rotated.write_bytes(b"b" * 20)

    removed = prune_log_dir_to_size_limit(
        str(tmp_path),
        max_total_size_bytes=100,
        active_log_file=str(active),
    )

    assert str(rotated) in removed
    assert active.exists()
    assert get_log_dir_total_size_bytes(str(tmp_path)) == 120


def test_oversized_active_log_is_rotated_and_reopened(tmp_path: Path):
    handler = CappedTimedRotatingFileHandler(
        filename=str(tmp_path / LOG_FILE_NAME),
        when="midnight",
        backupCount=14,
        encoding="utf-8",
        log_dir=str(tmp_path),
        max_total_size_bytes=100,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.max_file_size_bytes = 100

    logger = logging.getLogger("test_logging.oversized_active_log")
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False

    try:
        logger.info("x" * 120)
        handler.flush()
    finally:
        handler.close()
        logger.handlers = []

    active = tmp_path / LOG_FILE_NAME
    archived = list(tmp_path.glob(f"{LOG_FILE_NAME}.size-*"))

    assert active.exists()
    assert active.stat().st_size == 0
    assert get_log_dir_total_size_bytes(str(tmp_path)) <= 100
    assert len(archived) <= 1


def test_active_log_rollover_uses_hardcoded_single_file_limit(tmp_path: Path):
    handler = CappedTimedRotatingFileHandler(
        filename=str(tmp_path / LOG_FILE_NAME),
        when="midnight",
        backupCount=14,
        encoding="utf-8",
        log_dir=str(tmp_path),
        max_total_size_bytes=300 * 1024 * 1024,
    )
    handler.baseFilename = str(tmp_path / LOG_FILE_NAME)

    oversized = (DEFAULT_LOG_MAX_FILE_SIZE_MB * 1024 * 1024) + 1
    with open(tmp_path / LOG_FILE_NAME, "wb") as stream:
        stream.truncate(oversized)

    try:
        handler._rollover_active_file_if_oversized()
    finally:
        handler.close()

    archived = list(tmp_path.glob(f"{LOG_FILE_NAME}.size-*"))
    active = tmp_path / LOG_FILE_NAME

    assert archived
    assert active.exists()
    assert active.stat().st_size == 0


def test_server_log_captures_full_cdb_transcript_without_marker(tmp_path: Path):
    def write_handler(session, _payload: bytes) -> None:
        session._emit_line("A" * 450)
        session._emit_line(COMMAND_MARKER_TEXT)

    session = object.__new__(CDBSession)
    session.timeout = 1
    session.verbose = False
    session.log_context = {"file_id": "file-1", "session_id": "session-1"}
    session.logger = logging.getLogger("dump_analyzer_mcp_server.cdb_session")
    session._state_lock = __import__("threading").Lock()
    session._request_counter = 0
    session._symbol_diagnostics_enabled = False
    session._active_job = None
    session._jobs = {}
    session._job_queue = __import__("queue").Queue()
    session._shutdown_event = __import__("threading").Event()
    session.process = type(
        "_Process",
        (),
        {
            "stdin": type(
                "_Stdin",
                (),
                {"write": lambda _self, payload: write_handler(session, payload), "flush": lambda _self: None},
            )(),
            "poll": lambda _self: None,
        },
    )()
    session._worker_thread = __import__("threading").Thread(target=session._worker_loop, daemon=True)

    config = create_logging_runtime_config(log_dir=str(tmp_path), log_keep_console=False)
    configure_logging(config)
    try:
        session._worker_thread.start()
        result = session.execute_command("kb", timeout=1)
    finally:
        session._shutdown_event.set()
        shutdown_logging()

    assert result["status"] == "completed"
    content = (tmp_path / LOG_FILE_NAME).read_text(encoding="utf-8")
    assert "A" * 450 in content
    assert "<truncated>" not in content
    assert COMMAND_MARKER_TEXT not in content
