from os import path as os_path

from dump_analyzer_mcp_server.cdb_session import DEFAULT_CDB_PATHS


def find_available_cdb() -> str | None:
    for path in DEFAULT_CDB_PATHS:
        if os_path.exists(path):
            return path
    return None


def has_available_cdb() -> bool:
    return find_available_cdb() is not None
