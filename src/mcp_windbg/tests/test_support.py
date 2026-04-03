import os

from mcp_windbg.cdb_session import DEFAULT_CDB_PATHS


def find_available_cdb() -> str | None:
    env_path = os.getenv("CDB_PATH")
    if env_path and os.path.exists(env_path):
        return env_path
    for path in DEFAULT_CDB_PATHS:
        if os.path.exists(path):
            return path
    return None


def has_available_cdb() -> bool:
    return find_available_cdb() is not None
