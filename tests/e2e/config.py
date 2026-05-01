from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class E2EConfig:
    base_url: str
    dump_path: Path
    timeout_seconds: int
    symbol_heavy_dump_path: Path | None
    remote_server_configured: bool


def load_e2e_config(repo_root: Path) -> E2EConfig:
    default_dump_path = repo_root / "tests" / "dumps" / "DemoCrash1.exe.7088.dmp"
    default_symbol_heavy_dump_path = repo_root / "tests" / "dumps" / "electron.dmp"
    dump_path = Path(os.getenv("DUMP_E2E_DUMP_PATH", str(default_dump_path))).expanduser().resolve()
    configured_base_url = os.getenv("DUMP_E2E_BASE_URL", "").strip().rstrip("/")
    base_url = configured_base_url or "http://127.0.0.1:8000"

    symbol_heavy_dump_env = os.getenv("DUMP_E2E_SYMBOL_HEAVY_DUMP_PATH", str(default_symbol_heavy_dump_path)).strip()
    symbol_heavy_dump_path = (
        Path(symbol_heavy_dump_env).expanduser().resolve() if symbol_heavy_dump_env else None
    )

    return E2EConfig(
        base_url=base_url,
        dump_path=dump_path,
        timeout_seconds=int(os.getenv("DUMP_E2E_TIMEOUT_SECONDS", "600")),
        symbol_heavy_dump_path=symbol_heavy_dump_path,
        remote_server_configured=bool(configured_base_url),
    )
