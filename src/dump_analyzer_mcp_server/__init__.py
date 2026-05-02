from .logging_utils import (
    DEFAULT_LOG_LEVEL,
    DEFAULT_LOG_MAX_TOTAL_SIZE_MB,
    DEFAULT_LOG_RETENTION_DAYS,
    configure_logging,
    create_logging_runtime_config,
    shutdown_logging,
)
from .server import serve_http

def main():
    """Dump Analyzer MCP server entry point."""
    import argparse
    import asyncio

    parser = argparse.ArgumentParser(
        description="Run the dump-analyzer-mcp-server for remote Windows crash dump analysis."
    )
    parser.add_argument("--cdb-path", type=str, help="Custom path to cdb.exe")
    parser.add_argument(
        "--symbols-path",
        type=str,
        default=None,
        help=(
            "Server-side symbol path (not overridable by tool callers). "
            "Default: srv*c:\\symbols*https://msdl.microsoft.com/download/symbols"
        ),
    )
    parser.add_argument("--timeout", type=int, default=1800, help="Command timeout in seconds")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument(
        "--log-dir",
        type=str,
        default=None,
        help="Directory used for rotated server log files",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=DEFAULT_LOG_LEVEL,
        help=f"Base log level: CRITICAL, ERROR, WARNING, INFO, DEBUG (default: {DEFAULT_LOG_LEVEL})",
    )
    parser.add_argument(
        "--log-retention-days",
        type=int,
        default=DEFAULT_LOG_RETENTION_DAYS,
        help=f"Number of rotated daily log files to retain (default: {DEFAULT_LOG_RETENTION_DAYS})",
    )
    parser.add_argument(
        "--log-keep-console",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Keep mirrored logs on the console in addition to log files",
    )
    parser.add_argument(
        "--log-max-total-size-mb",
        type=int,
        default=DEFAULT_LOG_MAX_TOTAL_SIZE_MB,
        help=(
            "Maximum total size of rotated log files in MB; oldest rotated logs are removed first "
            f"(default: {DEFAULT_LOG_MAX_TOTAL_SIZE_MB})"
        ),
    )
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to bind HTTP server to (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind HTTP server to (default: 8000)")
    parser.add_argument(
        "--public-base-url",
        type=str,
        required=True,
        help="Externally reachable base URL used when returning upload_url",
    )
    parser.add_argument(
        "--upload-dir",
        type=str,
        default=None,
        help="Directory used for temporary uploaded dump storage",
    )
    parser.add_argument(
        "--max-upload-mb",
        type=int,
        default=100,
        help="Maximum upload size in MB (default: 100)",
    )
    parser.add_argument(
        "--session-ttl-seconds",
        type=int,
        default=1800,
        help="TTL for inactive upload/analysis sessions in seconds (default: 1800)",
    )
    parser.add_argument(
        "--max-active-sessions",
        type=int,
        default=10,
        help="Maximum number of active upload sessions (default: 10)",
    )

    args = parser.parse_args()
    runtime_log_level = "DEBUG" if args.verbose else args.log_level
    log_config = create_logging_runtime_config(
        log_dir=args.log_dir,
        log_level=runtime_log_level,
        log_retention_days=args.log_retention_days,
        log_keep_console=args.log_keep_console,
        log_max_total_size_mb=args.log_max_total_size_mb,
    )
    configure_logging(log_config)

    try:
        asyncio.run(
            serve_http(
                host=args.host,
                port=args.port,
                cdb_path=args.cdb_path,
                symbols_path=args.symbols_path,
                timeout=args.timeout,
                verbose=args.verbose,
                public_base_url_override=args.public_base_url,
                upload_dir=args.upload_dir,
                max_upload_mb=args.max_upload_mb,
                session_ttl_seconds=args.session_ttl_seconds,
                max_active_sessions=args.max_active_sessions,
            )
        )
    finally:
        shutdown_logging()


if __name__ == "__main__":
    main()
