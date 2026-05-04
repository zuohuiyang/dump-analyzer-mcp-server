[English](./README.md) | [简体中文](./README_zh.md)

# Dump Analyzer MCP Server

An MCP server for remote Windows Crash Dump analysis. It supports uploading dumps, creating analysis sessions, and executing CDB commands, returning structured status and raw output.

This enables AI agents to perform dump analysis via standard MCP interfaces by invoking CDB deployed on a Windows server, eliminating the need for the AI agent itself to run on a Windows operating system.

<!-- mcp-name: io.github.zuohuiyang/dump-analyzer-mcp-server -->

## Core Capabilities

- Wraps the CDB debugger into standard remote MCP calling interfaces
- Provides a complete analysis closed-loop workflow: uploading dumps, creating sessions, executing commands, and closing sessions

## Prerequisites

- OS: Windows
- Python: 3.10+
- Debugger: [Windows SDK `26100`](https://go.microsoft.com/fwlink/?linkid=2358390)+ (includes WinDbg/CDB)
- Clients must be able to access the `--public-base-url`

## Security Boundaries

- Designed for intranet/trusted environments by default. No built-in authentication. Do not expose directly to the public internet.
- Cross-network access requires authentication, TLS, and access control provided by a frontend gateway.
- Dangerous commands (`.shell`, redirection, `.create/.attach/.kill`, etc.) are rejected by default.

## Runtime Parameters

| Parameter | Default | Description |
| -- | -- | -- |
| `--host` | `0.0.0.0` | Service listen address |
| `--port` | `8000` | Service listen port |
| `--public-base-url` | Required | Externally accessible base URL, used to construct and return the dump upload URL to clients |
| `--cdb-path` | Auto-detect | Path to `cdb.exe` |
| `--symbols-path` | `srv*c:\symbols*https://msdl.microsoft.com/download/symbols` | Server-side symbol path |
| `--timeout` | `1800` | Command execution timeout (seconds) |
| `--upload-dir` | System temp dir | Temporary directory for uploads |
| `--max-upload-mb` | `100` | Maximum dump file upload size (MB) |
| `--session-ttl-seconds` | `1800` | Idle session TTL |
| `--max-active-sessions` | `10` | Maximum active sessions |
| `--verbose` | `false` | Enable DEBUG log level |

## Quick Start

### Installation via PyPI (Recommended)

```powershell
pip install dump-analyzer-mcp-server
dump-analyzer-mcp-server --public-base-url http://<your-public-ip-or-domain>:8000
```

### Run via uv (Development)

```powershell
uv sync
uv run dump-analyzer-mcp-server --public-base-url http://<your-public-ip-or-domain>:8000
```

- MCP Endpoint: `http://your-host:8000/mcp`

## MCP Client Configuration

```json
{
  "mcpServers": {
    "dump-analyzer": {
      "url": "http://<your-public-ip-or-domain>:8000/mcp"
    }
  }
}
```

## Documentation

- Development, Testing, E2E, CI: [`docs/development.md`](./docs/development.md)
- Technical Design & Protocol: [`docs/technical-design.md`](./docs/technical-design.md)
- Development Log: [`docs/devlog.md`](./docs/devlog.md)

## Acknowledgements

This project evolved from the upstream `svnscha/mcp-windbg` and has been focused as a dedicated MCP server for remote Windows Crash Dump analysis.

## License

MIT