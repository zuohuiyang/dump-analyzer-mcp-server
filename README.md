# Dump Analyzer MCP Server

用于远程 Windows Crash Dump 分析的 MCP 服务：支持上传 dump、创建分析会话、执行 CDB 命令，返回结构化状态与原始输出。

让 AI 侧通过标准 MCP 接口调用部署在 Windows 服务端的 CDB 完成 dump 分析，无需直接运行 Windows 调试器。

<!-- mcp-name: io.github.zuohuiyang/dump-analyzer-mcp-server -->

## 核心能力

- 标准 MCP 接口接入远程 Windows dump 分析
- 上传 dump → 创建会话 → 执行命令 → 关闭会话的完整闭环
- 同一会话内连续执行多条命令
- 重命令异步执行，通过查询接口获取状态与结果

## 前置条件

- OS：Windows
- Python：3.10+
- 调试器：[Windows SDK `26100`](https://go.microsoft.com/fwlink/?linkid=2358390)+（含 WinDbg/CDB）
- 客户端可访问 `--public-base-url`

## 安全边界

- 默认面向内网/受信任环境，无内置鉴权，请勿直接暴露公网
- 跨网络访问需在前置网关提供鉴权、TLS、访问控制
- 默认拒绝危险命令（`.shell`、重定向、`.create/.attach/.kill` 等）

## 运行参数

| 参数 | 默认值 | 说明 |
| -- | -- | -- |
| `--host` | `127.0.0.1` | 服务监听地址 |
| `--port` | `8000` | 服务监听端口 |
| `--public-base-url` | 必填 | 客户端可访问的基址 |
| `--cdb-path` | 自动探测 | `cdb.exe` 路径 |
| `--symbols-path` | `srv*c:\symbols*https://msdl.microsoft.com/download/symbols` | 服务端符号路径 |
| `--timeout` | `1800` | 命令执行超时（秒） |
| `--upload-dir` | 系统临时目录 | 上传临时目录 |
| `--max-upload-mb` | `100` | 最大上传大小（MB） |
| `--session-ttl-seconds` | `1800` | 空闲会话 TTL |
| `--max-active-sessions` | `10` | 最大活跃会话数 |
| `--verbose` | `false` | DEBUG 日志级别 |

## 启动方式

### PyPI 安装（推荐）

```powershell
pip install dump-analyzer-mcp-server
dump-analyzer-mcp-server --host 0.0.0.0 --port 8000 --public-base-url http://your-host:8000
```

### uv 运行（开发用）

```powershell
uv sync
uv run dump-analyzer-mcp-server --host 0.0.0.0 --port 8000 --public-base-url http://your-host:8000
```

- MCP 入口：`http://your-host:8000/mcp`
- 上传入口：`http://your-host:8000/uploads/dumps/{file_id}`

## MCP 客户端配置

```json
{
  "mcpServers": {
    "dump-analyzer": {
      "url": "http://your-host:8000/mcp"
    }
  }
}
```

## 开发文档

- 开发、测试、E2E、CI：[`docs/development.md`](./docs/development.md)
- 技术设计与协议：[`docs/technical-design.md`](./docs/technical-design.md)
- 历史决策：[`docs/devlog.md`](./docs/devlog.md)

## 来源

本项目基于上游 `svnscha/mcp-windbg` 演进而来，已收敛为面向远程 Windows Crash Dump 分析的 MCP 服务。

## 许可证

MIT
