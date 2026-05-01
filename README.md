# Dump Analyzer MCP Server

用于远程 Windows Crash Dump 分析的 MCP 服务：支持上传 dump、创建分析会话、执行 CDB 命令，并返回结构化状态与原始输出。

项目目标是让 AI 侧脱离对 Windows 操作系统的运行依赖：通过标准 MCP 接口调用部署在 Windows 服务端的 CDB 指令完成 dump 分析。

<!-- mcp-name: io.github.zuohuiyang/dump-analyzer-mcp-server -->

## 核心能力

- 通过标准 MCP 接口接入远程 Windows dump 分析能力
- 支持上传 dump、创建分析会话、执行 CDB 命令、关闭会话的完整闭环
- 支持在同一分析会话内连续执行多条命令
- 面向 AI/远程客户端场景，调用方无需直接运行 Windows 调试器

## 前置条件

- 操作系统：Windows
- Python：3.10 及以上
- 调试器：建议使用 Windows SDK `26100` 及以上版本（含 WinDbg/CDB），且服务端可访问 `cdb.exe`
- 网络：客户端可访问 `--public-base-url` 对应地址

## 安全边界

- 本服务默认面向内网/受信任环境，当前不内置用户鉴权与权限体系，请勿直接暴露公网。
- 如需跨网络访问，请在前置网关或反向代理层提供鉴权、访问控制与 TLS，并结合网络隔离、白名单和防火墙限制访问来源。
- 默认拒绝危险命令（如 `.shell`、重定向、`.create/.attach/.kill` 等）

## 使用流程

1. 调用 `prepare_dump_upload(file_size, file_name)` 获取 `file_id` 和 `upload_url`
2. 对 `upload_url` 发送 HTTP `PUT` 上传原始 dump 字节
3. 调用 `start_analysis_session(file_id)` 获取 `session_id`
4. 调用 `execute_windbg_command(session_id, command, timeout)` 执行 CDB 命令
5. 调用 `close_analysis_session(session_id)` 释放资源

## 运行特性

- MCP 通道采用 `streamable-http`
- 命令执行状态固定为：`queued`、`running`、`completed`
- CDB 输出原样透传，不做语义解析
- 命令长时间无输出时自动发送心跳，避免误判为卡死

## 从源码启动

适用于已克隆仓库、准备在本机直接启动服务的场景：

```powershell
uv sync
uv run dump-analyzer-mcp-server --host 0.0.0.0 --port 8000 --public-base-url http://your-host:8000
```

- MCP 入口：`http://your-host:8000/mcp`
- 上传入口：`http://your-host:8000/uploads/dumps/{file_id}`

## MCP 客户端配置示例

```json
{
  "mcpServers": {
    "dump-analyzer": {
      "url": "http://your-host:8000/mcp"
    }
  }
}
```

## 命令行参数

| 参数 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `--host` | 否 | `127.0.0.1` | 服务监听地址 |
| `--port` | 否 | `8000` | 服务监听端口 |
| `--public-base-url` | 是 | 无 | 返回给客户端的可访问基址 |
| `--cdb-path` | 否 | 自动探测 | `cdb.exe` 路径 |
| `--symbols-path` | 否 | `srv*c:\symbols*https://msdl.microsoft.com/download/symbols` | 服务端符号路径 |
| `--timeout` | 否 | `30` | 命令执行超时（秒） |
| `--upload-dir` | 否 | 系统默认目录 | 上传临时目录 |
| `--max-upload-mb` | 否 | `100` | 最大上传大小（MB） |
| `--session-ttl-seconds` | 否 | `1800` | 空闲会话 TTL（秒） |
| `--max-active-sessions` | 否 | `10` | 最大活跃会话数 |
| `--verbose` | 否 | `false` | 输出详细日志 |

说明：
- `--public-base-url` 必须是客户端可访问地址，否则 `prepare_dump_upload` 会返回 `UPLOAD_URL_UNAVAILABLE`
- `--symbols-path` 仅服务端管理员可配置；调用方工具参数不可覆盖符号路径

## 错误处理

- 工具调用失败时返回结构化错误（含错误码与错误信息）
- `prepare_dump_upload` 在无法生成可访问上传地址时返回 `UPLOAD_URL_UNAVAILABLE`
- 上传大小、文件格式、会话上限等限制会在入口阶段尽早失败

## 开发文档

- 开发、测试、E2E、CI 与常见排障：[`docs/development.md`](./docs/development.md)
- 技术设计与协议背景：[`docs/technical-design.md`](./docs/technical-design.md)
- 历史决策记录：[`docs/devlog.md`](./docs/devlog.md)

## 项目来源

- 本项目起步于上游 `svnscha/mcp-windbg`，并在此基础上持续演进。
- 当前项目已收敛为面向远程 Windows Crash Dump 分析的 MCP 服务，与上游在产品定位、工具边界和使用流程上存在明显差异。
- 本项目保留上游 MIT 许可证文本与原始版权声明，并在此基础上独立维护。

## 许可证

MIT
