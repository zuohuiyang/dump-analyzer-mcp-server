# Changelog

All notable changes to the MCP Server for WinDbg Crash Analysis project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Note:
- Entries from `0.12.x` and earlier are inherited from the upstream fork history.
- Those historical entries may mention capabilities or repository files that were removed after this project was refocused on remote crash dump analysis.

## [Unreleased]

### Added

- `README.md`：补充项目来源、上游仓库与 MIT 归因说明
- 新增工具面重构：`prepare_dump_upload`、`start_analysis_session`、`execute_windbg_command`、`close_analysis_session`
- 新增命令阶段状态：`queued/running/completed`
- 新增危险命令拦截策略，默认严格拒绝执行
- 在 README 中新增安全边界说明：服务默认用于内网/可信环境，当前不内置鉴权，公网使用需前置鉴权与 TLS
- 新增服务器日志系统：默认文件日志、按天轮转、保留关键审计字段，并支持通过 CLI 配置日志目录、级别与保留策略
- 新增日志目录总大小限制参数 `--log-max-total-size-mb`，默认 `2048MB`

### Changed

- 项目对外定位调整为 `Dump Analyzer MCP Server`，聚焦远程 crash dump 分析服务
- 上传会话结果重新返回完整 `upload_url`，降低客户端集成门槛
- MCP 工具面移除远程调试相关工具，仅保留 dump 分析链路
- `server.json`、README、CLI 与发布说明统一改名为 `dump-analyzer-mcp-server`
- 命令执行模型改为 marker 驱动完成判定（`COMMAND_COMPLETED_MARKER`），不再依赖提示符正则
- `pending` 阶段命名替换为 `queued`
- 调用方不再可配置符号路径，仅允许服务端管理员通过 CLI/环境变量配置
- 移除不再使用的 prompt 子系统代码与文件
- 服务器日志默认采用脱敏与截断策略，不再直接把完整 CDB 输出打印到控制台；多人并发调用时可通过 `request_id/file_id/session_id` 关联排障
- 日志清理策略扩展为“按天轮转 + 总目录大小上限”，超出限制时自动删除最老轮转日志
- 单个活动日志文件新增硬编码 `100MB` 上限，超过后服务会立即切换到新的活动日志文件

### Fixed

- **Upload Session Cleanup**: Clean up failed upload sessions immediately, reject expired uploaded sessions on access, and allow expired stale uploading sessions to be reclaimed safely
- 版本一致性脚本改为忽略 `Unreleased` 标题，按首个正式版本校验
- 修复 CDB 输出处理中 `\r` 进度行不及时透传的问题
- 修复服务端缺少长期运行日志落盘、并发会话缺少统一关联字段、以及日志中可能泄露完整本地路径/危险命令摘要的问题

## [0.1.0] - 2026-04-15

- 今天初始，待发版。

## [0.12.2] - 2025-12-15

### Fixed

- **Registry Schema Migration**: Updated MCP server schema from deprecated `2025-10-17` to current `2025-12-11` version for mcp-publisher compatibility

## [0.12.1] - 2025-12-15

### Added

- **HTTP Transport in Registry**: Added `streamable-http` transport configuration to server.json for MCP registry discovery
- **Schema Validation in CI**: New `validate-server-schema.py` script validates server.json against the official MCP schema

### Fixed

- **Registry Schema Update**: Updated MCP server schema version from 2025-09-29 to 2025-10-17 for compatibility with registry.modelcontextprotocol.io
- **CI Cache Warning**: Disabled unnecessary dependency caching in PyPI publish job to eliminate spurious warnings

## [0.12.0] - 2025-12-15

### Added

- **HTTP Transport Support**: New `--transport streamable-http` option enables HTTP-based communication alongside the default stdio transport (#31)
- **MCP Prompt API**: Implemented prompt templates for AI-assisted crash dump triage and analysis (#25)

### Changed

- **Updated Dependencies**: Bumped `mcp` to 1.17.0, `pydantic` to 2.12.0, and other dependencies (#26)
- **Improved Prompt Templates**: Removed hard-coded model references from prompt templates for better flexibility (#29)
- **Updated Dependabot Configuration**: Improved automated dependency update settings

### Fixed

- **Session Cleanup**: Prevent stale debugging sessions if `.shutdown()` fails (#28)

## [0.10.0] - 2025-10-10

**What's New in This Release**

This release focuses on making dump-analyzer-mcp-server more reliable, faster, and easier to use for everyone - from beginners to advanced users.

### New Features

**Core**
- Inherited upstream live debugging session support
- Extended dump file support for `.mdmp` and `.hdmp` formats
- Microsoft Store WinDbg CDB compatibility

**Devops**
- Set up continuous integration that automatically tests the code with Python versions 3.10 through 3.14
- Added automatic dependency updates to keep everything secure and up-to-date
- Streamlined the release process so new versions reach users faster

**Development**
- Switched to `uv` - a lightning-fast Python package manager that's 10-100x faster than pip
- Development setup is now much quicker with commands like `uv sync` and `uv run`
- More reliable builds with locked dependency versions

**Documentation**
- Added comprehensive debugging instructions for AI assistants ([`AGENTS.md`](AGENTS.md))
- Created inherited upstream prompt templates for crash dump analysis
- All documentation is now available in the [repository Wiki](https://github.com/zuohuiyang/dump-analyzer-mcp-server/wiki) for easy access
- Simplified the main [`README.md`](README.md) to focus on getting started quickly
- Added this structured [`CHANGELOG.md`](CHANGELOG.md) to track all project changes

### Improvements

**Performance Boost**: Build times are significantly faster thanks to the new tooling
**Enhanced Security**: Automatic scanning and updates keep dependencies secure

### 🤝 Community Contributions

Special thanks to [@sooknarine](https://github.com/sooknarine) for these valuable contributions:
- [Find local dumps with other common extensions #6](https://github.com/zuohuiyang/dump-analyzer-mcp-server/pull/6) - Now finds more crash dump files automatically
- [Add support for remote debugging #10](https://github.com/zuohuiyang/dump-analyzer-mcp-server/pull/10) - Connect to live debugging sessions


