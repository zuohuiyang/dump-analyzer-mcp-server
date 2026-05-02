# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This repository was forked from an upstream project, but this changelog only records
the release history of the refocused `dump-analyzer-mcp-server` project.

## [Unreleased]

## [0.1.0] - 2026-05-02

### Added

- 首发 `Dump Analyzer MCP Server`，聚焦远程 Windows crash dump 上传与分析场景
- 提供完整的 dump 分析工具链：`prepare_dump_upload`、`start_analysis_session`、`execute_windbg_command`、`close_analysis_session`
- 支持异步命令执行与状态查询，覆盖 `queued`、`running`、`completed` 等阶段
- 提供默认危险命令拦截，降低误执行高风险 WinDbg/CDB 命令的风险
- 提供服务端文件日志与基础审计能力，支持日志轮转、保留策略和关键关联字段记录
- 补充 README、CLI 与发布元数据，完善项目来源、运行方式与安全边界说明


