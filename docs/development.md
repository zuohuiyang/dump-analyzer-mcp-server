# 开发与测试

本文档面向项目维护者，补充主 `README.md` 中省略的开发、测试、E2E、CI 与排障细节。

## 目录约定

- 源码位于 `src/dump_analyzer_mcp_server/`
- 测试位于 `tests/`
- E2E 测试位于 `tests/e2e/`
- 测试 dump 位于 `tests/dumps/`
- 辅助脚本位于 `scripts/`

## 本地开发

安装开发依赖：

```powershell
uv sync --dev
```

本地启动服务：

```powershell
uv run python -m dump_analyzer_mcp_server --host 0.0.0.0 --port 8000 --public-base-url http://your-host:8000
```

说明：
- 所有运行时配置统一通过命令行参数传入
- `--public-base-url` 需要填写客户端实际可访问的地址
- `--symbols-path` 仅由服务端管理员配置，调用方不可覆盖

## 测试

运行全部测试：

```powershell
uv run pytest tests/ -v
```

只跑核心 CDB 测试：

```powershell
uv run pytest tests/test_cdb.py -v
```

只跑上传流程测试：

```powershell
uv run pytest tests/test_upload_session_integration.py -v
```

测试分层：
- 基础单测：覆盖工具协议、上传会话状态机与 CDB 执行内核关键行为
- 远端 E2E：覆盖“已部署服务 + 客户端调用”的真实闭环流程

## E2E 测试

E2E 统一按远程用户视角执行：测试代码作为客户端调用已部署服务。

一键执行部署、启动、全量 E2E 和清理：

```powershell
.\scripts\e2e-deploy-start-run.ps1
```

只跑核心闭环 E2E：

```powershell
uv run pytest tests/e2e -m "e2e and not e2e_symbol_heavy" -v
```

只跑大 PDB 长时间加载场景：

```powershell
uv run pytest tests/e2e -m "e2e_symbol_heavy" -v
```

脚本特性：
- 零参数执行：自动确定本机可用 IPv4 并启动服务
- 固定执行全量 E2E：`tests/e2e`
- `symbol_heavy` 样本路径由测试配置负责，默认使用 `tests/dumps/electron.dmp`
- E2E 客户端默认使用实际局域网 IP，与服务端 `public-base-url` 保持一致
- 执行前后都会清理临时 symbols 目录，保证下次仍为冷加载

常用环境变量：
- `DUMP_E2E_BASE_URL`：已部署服务地址
- `DUMP_E2E_DUMP_PATH`：核心闭环用例 dump 路径
- `DUMP_E2E_MCP_TRACE`：是否打印 MCP 收发日志
- `DUMP_E2E_MCP_TRACE_MAX_CHARS`：单条 MCP 日志最大字符数

## CI 建议

- 普通测试与远端 E2E 分离执行
- 普通测试使用：`pytest -m "not e2e_remote"`
- 远端 E2E 使用单独 Windows job，通过 `.\scripts\e2e-deploy-start-run.ps1` 启动服务后执行
- CI 中的 `public-base-url` 和 `DUMP_E2E_BASE_URL` 建议统一使用自动探测的本机可用 IPv4，而不是 `127.0.0.1`

## 常见排障

排查命令执行失败时，优先查看 E2E 日志中的 `[e2e-mcp]` 片段，可直接看到 MCP 请求参数与服务端返回的错误详情。

常见检查项：
- 端口冲突：`Get-NetTCPConnection -LocalPort 8000`
- 进程占用：`Get-CimInstance Win32_Process | ? { $_.CommandLine -match "dump_analyzer_mcp_server|pytest|uv run" }`
- dump 样本缺失：确认 `tests/dumps/` 中目标文件存在
- CDB 不可用：确认 Windows SDK / WinDbg 已安装，或显式传入 `--cdb-path`

日志位置：
- pytest 日志：`%TEMP%\dump-analyzer-e2e-pytest.log`
- server stdout：`%TEMP%\dump-analyzer-e2e-server.out.log`
- server stderr：`%TEMP%\dump-analyzer-e2e-server.err.log`

防火墙手动放行示例（管理员 PowerShell）：

```powershell
New-NetFirewallRule -DisplayName "DumpAnalyzer-E2E-8000" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8000
New-NetFirewallRule -DisplayName "DumpAnalyzer-E2E-Python" -Direction Inbound -Action Allow -Program "<venvPython路径>"
```

## 验收约束

`e2e_symbol_heavy` 场景的最低验收要求：
- 执行 `.ecxr;kv` 后，调用栈必须出现 `electron!electron::ElectronBindings::Crash`
- `00` 栈帧必须命中 `electron::ElectronBindings::Crash`
