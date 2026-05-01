# 开发日志 (Devlog)

## 2026-04-12

### 安全设计讨论

**议题：符号路径控制**

用户明确表示不希望调用方能够自定义符号服务器路径，希望将其硬编码在服务端。

**决策：**
- 符号路径硬编码为 `srv*c:\symbols*https://msdl.microsoft.com/download/symbols`
- `start_analysis_session` 的 `symbol_path` 参数移除
- 技术方案中明确说明符号路径不可配置

---

**议题：危险命令控制**

用户指出 CDB 命令中存在可执行 shell 命令的风险（`.shell`、管道操作等），这可能导致服务器被控制。

**建议禁用的命令类别：**

| 类别 | 典型命令 | 风险 |
|------|---------|------|
| shell 执行 | `.shell`, `\|`, `<`, `>` | 直接在服务器执行任意命令 |
| 进程控制 | `.create`, `.attach`, `.kill` | 控制服务器上其他进程 |
| 文件操作 | `.write_mem`, `.dump` (带路径) | 写服务器文件系统 |
| 远程连接 | `.remote`, `.server` | 建立反向 shell |
| 注册表 | `reg` | 修改服务器注册表 |
| 服务控制 | `sc` | 操控服务器服务 |

**决策：危险命令控制范围**

用户确认危险命令列表已经足够，路径暴露类命令不需要禁用。

**定位：**
- 目标：防止 AI 无意误用，不防刻意攻击
- 场景：内网服务，风险边界可控

**最终禁用列表：**
| 类别 | 典型命令 |
|------|---------|
| shell 执行 | `.shell`, `\|`, `<`, `>` |
| 进程控制 | `.create`, `.attach`, `.kill` |
| 文件操作 | `.write_mem`, `.dump` (带路径) |
| 远程连接 | `.remote`, `.server` |
| 注册表 | `reg` |
| 服务控制 | `sc` |

---

**议题：断线重连机制**

客户端使用 sessionId 即可重连，继续使用同一会话。sessionId 作为会话的唯一标识，足够支撑重连逻辑。

**结论：**
- 重连后客户端通过 sessionId 恢复会话
- 不需要额外的消费点（cursor）机制

---

**议题：命令完成检测改进**

参考 mcp-windbg，使用 `.echo COMMAND_COMPLETED_MARKER` 标记命令结束，比单独检测提示符更可靠，避免被输出内容中的提示符误触发。

**决策：**
- 每次执行命令时，在命令后附加 `.echo COMMAND_COMPLETED_MARKER`
- 通过检测该标记判断命令是否完成，而非依赖提示符正则

---

**议题：Ctrl+Break 中断实现**

参考 mcp-windbg 的 `send_ctrl_break` 实现，使用 `signal.CTRL_BREAK_EVENT` 发送中断信号。

**决策：**
- 取消机制采用 CTRL_BREAK_EVENT 信号
- 等待最多 5 秒让 CDB 响应中断

---

**议题：资源上限强制机制**

针对之前讨论的"限制 10 个会话、4GB dump 文件"，用户明确要求在**上传前/会话创建前就拒绝**，而不是接受后再清理。

**决策：**
- 最大会话数和最大 dump 文件大小在请求入口处强制校验，超限直接返回错误
- 不依赖事后清理，防止临时文件打满磁盘

---

**议题：HTTP SSE 与长连接方案选型（早期讨论）**

在 MCP + CDB/WinDbg 交互调试场景中，命令执行可能持续数十秒到数分钟，需要实时流式输出并兼顾断线恢复。
早期候选方案为 WebSocket 全双工长连接与 HTTP SSE 单向推送。
WebSocket 虽具备全双工和成熟重连能力，但在代理/防火墙适配、部分 MCP 客户端通道兼容性与连接状态管理复杂度上成本更高。
HTTP SSE 基于标准 HTTP，对 **MCP 客户端兼容性更好**，且与“请求一次、持续输出、执行结束”的交互模型天然匹配。
SSE 的静默超时可通过 5 秒心跳保活解决，因此无需为保活问题引入 WebSocket。

**决策：**
- 优先采用 HTTP SSE，不使用 WebSocket 作为主通道
- 约定无输出超过 5 秒发送一次保活信息（如“正在处理中...”）

**延伸结论：**
- 业务 session 与传输连接解耦，不能依赖连接存活维持 CDB 会话
- 客户端通过显式 `session_id` 重连并继续同一调试会话

---

## 2026-04-14

### 全量重构落地决策

**议题：阶段命名调整**

用户不接受 `pending` 阶段名，要求替换为更明确的命名。

**决策：**
- 三阶段状态机最终固定为：`queued -> running -> completed`

---

**议题：工具面收敛**

用户要求严格按技术方案执行，删除方案外工具与无用代码文件。

**决策：**
- 仅保留 4 个工具：`prepare_dump_upload`、`start_analysis_session`、`execute_windbg_command`、`close_analysis_session`
- 删除旧工具实现与不再使用的 prompt 子系统文件

---

**议题：符号路径控制**

用户要求调用方不可配置符号路径，同时保留服务端管理员可配置能力。

**决策：**
- 工具接口不暴露 `symbol_path`
- 服务端通过 CLI/环境变量配置符号路径；未配置时使用默认值 `srv*c:\symbols*https://msdl.microsoft.com/download/symbols`

---

## 2026-04-26

### SSE 落地与重符号场景可观测性

**议题：MCP 实时输出通道实现与文档一致性**

代码实现曾使用 `streamable-http` 的 JSON 响应模式，造成“文档写 SSE、实现看起来像非流式”的理解偏差。

**决策：**
- MCP `/mcp` 通道按 SSE 实时事件语义落地（单通道）
- 命令执行继续使用 `queued -> running -> completed` 三阶段
- 保留 5 秒心跳（`正在处理中...`）避免长时间静默误判
- 命令结束保留最终汇总结果（success/output/execution_time_ms/cancelled）

**议题：符号加载进度可见性验收（symbol_heavy）**

用户要求在大 PDB 场景中可见加载过程，便于定位“是否卡在符号下载/解析”。

**决策：**
- `test_e2e_symbol_heavy.py` 在 `.reload /f` 前执行 `!sym noisy`
- 通过实时 progress 事件观察符号相关调试输出（如 `SYMSRV/DBGHELP/PDB/symbol`）
- 场景收尾可执行 `!sym quiet` 降低后续命令噪声

**约束确认：**
- 坚持零解析原则：原样输出 CDB 文本，不引入百分比估算逻辑（无 30%/40% 推导）
