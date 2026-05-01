# MCP CDB 崩溃转储分析服务器设计方案

**作者：** 豆包  
**版本：** 1.0  
**日期：** 2026年4月12日  
**状态：** 最终确定  

> 📝 **开发日志：** [devlog.md](./devlog.md) — 设计讨论与决策记录

> ✅ **实现对齐注记（2026-04-26）：** 运行时通道按 `streamable-http` 的 SSE 实时事件语义落地；进度模型维持 `queued/running/completed + 原样文本 + 5秒心跳 + 最终汇总`，不引入百分比估算逻辑。

---

## 一、项目概述

本项目旨在开发一个符合MCP(Model Context Protocol)规范的远程崩溃转储分析服务器，允许用户通过Claude等AI助手上传dump文件并执行任意Windbg/CDB命令进行调试分析。

### 核心需求

1. 支持远程部署，通过HTTP协议访问

2. 处理长耗时操作（PDB下载、dump加载、复杂分析）

3. 解决长耗时操作导致的"假卡死"问题

4. 提供与原生CDB完全一致的输出体验

5. 支持交互式多命令会话

---

## 二、核心设计原则

以下原则是经过多轮讨论确定的，是整个设计的基础，任何修改都必须遵循这些原则。

### 决策1：零解析原则

**讨论过程：**

- 最初方案：设计复杂的输出解析器，提取符号加载进度、堆扫描进度等信息，生成结构化的进度通知

- 用户反对："不要加什么特殊的逻辑，我们直接把执行命令后WinDbg或者说CDB它们返回的每一行输出，我们都原样转发给调用者就好了"

- 最终结论：不对CDB输出做任何修改、过滤或解析

**理由：**

1. 调试工具的第一原则是输出绝对准确，任何解析都可能引入bug

2. 解析逻辑需要随着Windbg版本更新而维护，增加维护成本

3. 原样转发可以保证与原生CDB完全一致的体验

4. 代码量大幅减少，可靠性显著提高

---

### 决策2：通用阶段原则

**讨论过程：**

- 最初方案：为!analyze -v等命令设计特殊阶段（symbol_loading、heap_scan等）

- 用户反对："不要专门为一个命令而设计特殊的阶段，比方说符号加载。有时候用户可能执行lm这种命令，它并不会触发符号加载"

- 最终结论：使用通用的三阶段状态机，适用于所有命令

**理由：**

1. 没有任何命令特定的硬编码逻辑

2. 代码逻辑固定不变，永远不需要为新命令修改

3. 行为100%可预测，易于调试和维护

4. 简单命令表现简单，复杂命令自动获得相同的体验

---

### 决策3：HTTP SSE 传输协议

**讨论过程：**

- 可选方案：HTTP SSE vs WebSocket

- 最终结论：优先使用HTTP SSE

**理由：**

1. 100%兼容所有MCP客户端，包括Claude Web

2. 实现简单，维护成本低

3. 只要正确配置心跳和超时，完全可以满足5分钟以上的长调用需求

4. WebSocket虽然连接稳定性更好，但兼容性差，只适合特定客户端环境

---

### 决策4：保留明确状态机

**讨论过程：**

- 极简方案：只发送输出和心跳，不发送明确的状态通知

- 用户支持："queued 还有 complete 这种状态，我认为它需要保留的，这种阶段我认为它是需要保留的。因为这种它维护起来很方便，而且它十分的明确"

- 最终结论：保留queued/running/completed三阶段状态机

**理由：**

1. 明确的状态划分是代码可维护性的基础

2. 阶段切换完全由CDB进程的IO事件驱动，不需要任何解析逻辑

3. 让整个协议的行为100%可预测

4. 易于调试和问题排查

---

## 三、整体架构

```
客户端(Claude)                              MCP服务器(CDB服务)
   |                                              |
   |--- 1. 准备上传 ----------------------->|
   |<-- 预签名URL -------------------------|
   |--- 2. HTTP PUT上传dump -------------->|
   |                                              |
   |--- 3. 启动分析会话 ------------------->|
   |<-- 实时进度通知(PDB下载/加载) --------|
   |<-- 会话创建成功(sessionId) -----------|
   |                                              |
   |--- 4. 执行CDB命令 ------------------->|
   |<-- queued通知 ------------------------|
   |<-- 原样输出行 ------------------------|
   |<-- 自动心跳(5秒无输出) ---------------|
   |<-- completed通知 ---------------------|
   |<-- 最终响应 --------------------------|
   |                                              |
   |--- 5. 关闭会话 ----------------------->|
   |                |  终止CDB进程
   |                |  删除临时文件
   |<-- 关闭确认 --------------------------|
```

---

## 四、详细协议设计

### 4.1 工具定义

#### 4.1.1 prepare_dump_upload

```json
{
 "name": "prepare_dump_upload",
 "description": "准备上传崩溃转储文件，返回预签名上传地址",
 "inputSchema": {
 "type": "object",
 "properties": {
 "file_size": { "type": "number", "description": "文件大小(字节)" },
 "file_name": { "type": "string", "description": "原始文件名" }
 },
 "required": ["file_size", "file_name"]
 }
}
```

#### 4.1.2 start_analysis_session

```json
{
 "name": "start_analysis_session",
 "description": "启动崩溃转储分析会话，加载dump文件和符号。此操作可能需要3-10分钟，将实时显示进度。",
 "inputSchema": {
 "type": "object",
 "properties": {
 "file_id": { "type": "string", "description": "上传成功后返回的文件ID" }
 },
 "required": ["file_id"]
 }
}
```

#### 4.1.3 execute_windbg_command

```json
{
 "name": "execute_windbg_command",
 "description": "在分析会话中执行任意CDB命令，实时返回原始输出。长耗时命令会自动发送心跳保持连接。",
 "inputSchema": {
 "type": "object",
 "properties": {
 "session_id": { "type": "string", "description": "分析会话ID" },
 "command": { "type": "string", "description": "要执行的CDB命令" },
 "timeout": { "type": "number", "description": "命令超时时间(秒)", "default": 600 }
 },
 "required": ["session_id", "command"]
 }
}
```

#### 4.1.4 close_analysis_session

```json
{
 "name": "close_analysis_session",
 "description": "关闭分析会话，释放所有资源并删除临时文件",
 "inputSchema": {
 "type": "object",
 "properties": {
 "session_id": { "type": "string", "description": "会话ID" }
 },
 "required": ["session_id"]
 }
}
```

---

### 4.2 标准进度通知格式

所有通知都使用MCP标准的`$/progress`方法，没有任何自定义方法。

```json
{
 "jsonrpc": "2.0",
 "method": "$/progress",
 "params": {
 "token": <request_id>,
 "value": {
 "percent": <number|null>,
 "message": <string>,
 "phase": "queued"|"running"|"completed"
 }
 }
}
```

---

### 4.3 命令执行完整流程

```
客户端发送命令请求(id=456)
        ↓
服务器立即发送queued通知(100ms内)
{
 "jsonrpc": "2.0",
 "method": "$/progress",
 "params": {
 "token": 456,
 "value": {
 "percent": 0,
 "message": "执行命令: !analyze -v",
 "phase": "queued"
 }
 }
}
        ↓
写入命令到CDB stdin，同时附加 `.echo COMMAND_COMPLETED_MARKER` 标记
        ↓
收到第一字节输出 → 进入running阶段
        ↓
原样转发所有输出
{
 "jsonrpc": "2.0",
 "method": "$/progress",
 "params": {
 "token": 456,
 "value": {
 "percent": null,
 "message": "Loading unloaded module list\n",
 "phase": "running"
 }
 }
}
        ↓
连续5秒无输出 → 自动发送心跳
{
 "jsonrpc": "2.0",
 "method": "$/progress",
 "params": {
 "token": 456,
 "value": {
 "percent": null,
 "message": "正在处理中...",
 "phase": "running"
 }
 }
}
        ↓
检测到 COMMAND_COMPLETED_MARKER → 命令完成（不依赖提示符正则，避免输出内容误触发）
        ↓
发送completed通知
{
 "jsonrpc": "2.0",
 "method": "$/progress",
 "params": {
 "token": 456,
 "value": {
 "percent": 100,
 "message": "命令执行完成",
 "phase": "completed"
 }
 }
}
        ↓
返回最终响应
{
 "jsonrpc": "2.0",
 "id": 456,
 "result": {
 "success": true,
 "command": "!analyze -v",
 "output": "完整的原始输出",
 "execution_time_ms": 125430
 }
}
```

---

### 4.4 命令取消机制

使用MCP标准的`$/cancelRequest`通知：

```json
{
 "jsonrpc": "2.0",
 "method": "$/cancelRequest",
 "params": {
 "id": 456
 }
}
```

**服务器处理：**

1. 向CDB进程发送 `CTRL_BREAK_EVENT` 信号（Windows）

2. 等待最多5秒让CDB响应中断

3. 返回已收到的所有输出

4. 会话保持可用，可以继续执行下一个命令

---

## 五、关键技术问题与解决方案

### 问题1：CDB使用\r更新同一行进度导致进度丢失

**问题描述：**

CDB在显示PDB下载进度等信息时，使用回车符`\r`而不是换行符`\n`来更新同一行。标准的readline()方法会一直阻塞直到遇到`\n`，导致用户在整个下载过程中看不到任何输出。

**解决方案：**

实现字节级输出解析器，同等对待`\r`和`\n`：

```python
async def _process_buffer(self):
 while True:
 cr_pos = self.buffer.find(b'\r')
 lf_pos = self.buffer.find(b'\n')
 
 if cr_pos == -1 and lf_pos == -1:
 break
 
 if cr_pos != -1 and (lf_pos == -1 or cr_pos < lf_pos):
 line = self.buffer[:cr_pos]
 self.buffer = self.buffer[cr_pos+1:]
 
 if self.buffer and self.buffer[0] == ord('\n'):
 self.buffer = self.buffer[1:]
 else:
 line = self.buffer[:lf_pos]
 self.buffer = self.buffer[lf_pos+1:]
 
 if line:
 text = line.decode('utf-8', errors='replace')
 await self.on_output(text + '\n')
```

**额外优化：**

添加200ms限流，防止CDB更新过于频繁导致的网络开销：

```python
now = time.time()
if now - self.last_send_time >= self.min_send_interval:
 await self.on_output(text + '\n')
 self.last_send_time = now
```

---

### 问题2：长耗时操作导致的"假卡死"问题

**问题描述：**

!analyze -v等命令可能执行5分钟以上，期间可能长时间没有输出，导致用户以为程序卡死。

**解决方案：**

自动心跳机制：

- 当命令进入running阶段后，启动心跳计时器

- 如果连续5秒没有任何输出，自动发送"正在处理中..."的心跳通知

- 只要有任何输出，就重置心跳计时器

**为什么这是最佳方案：**

- 不需要任何输出解析或命令特定逻辑

- 对所有命令都有效

- 实现极其简单

- 从根本上解决了假卡死问题

---

### 问题3：HTTP SSE连接超时问题

**问题描述：**

几乎所有的反向代理和CDN都有默认的HTTP连接超时，通常是30-120秒。

**解决方案：**

1. 正常情况下，输出和心跳通知本身就起到了心跳的作用

2. 如果没有任何输出和心跳，每20秒发送一个空的SSE心跳包(`: ping\n\n`)

3. **服务器配置：**

   - Nginx：设置`proxy_read_timeout 3600s;`(1小时)

   - Cloudflare：升级到Pro版，设置缓存规则绕过MCP端点

---

## 六、实现指南

### 6.1 CDB会话管理

每个会话对应一个独立的CDB进程：

```python
class CdbSession:
 def __init__(self, dump_path):
 self.dump_path = dump_path
 self.process = None
 self.stdout_parser = None
 
 async def start(self):
 cmd = [
 "cdb.exe",
 "-z", self.dump_path,
 "-y", "srv*c:\\symbols*https://msdl.microsoft.com/download/symbols",
 "-c", ".echo Session ready;.echo COMMAND_COMPLETED_MARKER"
 ]

# 命令发送时，附加标记：
# self.stdin.write(f"{command}\n.echo COMMAND_COMPLETED_MARKER\n")
 
 self.process = await asyncio.create_subprocess_exec(
 *cmd,
 stdin=asyncio.subprocess.PIPE,
 stdout=asyncio.subprocess.PIPE,
 stderr=asyncio.subprocess.STDOUT
 )
 
 self.stdout_parser = CdbOutputParser(self.process.stdout, self._on_output)
 asyncio.create_task(self.stdout_parser.run())
 
 async def execute_command(self, command, timeout=600):
 # 实现命令执行逻辑
 pass
 
 async def close(self):
 if self.process:
 try:
 self.process.terminate()
 await self.process.wait()
 except:
 pass
```

---

### 6.2 会话与连接解耦

**重要原则：不要将sessionId与单个SSE连接绑定**

- 允许客户端断开重连后继续使用同一个sessionId

- 即使SSE连接断开，CDB进程也继续运行(可配置超时)

- 重新连接后，继续发送未完成的进度通知和命令结果

---

### 6.3 自动资源清理

- 每个会话设置30分钟无活动超时

- 服务器重启时，优雅关闭所有现有会话

- 定期扫描孤儿进程和临时文件，防止资源泄漏

---

## 七、部署注意事项

### 7.1 服务器配置

- 至少8GB内存，建议16GB以上

- 足够的磁盘空间用于存储dump文件和PDB缓存

- 稳定的网络连接，用于下载PDB文件

---

### 7.2 安全考虑

- 限制同时运行的最大会话数(如10个)

- 设置最大dump文件大小(如4GB)

- 可以考虑添加命令白名单，防止恶意操作

- 使用HTTPS加密传输

---

### 7.3 性能优化

- 永久缓存下载的PDB文件

- 使用本地SSD存储dump文件和PDB缓存

- 配置多个符号服务器，提高下载速度

---

## 八、错误处理设计

| 错误场景 | 处理方式 |
|---------|---------|
| dump文件损坏 | 立即返回明确错误，自动清理文件 |
| PDB下载失败 | 继续分析，但在输出中显示警告 |
| CDB进程崩溃 | 自动重启会话，返回错误信息 |
| 命令执行超时 | 终止命令，返回已执行的部分输出 |
| 会话不存在 | 返回错误，提示用户重新启动会话 |
| 服务器内部错误 | 返回错误ID，记录详细日志，自动清理资源 |
| 超出最大会话数 | 立即返回错误，拒绝创建会话 |
| dump文件超限 | 立即返回错误，拒绝上传 |

---

## 九、最佳实践

1. **使用CDB而不是Windbg**：CDB是命令行版本，输出更稳定，没有GUI干扰

2. **非阻塞IO**：所有IO操作都使用非阻塞模式

3. **统一 marker 检测**：通过 `.echo COMMAND_COMPLETED_MARKER` 作为命令结束判定，不依赖提示符正则

4. **日志记录**：记录所有命令和输出，方便问题排查

5. **结果缓存**：缓存常用命令的执行结果，提高响应速度

---

## 十、总结

本方案经过多轮讨论和优化，最终确定了"零解析、通用阶段、原样转发、自动心跳"的核心设计原则。该方案不仅解决了长耗时操作导致的假卡死问题，还保证了与原生CDB完全一致的输出体验，同时代码实现简单，维护成本极低。

所有决策都有明确的讨论过程和理由，为未来的维护和扩展提供了清晰的指导。
