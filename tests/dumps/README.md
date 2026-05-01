# Dump 测试资产说明

本目录存放仓库内默认使用的 dump 测试样本。

- `DemoCrash1.exe.7088.dmp`：基础功能与集成测试默认样本
- `electron.dmp`：symbol-heavy E2E 默认样本

约定：

- `tests/e2e/config.py` 负责默认路径解析
- `scripts/e2e-deploy-start-run.ps1` 使用同一默认 symbol-heavy 样本
- 如需替换重符号样本，优先通过环境变量 `DUMP_E2E_SYMBOL_HEAVY_DUMP_PATH` 覆盖
