# SDL Secure Development Agent

本仓库是一个基于 Claude Code 的安全开发生命周期（SDL）Agent。它接收用户的业务需求，依次完成：

1. **SOC2 合规设计** — 基于 SOC2 Trust Services Criteria（安全性、可用性、处理完整性、保密性、隐私性）对业务需求进行合规设计
2. **STRIDE 威胁分析** — 基于 STRIDE 方法（Spoofing / Tampering / Repudiation / Information Disclosure / Denial of Service / Elevation of Privilege）完成威胁建模与安全措施设计
3. **SPEC 驱动开发** — 将合规要求与安全措施汇编为可执行的开发规格（SPEC），再按 SPEC 实现代码
4. **安全代码审查** — 对照 SPEC、威胁模型与合规设计验证产出代码

## 工作流（必须遵守）

处理任何"基于需求生成代码"的请求时，**严格按以下阶段顺序执行，禁止跳过阶段直接写代码**：

```
用户需求
  → 阶段1: soc2-compliance-designer 子代理 → specs/<feature>/01-soc2-compliance.md
  → 阶段2: stride-threat-modeler 子代理   → specs/<feature>/02-stride-threat-model.md
  → 阶段3: spec-developer 子代理（编写SPEC）→ specs/<feature>/03-spec.md
  → 阶段4: 按 SPEC 实现代码               → src/<feature>/...
  → 阶段5: security-code-reviewer 子代理   → specs/<feature>/04-security-review.md
```

阶段规则：

- 每个阶段的输出文档必须落盘到 `specs/<feature>/` 目录（`<feature>` 为需求的短横线命名英文名）。
- 阶段 3 的 SPEC 必须**逐条引用**阶段 1 的合规控制项编号（C-xx）和阶段 2 的威胁编号（T-xx），形成可追溯矩阵；SPEC 中每条安全需求（SR-xx）必须能回溯到至少一个 C-xx 或 T-xx。
- 阶段 4 实现的代码中，安全相关实现处需在注释中标注对应的 SR-xx 编号。
- 阶段 5 审查发现 BLOCKER 级问题时，必须修复后重新审查，直到无 BLOCKER 才算完成。
- 若用户只要求做其中某一阶段（如只做威胁分析），可单独执行该阶段，但仍须读取已有的上游文档（如存在）。

## 目录结构

```
.claude/agents/      子代理定义（soc2-compliance-designer / stride-threat-modeler / spec-developer / security-code-reviewer）
.claude/commands/    斜杠命令（/secure-dev /soc2-design /stride-analysis /spec-dev /security-review）
docs/knowledge/      SOC2 控制项与 STRIDE 威胁/缓解措施知识库
docs/templates/      各阶段输出文档模板
specs/               各需求的阶段性产出文档
src/                 按 SPEC 实现的代码
```

## 知识库与模板

- 子代理执行前必须先读取 `docs/knowledge/` 下对应的知识库文件。
- 各阶段输出必须使用 `docs/templates/` 下对应模板的结构，不得自行发明文档格式。

## 代码实现要求（阶段 4 通用安全基线）

无论 SPEC 是否显式提及，生成的代码必须满足：

- 所有外部输入经过校验（白名单优先），所有输出按上下文编码/转义
- 禁止硬编码密钥、口令、token；统一从环境变量或密钥管理服务读取
- 数据库访问使用参数化查询，禁止字符串拼接 SQL
- 认证、授权检查在服务端强制执行，默认拒绝（deny by default）
- 错误信息不向客户端泄露堆栈、内部路径、SQL 等敏感细节
- 安全相关事件（登录、授权失败、敏感数据访问、配置变更）写入审计日志，日志中不得含明文敏感数据
- 依赖第三方库时选择维护活跃、无已知高危漏洞的版本
