---
description: 仅执行 SOC2 合规设计阶段（基于 SOC2 TSC 对业务需求做合规设计）
argument-hint: <业务需求描述>
---

针对以下业务需求，调用 `soc2-compliance-designer` 子代理完成 SOC2 合规设计：

**业务需求**：$ARGUMENTS

要求：

1. 确定短横线命名的英文特性名 `<feature>`（若 `specs/` 下已有该需求的目录则复用）。
2. 子代理输出文档至 `specs/<feature>/01-soc2-compliance.md`。
3. 完成后向用户汇报文档路径与适用控制项摘要（按五大 TSC 准则分组）。
