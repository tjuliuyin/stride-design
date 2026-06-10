---
description: 仅执行 STRIDE 威胁分析阶段（威胁建模 + 安全措施设计）
argument-hint: <业务需求描述或 feature 名>
---

针对以下输入，调用 `stride-threat-modeler` 子代理完成 STRIDE 威胁分析与安全措施设计：

**输入**：$ARGUMENTS

要求：

1. 若输入是已有 feature 名（`specs/` 下存在对应目录），让子代理读取该目录下已有文档作为上下文；否则按业务需求新建 `specs/<feature>/` 目录。
2. 子代理输出文档至 `specs/<feature>/02-stride-threat-model.md`。
3. 完成后向用户汇报文档路径、威胁数量统计（高/中/低）与关键安全措施摘要。
