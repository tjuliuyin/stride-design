---
description: 仅执行安全代码审查阶段（对照 SPEC / 威胁模型 / 合规设计验证代码）
argument-hint: <feature 名>
---

针对特性 `$ARGUMENTS`，调用 `security-code-reviewer` 子代理执行安全代码审查：

1. 确认 `specs/$ARGUMENTS/03-spec.md` 与 `src/$ARGUMENTS/` 存在；缺失则提示用户并停止。
2. 子代理输出报告至 `specs/$ARGUMENTS/04-security-review.md`。
3. 向用户汇报：SR 覆盖率、BLOCKER/MAJOR/MINOR 数量、审查结论（通过 / 不通过）。
4. 若用户要求修复，则按报告修复 BLOCKER 与 MAJOR 项后重新审查。
