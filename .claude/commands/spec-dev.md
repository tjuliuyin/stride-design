---
description: 执行 SPEC 编写 + 代码实现（要求已完成 SOC2 合规设计与 STRIDE 威胁分析）
argument-hint: <feature 名>
---

针对特性 `$ARGUMENTS`，执行 SPEC 驱动开发：

1. 检查 `specs/$ARGUMENTS/01-soc2-compliance.md` 与 `specs/$ARGUMENTS/02-stride-threat-model.md` 是否存在；缺失则提示用户先运行 `/soc2-design` 和 `/stride-analysis`，停止执行。
2. 调用 `spec-developer` 子代理编写规格，产出 `specs/$ARGUMENTS/03-spec.md`。
3. 按 SPEC 实现代码到 `src/$ARGUMENTS/`：
   - 严格实现每条 FR-xx 和 SR-xx，安全实现处用注释标注 SR 编号
   - 编写并运行 SPEC 要求的测试，全部通过后回填追溯矩阵的"实现位置"列
4. 调用 `security-code-reviewer` 子代理审查；有 BLOCKER 则修复并复审，直到通过。
5. 向用户汇报 SPEC 路径、代码位置、测试结果与审查结论。
