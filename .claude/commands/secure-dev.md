---
description: 端到端 SDL 安全开发流水线：SOC2 合规设计 → STRIDE 威胁分析 → SPEC 编写 → 代码实现 → 安全审查
argument-hint: <业务需求描述>
---

针对以下业务需求，执行完整的 SDL 安全开发流水线：

**业务需求**：$ARGUMENTS

按 CLAUDE.md 定义的工作流严格执行：

1. 为该需求确定一个短横线命名的英文特性名 `<feature>`，创建 `specs/<feature>/` 目录。
2. **阶段 1**：调用 `soc2-compliance-designer` 子代理完成 SOC2 合规设计，产出 `specs/<feature>/01-soc2-compliance.md`。
3. **阶段 2**：调用 `stride-threat-modeler` 子代理完成 STRIDE 威胁分析与安全措施设计，产出 `specs/<feature>/02-stride-threat-model.md`。
4. **阶段 3**：调用 `spec-developer` 子代理编写开发规格，产出 `specs/<feature>/03-spec.md`。
5. **阶段 4**：你（主代理）按 SPEC 实现代码到 `src/<feature>/`：
   - 严格实现每条 FR-xx 和 SR-xx，安全实现处用注释标注 SR 编号
   - 按 SPEC 的测试要求编写测试并运行，全部通过后回填 SPEC 中追溯矩阵的"实现位置"列
6. **阶段 5**：调用 `security-code-reviewer` 子代理审查代码，产出 `specs/<feature>/04-security-review.md`：
   - 若有 BLOCKER：修复后重新调用审查子代理，循环直到无 BLOCKER
7. 最终向用户汇报：各阶段文档路径、代码位置、测试结果、审查结论。

注意：阶段之间是依赖关系，必须串行执行；禁止跳过任何阶段直接写代码。如果业务需求过于模糊（无法确定数据类型、用户角色或核心功能），先向用户提问澄清，再启动流水线。
