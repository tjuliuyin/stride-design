# SDL Secure Development Agent（基于 Claude Code）

一个基于 Claude Code 构建的安全开发生命周期（SDL）Agent：输入业务需求，自动完成 **SOC2 合规设计 → STRIDE 威胁分析 → SPEC 编写 → 代码实现 → 安全审查**，最终产出合规、安全、可追溯的代码。

## 核心能力

1. **SOC2 合规设计** — 基于 SOC2 Trust Services Criteria（Security/Availability/Processing Integrity/Confidentiality/Privacy）评估需求适用的控制项，输出可落地的合规设计文档（控制项编号 C-xx）。
2. **STRIDE 威胁分析** — 构建数据流图与信任边界，按 STRIDE 六类逐项识别威胁、评级风险，设计具体安全措施（威胁编号 T-xx）。
3. **SPEC 驱动开发** — 将合规控制项与威胁缓解措施转译为可执行的安全需求（SR-xx），与功能需求（FR-xx）一起形成完整开发规格，建立 `C-xx/T-xx → SR-xx → 代码位置 → 测试用例` 的全链路追溯矩阵，再按 SPEC 实现代码。
4. **安全代码审查** — 逐条核对 SR 实现情况并扫描通用安全缺陷，存在 BLOCKER 时强制修复后复审。

## 架构

通过 Claude Code 原生机制实现，无需额外运行时：

| 组件 | 路径 | 说明 |
|---|---|---|
| 工作流总纲 | `CLAUDE.md` | 定义五阶段 SDL 流水线与强制规则 |
| 子代理 | `.claude/agents/` | `soc2-compliance-designer`、`stride-threat-modeler`、`spec-developer`、`security-code-reviewer` |
| 斜杠命令 | `.claude/commands/` | `/secure-dev`、`/soc2-design`、`/stride-analysis`、`/spec-dev`、`/security-review` |
| 知识库 | `docs/knowledge/` | SOC2 TSC 控制项映射、STRIDE 威胁与缓解措施参考 |
| 模板 | `docs/templates/` | 四个阶段的输出文档模板 |
| 产出 | `specs/<feature>/`、`src/<feature>/` | 阶段文档与实现代码 |

```
用户需求 ─→ /secure-dev
  ├─ 阶段1 soc2-compliance-designer ─→ specs/<feature>/01-soc2-compliance.md   (C-xx)
  ├─ 阶段2 stride-threat-modeler    ─→ specs/<feature>/02-stride-threat-model.md (T-xx)
  ├─ 阶段3 spec-developer           ─→ specs/<feature>/03-spec.md              (FR-xx/SR-xx + 追溯矩阵)
  ├─ 阶段4 主代理按 SPEC 实现        ─→ src/<feature>/ (代码注释标注 SR-xx) + 测试
  └─ 阶段5 security-code-reviewer   ─→ specs/<feature>/04-security-review.md   (BLOCKER 必须修复)
```

## 使用方法

前置条件：已安装 [Claude Code](https://code.claude.com/docs)。

```bash
cd stride-design
claude
```

### 端到端生成合规、安全的代码

```
/secure-dev 实现一个用户注册登录模块，支持邮箱注册、登录、找回密码，用户数据含手机号和邮箱
```

Agent 会依次完成五个阶段，最终交付带追溯矩阵的 SPEC、实现代码、测试和安全审查报告。

### 单独执行某个阶段

```
/soc2-design 实现一个订单支付模块，对接第三方支付，存储用户支付记录
/stride-analysis user-auth          # 对已有 feature 做威胁分析
/spec-dev user-auth                 # 基于已有合规+威胁文档写 SPEC 并实现
/security-review user-auth          # 单独审查
```

### 可追溯性

每条安全设计从合规/威胁来源到代码实现全程可追溯：

```
CC6.1（SOC2 准则） → C-03（合规控制项） ─┐
                                        ├→ SR-05（安全需求） → src/user-auth/auth.py:42 → 安全测试 ST-05
T-02（STRIDE 威胁：撞库攻击） ────────────┘
```

## 自定义

- 调整合规口径：编辑 `docs/knowledge/soc2-controls.md`（如叠加 GDPR、等保要求）
- 扩充威胁库：编辑 `docs/knowledge/stride-reference.md`
- 修改文档结构：编辑 `docs/templates/` 下模板
- 收紧/放宽代码安全基线：编辑 `CLAUDE.md` 中"代码实现要求"
