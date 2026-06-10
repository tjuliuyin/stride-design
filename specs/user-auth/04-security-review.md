# 安全审查报告：user-auth（用户注册登录认证核心库）

- 审查对象：src/user-auth/（auth_core 库 11 模块 + tests）
- 依据文档：03-spec.md（SR-01~SR-22 代码实现项）、02-stride-threat-model.md（T-01~T-31）、01-soc2-compliance.md（C-01~C-18）
- 日期：2026-06-10
- 阶段：5/5（安全代码审查）
- 审查方式：逐条核对 SR 实现位置 + 通用缺陷静态扫描 + 测试套件执行验证（35/35 通过）

## 1. SR 覆盖核对（SR-01 ~ SR-22 代码实现项）

| SR 编号 | 判定 | 实现位置（文件:行号） | 说明 |
|---|---|---|---|
| SR-01 口令 scrypt 哈希 | ✅ | password.py:38,60 | scrypt(n=2¹⁴,r=8,p=1,dklen=64)+16B 随机盐，自描述前缀；校验用 compare_digest；ST-01 验证盐独立、无明文 |
| SR-02 口令策略+泄露检查 | ✅ | password.py:93 | 长度 12~128 + 泄露清单 + 禁含邮箱本地部分（≥4 字符判定）；ST-02 三类拒绝 |
| SR-03 退避/软锁定/通知 | ✅ | service.py:184,202,302 | 失败键=邮箱 HMAC（覆盖不存在账号）；5 次退避/10 次锁定 15min+通知；ST-03 含防枚举一致性 |
| SR-04 多维限流 | ✅ | ratelimit.py:21, service.py:125 | 登录/注册/重置/token 校验四维；阈值来自 AuthConfig 不可被请求覆盖；ST-04 逐维打满 |
| SR-05 防枚举统一响应+恒时 | ✅ | service.py:243,309,386, password.py:64 | dummy_verify 拉平耗时；ST-05 实测 200 次耗时中位数差异 < 20% 且响应逐字段一致 |
| SR-06 会话全生命周期 | ✅ | tokens.py:14, service.py:135,159,344 | token_urlsafe(32)、仅存 sha256、空闲 30min+绝对 24h 双判定（service.py:146）、登录全新 token、改密吊销全部；ST-06 通过 |
| SR-07 重置 token 安全 | ✅ | tokens.py:14, service.py:110,418 | 256bit CSPRNG、仅存哈希、30min、一次性、重申失效；ST-07 复用/过期/重申三场景 |
| SR-08 状态机与激活 | ✅ | models.py:37,46, service.py:275,286,614 | 迁移白名单非法即 IllegalStateError；未激活登录返回 INVALID_CREDENTIALS；ST-08 通过 |
| SR-09 参数化查询+输入白名单 | ✅ | storage.py（全表 `?` 占位符）, models.py:51,62,68 | 静态扫描确认存储层零拼接 SQL；ST-09 注入集 11 条 + 超长输入 |
| SR-10 DTO 字段白名单 | ✅ | models.py:94 | from_dict 仅 4 键，role/status/email_verified 等拒绝；ST-10 验证落库默认值 |
| SR-11 对象级授权（防 IDOR） | ✅ | service.py:450,464 | 显式 user_id≠会话用户且非 ADMIN → PERMISSION_DENIED；UUIDv4 主键；ST-11 横向越权拒绝 |
| SR-12 重新认证+换绑双验证 | ✅ | service.py:177,495 | 敏感操作重认证、失败计入锁定；换绑需双 token；ST-12 通过 |
| SR-13 审计+脱敏 | ✅ | audit.py:25,32,46 | 全事件覆盖；sanitize 拦截口令/token/PII；ST-13 全表扫描零泄漏 + message_id 举证 |
| SR-14 盲索引+展示脱敏 | ✅ | masking.py:10,15, storage.py:128, service.py:67 | pepper 空拒绝初始化；检索仅走 email_bidx（无 WHERE email=?）；ST-14 通过 |
| SR-15 注销与数据销毁 | ✅ | service.py:627 | 30 天宽限、到期 PII 置 NULL+状态 PURGED+会话/token 清空；ST-15 验证盲索引查询为空 |
| SR-16 同意记录 | ✅ | service.py:258, storage.py:334, models.py:101 | 空 consent_version 拒绝；ST-16 通过 |
| SR-17 收集最小化 | ✅ | models.py:86, service.py:230 | phone 严格可选；ST-17 校验 users 表无多余 PII 列 |
| SR-18 通道白名单 | ✅ | notify.py:36,50, service.py:84 | 参数键白名单+值含 PII 拒绝；action_url 仅不透明 token；ST-18 通过 |
| SR-19 错误不泄露内部 | ✅ | errors.py:31,75, storage.py:95 | 固定通用文案；sqlite3 异常转译 StorageError；ST-19 验证文案无 sqlite/SQL/路径 |
| SR-20 批量重置+导出 | ✅ | service.py:586,601, 登录拦截 service.py:325 | force_password_reset 标记下口令正确也拒签发；ST-20 通过 |
| SR-21 管理 RBAC 默认拒绝 | ✅ | service.py:172,566 | require_role 先鉴权后执行；None/USER 全拒；ST-21 验证无副作用 |
| SR-22 增长保护 | ✅ | storage.py:213, service.py:159 | 单用户 20 会话上限淘汰最旧；清理任务；ST-22 通过 |

**SR 覆盖率：22/22 满足（✅），0 部分满足，0 未满足。**

> SR-23 ~ SR-40（18 项）为部署层/组织层要求，按 SPEC 约定不在本次代码审查范围；其中 SR-25（MFA）为 SPEC 记录在案的有意延期项，数据模型已预留 `mfa_enabled/mfa_secret_enc` 字段，管理后台上线前强制门禁已在 SPEC 注明。

## 2. 通用缺陷扫描

| 检查项 | 结果 |
|---|---|
| 注入（SQL/命令/路径） | ✅ 全表参数化查询；无 eval/exec/os.system/subprocess（静态扫描确认） |
| 硬编码密钥/口令/token | ✅ 无；pepper 经构造注入且空值拒绝初始化（service.py:67） |
| 弱加密/弱随机 | ✅ 无 md5/sha1 用于凭据；全部随机数走 secrets（CSPRNG），无 random 模块 |
| 时序侧信道 | ✅ 口令校验 compare_digest + 用户不存在路径 dummy_verify；ST-05 实测验证 |
| 认证绕过/越权 | ✅ 对象级授权 + RBAC 默认拒绝；状态机阻断非法迁移 |
| 敏感信息日志泄露 | ✅ audit.sanitize 强制脱敏；ST-13 全表扫描零泄漏 |
| 错误处理泄露内部细节 | ✅ 统一类型化异常 + 固定文案；StorageError 转译 |
| 会话管理 | ✅ 哈希存储、双超时、登录轮换、改密/重置/注销全吊销 |

## 3. 依赖审计

零第三方依赖（仅 Python 3.11 标准库），SCA 攻击面天然消除，SR-34 依赖扫描项在本期自动满足。生产引入第三方实现（HIBP、真实邮件/短信 SDK、argon2）时须按 SR-34 接入 SCA 门禁。

## 4. 发现列表

### MINOR
- **F-01 [MINOR] 会话/token 校验为哈希主键等值查询而非逐字节比较** — 位置 service.py:112,137。`_consume_token` 与 `_session_context` 通过 `hash_token()` 后用 sqlite 主键查找定位记录，未对查找本身用 compare_digest。影响：理论上数据库索引查找耗时与命中位置相关，但比较对象是 256bit 秘密的 SHA-256，且 token 本身高熵不可枚举，时序信息无法转化为可行攻击。建议：保持现状即可；如需极致防御可改为取出候选行后 compare_digest 比较哈希（成本收益不高，记录备查）。
- **F-02 [MINOR] scrypt 参数低于 OWASP argon2id 基线** — 位置 password.py:13。受标准库限制采用 scrypt(n=2¹⁴)，SPEC SR-01 已明确生产推荐迁移 argon2id 并预留存储前缀。影响：拖库后离线破解成本低于 argon2id 基线但仍显著（每次 ~47ms）。建议：按 SPEC 既定计划生产迁移，无需本期处理。

### MAJOR
无。

### BLOCKER
无。

## 5. 结论

- **BLOCKER：0，MAJOR：0，MINOR：2**
- SR 覆盖率：22/22（代码实现项全部满足）
- 测试：35/35 通过（FT-01~FT-13 功能 + ST-01~ST-22 安全，与 SR 一一对应）
- **审查结论：通过（PASS）。** 无 BLOCKER 与 MAJOR；2 项 MINOR 均为 SPEC 已记录的部署期改进方向（argon2id 迁移）或成本收益不高的加固备查项，不阻塞交付。部署上线前须落实 SR-23~SR-40 部署层要求（尤其 TLS/HSTS、KMS pepper、MFA、日志外送、WAF）。
