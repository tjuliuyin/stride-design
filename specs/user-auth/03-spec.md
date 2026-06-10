# 开发规格（SPEC）：user-auth（用户注册登录模块 —— 认证核心库）

- 上游文档：specs/user-auth/01-soc2-compliance.md（C-01 ~ C-18）、specs/user-auth/02-stride-threat-model.md（T-01 ~ T-31）
- 日期：2026-06-10
- 阶段：3/5（SPEC 编写）

## 1. 概述与目标

实现一个 **Python 3.11 认证核心库**（service 层 + 存储层），提供邮箱注册、登录、找回密码、账号资料管理与注销的完整业务逻辑与安全控制。本期**不含** HTTP 框架、真实邮件/短信发送（以接口抽象 + 假实现注入）与管理后台；库以可注入依赖（时钟、发送器、泄露口令检查器、配置）的形式构建，保证全部安全行为可被 unittest 自动化验证。环境约束：**仅使用 Python 标准库**（hashlib.scrypt / secrets / sqlite3 / hmac / unittest 等）。凡属部署层/组织层的安全需求仍列为 SR 并给出部署验收标准，在追溯矩阵中标注"部署层要求，不在代码实现范围"。

## 2. 功能需求（FR）

### FR-01 邮箱注册
- **用户故事**：作为访客，我希望用邮箱 + 口令注册账号（手机号可选），以便获得系统身份。
- **验收标准**：
  - Given 合法邮箱与符合策略的口令及已勾选的同意版本号 When 调用 `register(RegisterRequest)` Then 创建状态为 `PENDING_VERIFICATION` 的账号，持久化同意记录，并通过 EmailSender 发出含验证 token 的激活邮件，返回不含敏感信息的 `RegisterResult`。
  - Given 该邮箱已注册 When 再次注册 Then 接口返回与新注册完全一致的成功结果，且向该邮箱发送"您已有账号"模板邮件（不在返回值中暴露"已注册"）。
  - Given 缺少同意版本号 When 注册 Then 抛出 `ValidationError(CONSENT_REQUIRED)`。

### FR-02 邮箱验证激活
- **用户故事**：作为新注册用户，我希望点击邮件中的验证链接完成激活，以便正常登录。
- **验收标准**：
  - Given 有效且未使用的验证 token When 调用 `verify_email(token)` Then 账号状态 `PENDING_VERIFICATION → ACTIVE`，记录 `email_verified_at`，token 标记已用。
  - Given token 已使用 / 已过期（>24h）/ 不存在 When 验证 Then 抛出 `AuthError(INVALID_TOKEN)`，三种情况返回完全一致。

### FR-03 登录
- **用户故事**：作为已激活用户，我希望用邮箱 + 口令登录，以便获得会话凭据。
- **验收标准**：
  - Given 正确邮箱与口令、账号 `ACTIVE` When 调用 `login(email, password, client=ClientInfo(ip, user_agent))` Then 返回新签发的会话 token（明文仅此一次返回），失败计数清零，写入登录成功审计事件。
  - Given 口令错误或邮箱未注册 When 登录 Then 抛出 `AuthError(INVALID_CREDENTIALS)`，两种情况的异常类型、错误码、消息完全一致。
  - Given 账号 `PENDING_VERIFICATION` / `BANNED` / 处于注销宽限期 When 登录 Then 按 SR-08 状态机定义的结果处理（未激活与口令错误同样返回 `INVALID_CREDENTIALS`，防枚举）。

### FR-04 登出
- **用户故事**：作为已登录用户，我希望登出后会话立即失效。
- **验收标准**：Given 有效会话 When `logout(session_token)` Then 服务端会话记录即时删除/失效，再次校验该 token 抛出 `AuthError(NOT_AUTHENTICATED)`。

### FR-05 会话校验
- **用户故事**：作为业务模块（库的调用方），我希望校验会话 token 并获得用户身份，以便实施后续授权。
- **验收标准**：
  - Given 有效且未超时的 token When `validate_session(token)` Then 返回 `SessionContext(user_id, role, issued_at)` 并刷新 `last_seen_at`。
  - Given 空闲超 30 分钟或签发超 24 小时的 token When 校验 Then 抛出 `AuthError(NOT_AUTHENTICATED)` 且会话被清除。

### FR-06 找回密码（申请重置）
- **用户故事**：作为忘记口令的用户，我希望通过邮箱收到重置链接。
- **验收标准**：
  - Given 已注册邮箱 When `request_password_reset(email, client)` Then 生成重置 token，经 EmailSender 发出重置邮件，返回统一成功结果。
  - Given 未注册邮箱 When 申请 Then 返回与上一致的成功结果且不发送重置邮件（防枚举），写审计事件。

### FR-07 重置口令（消费 token）
- **用户故事**：作为申请了重置的用户，我希望凭重置 token 设置新口令。
- **验收标准**：
  - Given 有效 token 与合规新口令 When `reset_password(token, new_password)` Then 更新口令哈希、token 标记已用、该用户全部会话被吊销、发送"口令已重置"通知邮件、写审计。
  - Given token 已用 / 过期 / 不存在 When 重置 Then 抛出 `AuthError(INVALID_TOKEN)`（统一响应）。

### FR-08 修改口令（已登录）
- **用户故事**：作为已登录用户，我希望提供当前口令后修改为新口令。
- **验收标准**：Given 有效会话 + 正确当前口令 + 合规新口令 When `change_password(session_token, old, new)` Then 更新哈希、吊销该用户全部旧会话并返回新签发会话、发送通知邮件、写审计；当前口令错误则抛出 `AuthError(REAUTH_FAILED)` 且计入失败计数。

### FR-09 查看本人资料
- **用户故事**：作为已登录用户，我希望查看本人邮箱与手机号。
- **验收标准**：Given 有效会话 When `get_profile(session_token)` Then 仅返回会话所属用户的资料；`masked=True`（默认）时邮箱/手机号脱敏（`l***@gmail.com` / `+86138****1234`），`masked=False` 返回完整值并写"完整 PII 查看"审计事件。

### FR-10 更新手机号 / 换绑邮箱
- **用户故事**：作为已登录用户，我希望修改手机号或换绑邮箱。
- **验收标准**：
  - Given 有效会话 + 重新认证（当前口令）When `update_phone(session_token, password, new_phone)` Then E.164 校验通过后更新，写审计。
  - Given 有效会话 + 重新认证 When `request_email_change(session_token, password, new_email)` Then 向旧邮箱发确认 token、向新邮箱发验证 token；When `confirm_email_change(old_token, new_token)` 双 token 均有效 Then 换绑生效并通知双方邮箱，写审计。

### FR-11 账号注销（含宽限期撤销）
- **用户故事**：作为用户，我希望注销账号并在宽限期内可反悔。
- **验收标准**：
  - Given 有效会话 + 重新认证 When `request_deletion(session_token, password)` Then 状态 → `PENDING_DELETION`，`purge_after = now + 30 天`，吊销全部会话，发送告知邮件。
  - Given 宽限期内 When 用户登录并调用 `cancel_deletion(session_token)` Then 状态恢复 `ACTIVE`。
  - Given 超过 `purge_after` When 运行 `purge_deleted_accounts()` Then 执行 SR-15 定义的硬删除。

### FR-12 库级管理功能（批量强制重置 / 封禁 / 导出）
- **用户故事**：作为安全响应人员（经上层管理系统调用本库），我希望对指定用户集合吊销会话并强制重置口令、封禁/解封账号、按时间范围导出受影响用户，以支撑泄露响应。
- **验收标准**：Given `ActorContext(role=ADMIN)` When 调用 `bulk_force_reset(actor, user_ids)` / `ban_user(actor, user_id)` / `unban_user(actor, user_id)` / `export_affected_users(actor, start, end)` Then 操作生效并逐条写管理审计事件（含 actor id）；Given 非 ADMIN actor Then 一律抛出 `AuthError(PERMISSION_DENIED)`。

### FR-13 后台维护任务
- **用户故事**：作为运维（通过定时任务调用本库），我希望自动清理过期数据。
- **验收标准**：`purge_unverified_accounts()` 删除创建超 72h 仍未激活的账号；`purge_expired_sessions()` 删除超时会话；`purge_expired_tokens()` 删除过期 token；各任务返回清理计数并写审计。

## 3. 安全需求（SR）

> 每条 SR 标注来源（C-xx / T-xx）。SR-01 ~ SR-22 为**本库代码实现**；SR-23 ~ SR-40 为**部署层/组织层要求**（不在代码实现范围，但给出部署验收标准；其中 SR-25 为有意延期项）。

### 3.1 代码实现的 SR（SR-01 ~ SR-22）

### SR-01 口令 scrypt 哈希存储 [来源: C-01.1, T-17]
- **要求**：口令使用 `hashlib.scrypt(password, salt, n=2**14, r=8, p=1, dklen=64)` 哈希，盐为每用户独立的 `secrets.token_bytes(16)`；存储格式 `scrypt$n=16384,r=8,p=1$<salt_b64>$<hash_b64>`（参数自描述，支持未来升级迁移）。禁止 MD5/SHA 直接哈希、可逆加密、明文。校验使用 `hmac.compare_digest`。**生产环境注**：标准库限制下采用 scrypt（OWASP 认可）；生产部署推荐迁移 argon2id（memory 19 MiB / iterations 2 / parallelism 1），存储格式已预留算法前缀支持平滑迁移。
- **验收标准**：Given 任意注册 When 读取数据库 `password_hash` 字段 Then 值以 `scrypt$n=16384,r=8,p=1$` 开头且不含口令明文；同一口令两次注册产生不同哈希（盐独立）；正确口令校验通过、错误口令拒绝。

### SR-02 口令策略与泄露口令检查 [来源: C-02, T-01]
- **要求**：(1) 口令长度 12 ≤ len ≤ 128，不强制复杂字符组合、不强制定期更换；(2) 注册/重置/修改口令时经 `BreachChecker` 接口校验，命中泄露库则拒绝（库内置 `LocalListBreachChecker`，默认加载内置常见泄露口令清单，含 `password123456`；生产可注入 HIBP k-anonymity 实现，见 SR-36 部署注记）；(3) 口令（忽略大小写）不得包含本人邮箱本地部分（@ 前内容）。
- **验收标准**：Given 11 字符口令 / `password123456` / 邮箱 `liuyin0214@x.com` 配口令 `Liuyin0214aaaa` When 注册 Then 分别抛出 `WEAK_PASSWORD` / `BREACHED_PASSWORD` / `WEAK_PASSWORD`；12~128 字符且未命中的口令通过。

### SR-03 登录失败退避、账号软锁定与锁定通知 [来源: C-04.1, T-01, T-11]
- **要求**：失败计数以**提交的规范化邮箱字符串**为键（账号是否存在均计数，防枚举）：连续失败第 5 次起设置 `next_allowed_at = now + min(2^(n-4), 60) 秒`，期间登录直接拒绝（不执行口令校验）；连续失败 ≥ 10 次锁定 15 分钟（`lockout_until`），锁定时向该账号（若存在）发送锁定通知邮件并写审计事件 `ACCOUNT_LOCKED`。登录成功清零计数。锁定为软锁定：锁定期间"找回密码"通道仍可用（T-11 兜底）。
- **验收标准**：Given 同一邮箱连续 5 次失败 When 立即第 6 次登录（即使口令正确）Then 拒绝并返回 `retry_after`；Given 连续 10 次失败 Then 后续 15 分钟内登录均拒绝、FakeEmailSender 收到 1 封锁定通知、审计含 `ACCOUNT_LOCKED`；Given 锁定中 When 申请找回密码 Then 正常受理。

### SR-04 多维限流 [来源: C-04.2/3, T-01, T-03, T-10]
- **要求**：库内实现持久化滑动窗口限流器（sqlite 表），默认阈值（`AuthConfig` 可配置，但配置项不可被请求数据覆盖）：登录同 IP ≤ 10 次/分钟；注册同 IP ≤ 10 次/分钟；找回密码同账号 ≤ 1 次/分钟且 ≤ 5 次/天、同 IP ≤ 10 次/分钟；重置/验证 token 校验同 IP ≤ 10 次/分钟（防在线枚举，T-03.3）。超限抛出 `AuthError(RATE_LIMITED, retry_after=...)`，写审计事件 `RATE_LIMITED`。
- **验收标准**：Given 同 IP 1 分钟内第 11 次登录 When 调用 Then 抛 `RATE_LIMITED`；Given 同账号 1 天内第 6 次找回密码 Then 抛 `RATE_LIMITED`；Given 同 IP 第 11 次 token 校验 Then 抛 `RATE_LIMITED`；窗口过后恢复。

### SR-05 防枚举统一响应与恒时校验 [来源: C-04.4, T-07]
- **要求**：(1) 登录失败（用户不存在 / 口令错误 / 账号未激活）返回完全相同的 `INVALID_CREDENTIALS`；(2) 用户不存在时仍执行一次等参数 dummy scrypt 计算（固定盐）拉平耗时；(3) 找回密码无论邮箱是否注册返回统一成功；(4) 重复注册返回与新注册一致的成功结果并改发"您已有账号"邮件；(5) token 校验失败的三种原因（不存在/过期/已用）统一返回 `INVALID_TOKEN`。
- **验收标准**：Given 存在与不存在的邮箱各登录失败一次 When 比较异常对象的错误码与 message Then 完全一致；When 各执行 200 次比较耗时分布 Then 中位数差异 < 20%（dummy 哈希生效）；找回密码两种情况返回值逐字段相等。

### SR-06 会话令牌生成、哈希存储、超时、轮换与吊销 [来源: C-05, T-02, T-09]
- **要求**：(1) 会话 token 由 `secrets.token_urlsafe(32)` 生成（256 bit）；(2) 服务端仅存 `sha256(token)` 十六进制，校验用 `hmac.compare_digest`（T-09：DB 泄露不致会话被冒用）；(3) 空闲超时 30 分钟（`last_seen_at`）、绝对生命周期 24 小时（`created_at`），均可配置但默认不放宽；(4) 每次登录签发全新 token（库内无登录前匿名会话，等效消除会话固定），另提供 `rotate_session(token)` 供调用方在权限提升时轮换；(5) `logout` 即时失效；修改/重置口令、注销、封禁、`bulk_force_reset` 均吊销该用户全部会话；(6) 提供 `revoke_all_sessions(user_id)` 与 `list_sessions(session_token)`。
- **验收标准**：Given 登录两次 Then 两 token 不同且 DB 中无 token 明文（仅 64 位十六进制哈希）；Given 注入时钟前进 31 分钟 When 校验 Then `NOT_AUTHENTICATED`；前进 24 小时零 1 秒同理；Given 改密后 When 用旧 token 校验 Then `NOT_AUTHENTICATED`；`rotate_session` 后旧 token 立即失效。

### SR-07 密码重置 token 安全 [来源: C-01.2, T-03, T-09]
- **要求**：(1) `secrets.token_urlsafe(32)` 生成（256 bit ≥ 128 bit 要求）；(2) DB 仅存 SHA-256 哈希；(3) 有效期 30 分钟；(4) 一次性：使用后立即标记 `used_at`；(5) 同一用户重新申请时，先前未使用的重置 token 全部立即失效；(6) 重置完成吊销全部会话并发通知邮件（SR-06.5）；(7) token 校验纳入 SR-04 限流。
- **验收标准**：Given 已使用的 token When 二次使用 Then `INVALID_TOKEN`；Given 时钟前进 31 分钟 Then `INVALID_TOKEN`；Given 重新申请后 When 使用旧 token Then `INVALID_TOKEN`；DB 中 token 字段为 SHA-256 哈希且与明文不同。

### SR-08 邮箱验证激活与账号状态机 [来源: C-06, T-12]
- **要求**：(1) 注册后状态 `PENDING_VERIFICATION`，必须消费验证 token（256 bit CSPRNG、哈希存储、24h 有效、一次性）才迁移到 `ACTIVE`；(2) 状态机：`PENDING_VERIFICATION → ACTIVE → (LOCKED 临时) / BANNED / PENDING_DELETION → PURGED`，非法迁移抛 `IllegalStateError`；(3) 每次状态变更写审计（who/when/old→new）；(4) `purge_unverified_accounts()` 清理超 72h 未激活账号；(5) 未激活账号登录返回 `INVALID_CREDENTIALS`（防枚举）但找回密码不发送重置邮件（改发激活提醒）。
- **验收标准**：Given 未激活账号 When 登录（正确口令）Then `INVALID_CREDENTIALS`；Given 时钟前进 73h When 清理任务 Then 该账号行被删除；Given `BANNED` 账号直接置 `ACTIVE` 以外的非法迁移调用 Then `IllegalStateError`；每次迁移在审计表有记录。

### SR-09 参数化查询与输入白名单校验 [来源: T-04, C-16.2]
- **要求**：(1) 全部 sqlite3 访问使用 `?` 占位符参数化查询，存储层代码中禁止任何 f-string/`%`/`+` 拼接 SQL 值（表名/列名为代码常量除外）；(2) 输入校验：邮箱经正则 + 长度 ≤ 254 校验并小写规范化；手机号匹配 E.164（`^\+[1-9]\d{6,14}$`）；所有字符串入参设长度上限（口令 ≤ 128、user_agent ≤ 512、ip ≤ 45）；不合法即抛 `ValidationError`，不进入存储层。
- **验收标准**：Given 邮箱字段传入 `' OR 1=1 --` / `"; DROP TABLE users;--` When 注册或登录 Then 抛 `ValidationError` 或正常按"无此用户"处理，且 users 表完好；代码审查（阶段 4）确认存储层零拼接 SQL；超长输入（255 字符邮箱、129 字符口令）被拒。

### SR-10 DTO 字段白名单绑定 [来源: T-12, C-16.2, C-07.2]
- **要求**：(1) `RegisterRequest.from_dict()` 仅接受 `email / password / phone / consent_version` 四个键，出现任何未知键（含 `role`、`status`、`email_verified`、`is_admin` 等）抛 `ValidationError(UNEXPECTED_FIELD)` 并写审计告警事件；(2) 资料更新接口同理仅接受声明字段；(3) `role`、`status`、`email_verified_at`、`lockout_until` 等字段只能由服务端内部逻辑或带 ADMIN actor 的管理方法写入，不存在任何从用户输入直达这些列的代码路径。
- **验收标准**：Given dict 含 `{"role": "admin", "email_verified": true}` When `RegisterRequest.from_dict` Then 抛 `ValidationError`；Given 通过合法注册创建的账号 Then 落库 `role='user'`、`status='PENDING_VERIFICATION'`（默认值）。

### SR-11 对象级授权（防 IDOR） [来源: T-13, C-07.1/2]
- **要求**：所有读写用户资料的方法强制从 `validate_session()` 返回的会话上下文获取 `user_id`；若调用方显式传入目标 `user_id` 且与会话用户不一致，非 ADMIN 一律抛 `AuthError(PERMISSION_DENIED)`（默认拒绝）。用户主键使用 UUIDv4（`uuid.uuid4()`），不可遍历。
- **验收标准**：Given 用户 A 的有效会话 When `get_profile(token_A, user_id=B_id)` / `update_phone(... user_id=B_id ...)` Then `PERMISSION_DENIED`；Given ADMIN actor Then 允许并写管理审计；新建用户 id 符合 UUIDv4 格式。

### SR-12 敏感操作重新认证与换绑双向验证 [来源: C-17.2/3, T-13]
- **要求**：换绑邮箱、修改手机号、修改口令、注销账号必须提供当前口令重新认证，口令错误抛 `REAUTH_FAILED` 并计入 SR-03 失败计数；换绑邮箱需旧邮箱确认 token + 新邮箱验证 token 双向验证（各 24h 有效、一次性、哈希存储）均通过方可生效，生效后通知新旧双邮箱。
- **验收标准**：Given 有效会话但口令错误 When 注销/换绑/改手机号 Then `REAUTH_FAILED` 且未发生变更；Given 仅新邮箱 token 验证（旧邮箱 token 未确认）When `confirm_email_change` Then 不生效；双 token 均通过后 `email` 与盲索引同步更新、FakeEmailSender 收到新旧邮箱各一封通知。

### SR-13 结构化审计日志与日志脱敏 [来源: C-11.1/3, C-01.3, T-06, T-22]
- **要求**：(1) 审计事件覆盖：注册、登录成功/失败、登出、锁定/解锁、口令修改/重置申请/重置完成、邮箱验证、换绑、注销申请/撤销/清除、限流触发、管理操作（封禁/解封/批量重置/导出/完整 PII 查看）、邮件发送（含 FakeSender 返回的 message_id，T-22 举证）；(2) 字段：`event_id, event_type, ts（UTC ISO-8601，注入时钟）, user_id（UUID）, actor_id, ip, user_agent, result, detail(JSON)`；(3) 脱敏强制：审计写入口统一经 `sanitize()` —— 任何值中不得出现口令明文、token 明文（≥ 32 字符的 base64url 串告警拦截）、完整邮箱/手机号（强制 `l***@gmail.com` / `+86138****1234` 格式）；(4) 审计写入失败不阻塞主流程但产生降级标记。
- **验收标准**：Given 执行 FR-01~FR-12 全部操作 When 检查审计表 Then 每类事件至少一条且字段完备；Given 全表扫描审计 detail Then 不含任何注册口令明文、任何已签发 token 明文、任何完整邮箱/手机号；Given 故意向审计写入含 token 的 detail Then 被 `sanitize()` 替换为 `[REDACTED]`。

### SR-14 PII 盲索引与展示脱敏 [来源: C-09.2/4, T-17, T-29]
- **要求**：(1) 邮箱等值检索一律经盲索引列 `email_bidx = HMAC-SHA256(server_pepper, normalized_email)`（pepper 由配置注入，禁止硬编码默认值用于生产——库在 pepper 为空时拒绝初始化）；(2) 提供 `mask_email()` / `mask_phone()` 纯函数，`get_profile` 默认脱敏，完整值查看写审计（FR-09）；(3) PII 列（email、phone）的静态加密由部署层承接（SR-26），代码层已通过盲索引解耦检索与存储形态，部署层切换密文存储不影响查询路径。
- **验收标准**：Given pepper 未配置 When 初始化 `AuthService` Then 抛 `ConfigError`；Given 按邮箱查询 When 检查存储层 SQL Then WHERE 条件仅使用 `email_bidx`；`mask_email("liuyin0214@gmail.com") == "l***@gmail.com"`、`mask_phone("+8613812341234") == "+86138****1234"`。

### SR-15 账号注销与数据销毁 [来源: C-10.1/2/4, C-17.4, T-17]
- **要求**：(1) 注销进入 30 天宽限期（可撤销），到期 `purge_deleted_accounts()` 执行硬删除：users 行的 `email / email_bidx / phone / password_hash` 置 NULL 并将状态置 `PURGED`（保留 UUID 行壳以维持审计引用完整），删除该用户全部会话与 token 行；(2) 审计日志仅含 UUID 与脱敏值，PII 映射行清除后 UUID 不可逆向关联到自然人（满足假名化）；(3) 未激活账号 72h 清理（SR-08.4）为整行删除。
- **验收标准**：Given 注销满 30 天 When 运行清除任务 Then 该用户 email/phone/password_hash/email_bidx 均为 NULL、sessions 与 tokens 表无该用户记录、按原邮箱盲索引查询返回空；审计历史中该用户仅以 UUID + 脱敏邮箱出现；宽限期内 `cancel_deletion` 后数据完整保留。

### SR-16 同意记录持久化 [来源: C-15.2]
- **要求**：注册必须携带 `consent_version`（非空字符串），持久化 `consent_records(user_id, consent_version, consented_at, ip)`；不可默认填充。撤回与政策更新重提示属 UI/上层范围（SR-36），库提供 `get_consent(user_id)` 查询。
- **验收标准**：Given `consent_version=None` 或空串 When 注册 Then `ValidationError(CONSENT_REQUIRED)`；注册成功后 consent_records 存在对应记录且版本号、时间戳正确。

### SR-17 收集最小化 [来源: C-16.1, T-12]
- **要求**：注册必填项仅 `email + password + consent_version`；`phone` 严格可选（None 合法）；数据模型不含与认证无关字段（生日、地址等）；schema 约束由 SR-10 白名单强制。
- **验收标准**：Given 不含 phone 的注册请求 When 注册 Then 成功且 `phone` 为 NULL；数据模型评审确认无额外 PII 字段。

### SR-18 通道接口抽象与传参白名单 [来源: C-14.1/4, T-23, T-21, T-09]
- **要求**：(1) 定义 `EmailSender.send(to_email, template_id, params) -> SendResult(message_id)` 与 `SmsSender.send(to_phone, template_id, params)` 抽象基类，本期仅提供 `FakeEmailSender / FakeSmsSender`（记录调用供测试断言）；(2) `params` 白名单：仅允许 `token`、`action_url`（由配置 `base_url` + 不透明 token 拼装）、`expires_minutes`、`retry_after` 等非 PII 键，出现邮箱/手机号/用户 ID 之外键值含 PII 时由发送网关层校验拒绝（`SenderParamError`）；(3) 链接 URL 仅含不透明 token，无邮箱等明文参数；(4) `SendResult.message_id` 写入审计（SR-13）。
- **验收标准**：Given 任意触发邮件的流程 When 检查 FakeEmailSender 捕获的 params Then 仅含白名单键且 `action_url` 中无 `@`、无手机号；Given params 中注入 `{"user_email": ...}` When 经发送网关 Then 抛 `SenderParamError`。

### SR-19 统一错误处理不泄露内部细节 [来源: T-08]
- **要求**：库对外仅抛出 `errors.py` 中定义的类型化异常（`AuthError(code)` / `ValidationError(code)` / `ConfigError` 等），异常 message 为固定通用文案，不含 SQL 语句、文件路径、堆栈片段、内部状态；sqlite3 等内部异常在存储层捕获并转译为 `StorageError`（细节仅写服务端审计/日志，经 SR-13 脱敏）。
- **验收标准**：Given 人为制造存储故障（注入损坏的连接）When 调用任意接口 Then 抛 `StorageError` 且 `str(e)` 不含 "sqlite"、SQL 关键字、绝对路径；全部公开异常类型有错误码枚举。

### SR-20 批量吊销、强制重置与受影响用户导出 [来源: C-18.2/3, T-17]
- **要求**：(1) `bulk_force_reset(actor, user_ids)`：吊销目标集合全部会话并置 `force_password_reset=1`，该标记下登录时口令校验通过也不签发会话，返回 `AuthError(PASSWORD_RESET_REQUIRED)`，仅可经找回密码流程重置后恢复；(2) `export_affected_users(actor, start_ts, end_ts)` 基于审计日志返回该时间窗内发生认证事件的 user_id 列表（去重）；(3) 二者仅限 ADMIN actor（SR-21），全程审计。
- **验收标准**：Given 强制重置标记的用户 When 用正确口令登录 Then `PASSWORD_RESET_REQUIRED` 且无新会话；When 完成重置流程后登录 Then 恢复正常；导出结果与窗口内审计事件的用户集合一致。

### SR-21 管理方法 RBAC 默认拒绝 [来源: T-31, T-28, C-07.1/2, C-06.4]
- **要求**：全部管理类方法（封禁/解封/批量重置/导出/跨用户读取）入口统一经 `require_role(actor, Role.ADMIN)` 守卫：actor 为 None、role 非 ADMIN、或 actor 会话无效时一律 `PERMISSION_DENIED`（默认拒绝，先鉴权后执行）；每次管理操作审计记录含 `actor_id`（个人化账号，T-28）、目标用户、操作、结果。本期不实现管理后台，该守卫为未来 P3 的强制接入点。
- **验收标准**：Given role=user 的 actor / None When 调用全部 4 个管理方法 Then 均 `PERMISSION_DENIED` 且目标数据无变化；Given ADMIN actor Then 成功且审计含 actor_id 与目标。

### SR-22 会话与数据增长保护 [来源: T-18, C-05.2]
- **要求**：(1) 会话行带 `expires_at`，`purge_expired_sessions()` 可清理；(2) 单用户活跃会话上限 20，超限时淘汰最旧会话；(3) 限流表按窗口过期自动清理；(4) sqlite 连接设置 `busy_timeout`（5s），单请求查询不持有长事务。
- **验收标准**：Given 同一用户登录 21 次 When 检查会话表 Then 该用户恰 20 行且最早一次的 token 已失效；过期会话/限流行被清理任务删除。

### 3.2 部署层 / 组织层 SR（SR-23 ~ SR-40，不在代码实现范围）

> 下列 SR 必须在部署/集成阶段落实，追溯矩阵标注"部署层要求"。每条给出部署验收标准。

### SR-23 传输加密（TLS/HSTS） [来源: C-08, T-05, T-21]
- **要求**：上层 HTTP 服务全站强制 TLS 1.2+（推荐 1.3），HTTP 301 → HTTPS，HSTS `max-age ≥ 31536000; includeSubDomains`（申请 preload）；禁用 TLS 1.0/1.1 与弱套件；应用 ↔ 数据库/邮件/短信网关链路 TLS（SMTP 启用 STARTTLS/implicit TLS 且校验证书、禁止明文回退）。
- **部署验收**：testssl.sh / SSL Labs 评级 ≥ A；HTTP 访问返回 301 且响应含 HSTS 头；抓包确认出站 SMTP/API 链路加密。

### SR-24 会话 Cookie 属性 [来源: C-05.1, T-02]
- **要求**：集成层将本库返回的会话 token 写入 Cookie 时必须设置 `HttpOnly; Secure; SameSite=Lax`（或 Strict），禁止放入 URL 或 localStorage。
- **部署验收**：浏览器/集成测试断言 Set-Cookie 三属性齐备；扫描确认无 URL 传递会话 token。

### SR-25 多因素认证（TOTP）——本期有意延期 [来源: C-03, T-01, T-26]
- **要求**：TOTP（RFC 6238）第二因素、恢复码、异常登录邮箱二次确认本期**不实现**。**延期理由**：本期为无 HTTP 面的核心库且管理后台不在范围，MFA 的密钥加密存储依赖 KMS（标准库不可用 AES）；数据模型已预留 `mfa_enabled / mfa_secret_enc` 字段。**强制门禁**：管理后台（P3）上线前必须完成 MFA 并对管理员强制启用，否则不得开放管理面（T-26）。
- **部署验收**：下期迭代实现后，未启用 MFA 的管理员登录管理面被拒；本期发布说明中明确记录该延期与门禁。

### SR-26 静态加密与 KMS 密钥管理 [来源: C-09.1/3, T-14, T-17]
- **要求**：生产数据库与备份启用 AES-256 静态加密（或 SQLCipher/云盘加密）；email/phone 列切换字段级加密（检索经 SR-14 盲索引不受影响）；盲索引 pepper、数据库凭据存于 KMS/密管系统并支持 ≤ 1 年轮换；CI 接入 secret 扫描门禁阻断硬编码。
- **部署验收**：存储介质抽查为密文；KMS 密钥策略与轮换配置检查通过；secret 扫描报告零硬编码凭据。

### SR-27 数据库账号最小权限与网络隔离 [来源: C-07.3, T-15, T-19, T-14]
- **要求**：生产替换 sqlite 为服务化数据库时：应用账号仅业务表 DML（禁 DDL/FILE/系统库）；用户面与管理面使用不同账号；数据库仅应用子网可达，禁止公网；DBA 直连走堡垒机留痕；非应用路径的关键字段（口令哈希/状态/MFA）变更触发告警。
- **部署验收**：以应用账号执行 DDL/FILE 被拒；非应用网段连接被拒；模拟直改口令哈希触发告警。

### SR-28 审计日志 append-only 外送与保留 [来源: C-11.2, T-16, T-06]
- **要求**：本库审计表为缓冲，生产须实时外送独立日志系统（append-only/WORM），应用与运维账号无删改权限，IAM 与业务系统隔离，保留 ≥ 1 年；主机 NTP 同步。
- **部署验收**：以应用账号删改外送日志失败；外送链路中断告警生效；时钟偏移监控 < 1s。

### SR-29 WAF / CAPTCHA / 抗 DDoS [来源: C-04.2, T-10, T-18]
- **要求**：入口部署 WAF 与抗 DDoS；限流超限（本库 `RATE_LIMITED` 信号）触发 CAPTCHA 挑战；请求体大小限制 ≤ 16 KB、服务端超时；口令哈希计算工作池并发上限（信号量），防 scrypt 算力耗尽。
- **部署验收**：压测下正常用户可用、洪泛被 429+CAPTCHA 拦截；scrypt 并发洪泛下服务保持响应。

### SR-30 重置页 token 防泄露 [来源: T-09]
- **要求**：前端重置/验证落地页设置 `Referrer-Policy: no-referrer` 且不加载第三方资源；落地后立即以 token 换取一次性服务端状态并 `history.replaceState` 重写 URL；网关访问日志过滤 token 查询参数。
- **部署验收**：抓包确认无 Referer 外泄；访问日志扫描无完整 token；落地后地址栏无 token。

### SR-31 发件域 SPF/DKIM/DMARC [来源: T-20, C-14]
- **要求**：发件域配置 SPF + DKIM + DMARC（p=reject）并监控聚合报告；邮件模板含固定品牌要素与"我们不会索取口令"提示，链接仅指向官方域名。
- **部署验收**：dig + 第三方工具校验三记录齐备；伪造发件测试被主流邮箱拒收。

### SR-32 通道 API 凭据管控 [来源: C-14.2, T-25, C-09.3]
- **要求**：真实邮件/短信服务商接入时：API key 仅发送权限、按环境隔离、存于 KMS、支持 ≤ 1 小时内轮换；服务商侧配置发送 IP 白名单；发送量异常告警。
- **部署验收**：用发送 key 调用管理类 API 被拒；非白名单 IP 调用被拒；轮换演练 ≤ 1 小时。

### SR-33 发送异步化与通道可用性 [来源: T-24, C-11.4, C-13]
- **要求**：真实发送实现须异步队列 + 指数退避重试；发送失败率与配额水位监控告警；邮件通道支持配置化备用服务商切换（变更走 SR-35 流程）。本库的 Sender 抽象已为此预留注入点。
- **部署验收**：注入服务商 5xx 验证重试与告警；备用通道切换演练通过。

### SR-34 CI 安全门禁与渗透测试 [来源: C-12, T-04, T-08, T-14]
- **要求**：CI 集成 SAST（含"禁止拼接 SQL""禁止 ORM 直绑"规则）、SCA（lockfile 锁定，本期无第三方依赖天然满足）、secret 扫描；高危（CVSS ≥ 7）阻断合并；上线前 DAST/渗透测试覆盖 OWASP ASVS V2/V3/V4；高危修复 ≤ 7 天、中危 ≤ 30 天。
- **部署验收**：CI 门禁配置审查；渗透测试报告零未闭环高危；调试端点扫描 404。

### SR-35 变更管理与配置漂移检测 [来源: C-13, T-27]
- **要求**：所有变更走 PR + 非作者审查 + CI 绿灯；认证核心逻辑（password.py / tokens.py / service.py 重置流程）变更需安全角色额外审批（CODEOWNERS）；`AuthConfig` 生产取值由配置中心管理、禁止生产手改；实际生效配置与仓库基线定期比对，漂移告警；紧急变更 48h 内补审。
- **部署验收**：分支保护与 CODEOWNERS 配置检查；人为制造配置漂移触发告警；变更记录抽样可追溯。

### SR-36 供应商合规、隐私政策与泄露口令服务 [来源: C-14.3, C-15.1/3, C-02.2, T-23]
- **要求**：邮件/短信服务商须具备有效 SOC2 Type II 或等效认证并签署 DPA；注册页展示隐私政策（收集字段、目的、第三方共享、留存、用户权利）且同意框非默认勾选（同意版本号传入本库 SR-16）；政策更新后下次登录重新确认、支持撤回非必要用途；生产环境将 `BreachChecker` 替换为 HIBP k-anonymity 实现（仅传口令 SHA-1 前 5 位）。
- **部署验收**：供应商合规证明归档年检；注册 UI 走查；HIBP 集成契约测试确认不外发完整口令哈希。

### SR-37 管理面隔离与管理员账号控制 [来源: T-26, T-28, T-29, T-30, T-31, C-06.4, C-07.4]
- **要求**：未来管理后台（P3）：独立部署 + IP 白名单/VPN 接入，不与用户面共享会话体系；管理员实名个人账号、强制 MFA（SR-25 门禁）、空闲超时 ≤ 15 分钟；批量操作（影响 > 100 用户）需二次 MFA 确认 + 操作预览 + 支持解除强制重置标记；后台默认脱敏展示 PII（复用本库 `mask_*` 与完整查看审计）；导出限特定角色；季度权限复核（本库 `require_role` 与审计提供技术支撑）。
- **部署验收**：非白名单网络访问管理面被拒；普通用户会话遍历管理端点全部 401/403；批量操作与完整 PII 查看产生审计与告警。

### SR-38 备份加密、保留与恢复过滤 [来源: C-10.3, C-09.1, T-17]
- **要求**：备份 AES-256 加密、保留 ≤ 35 天；恢复流程包含"已注销（PURGED）账号过滤"步骤，防止已删除 PII 复活。
- **部署验收**：备份文件抽查为密文；保留策略配置检查；恢复演练确认 PURGED 账号未复活。

### SR-39 安全告警规则 [来源: C-11.4, T-01, T-10, T-11, T-15]
- **要求**：基于本库审计事件流配置告警：单账号短时多次失败、同 IP 批量失败（撞库）、同一来源批量锁定多账号（T-11 特征）、重置接口调用激增、管理员批量操作、异地登录、非应用路径数据变更，触达安全响应通道。
- **部署验收**：注入测试事件逐条验证告警触达；告警-事件类型映射表评审。

### SR-40 泄露响应与 72 小时通知 [来源: C-18.1/4, T-17]
- **要求**：定义认证数据泄露分级（凭据库泄露 = P0）并接入事件响应流程；预置用户通知模板与渠道；事件确认后 72h 内可发出通知（受影响用户清单由本库 SR-20 导出能力支撑，批量处置由 `bulk_force_reset` 支撑）。
- **部署验收**：桌面演练记录：导出清单 + 批量强制重置 + 模板发送全链路 ≤ 72h。

## 4. 追溯矩阵

> 实现位置于阶段 4 回填（文件:行号）。"部署层" = 部署层要求，不在代码实现范围。

| 来源（C-xx/T-xx） | SR 编号 | 实现位置（阶段4回填） | 测试用例 |
|---|---|---|---|
| C-01.1, T-17 | SR-01 | auth_core/password.py:38,60 | ST-01 |
| C-01.2, T-03, T-09 | SR-07 | auth_core/tokens.py:14, auth_core/service.py:110,418 | ST-07 |
| C-01.3, T-09 | SR-13 | auth_core/audit.py:25,32 | ST-13 |
| C-02, T-01 | SR-02 | auth_core/password.py:93 | ST-02 |
| C-03, T-01, T-26 | SR-25 | 延期（下期 + 部署门禁，理由见 SR-25） | ST-25（部署验收） |
| C-04.1, T-01, T-11 | SR-03 | auth_core/service.py:184,202,302 | ST-03 |
| C-04.2/3, T-01, T-03, T-10 | SR-04 | auth_core/ratelimit.py:21, auth_core/service.py:125 | ST-04 |
| C-04.4, T-07 | SR-05 | auth_core/service.py:243,309,386, auth_core/password.py:64 | ST-05 |
| C-04.2（CAPTCHA/WAF）, T-10, T-18 | SR-29 | 部署层 | ST-29（部署验收） |
| C-05.1, T-02 | SR-24 | 部署层（集成层 Cookie） | ST-24（部署验收） |
| C-05.2/3/4, T-02, T-09 | SR-06 | auth_core/tokens.py:14, auth_core/service.py:135,159,344 | ST-06 |
| C-05.2, T-18 | SR-22 | auth_core/storage.py:213,238, auth_core/service.py:159,648 | ST-22 |
| C-06, T-12 | SR-08 | auth_core/models.py:37,46, auth_core/service.py:275,286,614 | ST-08 |
| C-06.4, C-07.1/2, T-28, T-31 | SR-21 | auth_core/service.py:172,566 | ST-21 |
| C-07.1, T-13 | SR-11 | auth_core/service.py:450,464 | ST-11 |
| C-07.3, T-15, T-19, T-14 | SR-27 | 部署层 | ST-27（部署验收） |
| C-07.4, T-26, T-28, T-29, T-30, T-31 | SR-37 | 部署层（管理后台下期） | ST-37（部署验收） |
| C-08, T-05, T-21 | SR-23 | 部署层 | ST-23（部署验收） |
| C-09.1/3, T-14, T-17 | SR-26 | 部署层 | ST-26（部署验收） |
| C-09.2/4, T-17, T-29 | SR-14 | auth_core/masking.py:10,15,24, auth_core/storage.py:128, auth_core/service.py:74 | ST-14 |
| C-10.1/2/4, C-17.4, T-17 | SR-15 | auth_core/service.py:627 | ST-15 |
| C-10.3, T-17 | SR-38 | 部署层 | ST-38（部署验收） |
| C-11.1/3, T-06, T-22 | SR-13 | auth_core/audit.py:46,57 | ST-13 |
| C-11.2, T-16 | SR-28 | 部署层 | ST-28（部署验收） |
| C-11.4, T-01, T-10, T-11, T-15 | SR-39 | 部署层 | ST-39（部署验收） |
| C-12, T-04, T-08, T-14 | SR-34 | 部署层（CI/渗透） | ST-34（部署验收） |
| C-13, T-27 | SR-35 | 部署层（流程/CI） | ST-35（部署验收） |
| C-14.1/4, T-23, T-21, T-09 | SR-18 | auth_core/notify.py:36,50, auth_core/service.py:84 | ST-18 |
| C-14.2, T-25 | SR-32 | 部署层 | ST-32（部署验收） |
| C-14.3, C-15.1/3, C-02.2, T-23 | SR-36 | 部署层/组织层 | ST-36（部署验收） |
| C-15.2 | SR-16 | auth_core/service.py:258, auth_core/storage.py:334, auth_core/models.py:101 | ST-16 |
| C-16.1 | SR-17 | auth_core/models.py:86, auth_core/service.py:230 | ST-17 |
| C-16.2, T-04 | SR-09 | auth_core/storage.py:95（全表参数化）, auth_core/models.py:51,62,68 | ST-09 |
| C-16.2, C-07.2, T-12 | SR-10 | auth_core/models.py:94,251 | ST-10 |
| C-17.2/3, T-13 | SR-12 | auth_core/service.py:177,495 | ST-12 |
| C-18.2/3, T-17 | SR-20 | auth_core/service.py:586,601, 登录拦截 service.py:325 | ST-20 |
| C-18.1/4, T-17 | SR-40 | 部署层/组织层 | ST-40（部署验收） |
| T-08 | SR-19 | auth_core/errors.py:31,75, auth_core/storage.py:95 | ST-19 |
| T-09（前端落地页） | SR-30 | 部署层 | ST-30（部署验收） |
| T-20 | SR-31 | 部署层 | ST-31（部署验收） |
| T-24 | SR-33 | 部署层（真实 Sender 实现时） | ST-33（部署验收） |

> **覆盖性声明**：上游全部 C-01 ~ C-18 与全部中高风险威胁（高 12 项：T-01/02/03/04/05/09/10/12/14/17/26/31；中 17 项：T-06/07/08/11/13/15/16/18/19/20/21/23/24/25/27/28/29）均被至少一条 SR 覆盖。
> **未完整覆盖项及理由**：
> 1. **C-03 / MFA（SR-25）**：本期有意延期。理由：标准库无 AES 无法满足 TOTP 密钥加密存储（依赖 KMS），且本期无 HTTP 面与管理后台；已设置"管理面上线前强制完成"门禁，数据模型预留字段。
> 2. **低风险 T-22、T-30**：上游威胁模型已正式接受残余风险；本 SPEC 仍部分覆盖（T-22 → SR-13 记录 message_id；T-30 → SR-37 批量操作二次确认），不另设独立 SR。

## 5. 接口设计

本期交付为 **Python 库 API**（无 HTTP 层）。所有方法为 `AuthService` 实例方法；错误以类型化异常表达（见 5.3）；"速率限制"列为库内 SR-04 限流维度。附 5.4 为未来 HTTP 映射建议（部署阶段参考）。

### 5.1 服务构造

```python
AuthService(
    db_path: str,                      # sqlite3 数据库路径
    config: AuthConfig,                # 阈值/TTL 配置（见下）
    email_sender: EmailSender,         # 抽象基类，本期注入 FakeEmailSender
    sms_sender: SmsSender | None,
    breach_checker: BreachChecker,     # 默认 LocalListBreachChecker
    clock: Clock = SystemClock(),      # 可注入时钟（测试控制时间）
    pepper: bytes,                     # 盲索引 HMAC pepper，空则 ConfigError（SR-14）
)
```

`AuthConfig` 默认值（均为 SR 规定的安全基线，只可收紧）：`session_idle_minutes=30, session_absolute_hours=24, sessions_per_user_max=20, lockout_threshold=10, lockout_minutes=15, backoff_start_at=5, reset_token_minutes=30, verify_token_hours=24, login_ip_per_minute=10, register_ip_per_minute=10, reset_per_account_per_minute=1, reset_per_account_per_day=5, token_check_ip_per_minute=10, deletion_grace_days=30, unverified_purge_hours=72, password_min=12, password_max=128, base_url="https://example.com"`。

### 5.2 方法清单

| 方法 | 入参 schema | 返回 schema | 主要错误码 | 限流维度 |
|---|---|---|---|---|
| `register(req: RegisterRequest, client: ClientInfo)` | `RegisterRequest{email:str, password:str, phone:str\|None, consent_version:str}`（from_dict 白名单，SR-10） | `RegisterResult{ok:True}`（无论新注册/重复，SR-05） | VALIDATION_ERROR, WEAK_PASSWORD, BREACHED_PASSWORD, CONSENT_REQUIRED, RATE_LIMITED | 注册 IP |
| `verify_email(token: str)` | token: str | `None` | INVALID_TOKEN, RATE_LIMITED | token 校验 IP |
| `login(email, password, client)` | email ≤254, password ≤128, `ClientInfo{ip:str, user_agent:str}` | `LoginResult{session_token:str, user_id:str}` | INVALID_CREDENTIALS, RATE_LIMITED, ACCOUNT_LOCKED*, PASSWORD_RESET_REQUIRED | 登录 IP + 账号失败计数 |
| `logout(session_token)` | token | `None` | NOT_AUTHENTICATED | — |
| `validate_session(session_token)` | token | `SessionContext{user_id, role, issued_at}` | NOT_AUTHENTICATED | — |
| `rotate_session(session_token)` | token | 新 `session_token` | NOT_AUTHENTICATED | — |
| `request_password_reset(email, client)` | email | `{ok:True}`（统一） | RATE_LIMITED, VALIDATION_ERROR | 账号 1/min, 5/day + IP |
| `reset_password(token, new_password, client)` | token, new_password | `None` | INVALID_TOKEN, WEAK_PASSWORD, BREACHED_PASSWORD, RATE_LIMITED | token 校验 IP |
| `change_password(session_token, old, new)` | — | 新 `session_token` | NOT_AUTHENTICATED, REAUTH_FAILED, WEAK_PASSWORD, BREACHED_PASSWORD | 账号失败计数 |
| `get_profile(session_token, masked=True)` | — | `Profile{user_id, email, phone, status, created_at}`（默认脱敏） | NOT_AUTHENTICATED | — |
| `update_phone(session_token, password, new_phone)` | E.164 | `None` | REAUTH_FAILED, VALIDATION_ERROR | — |
| `request_email_change(session_token, password, new_email)` | — | `None`（发双 token） | REAUTH_FAILED, VALIDATION_ERROR, RATE_LIMITED | 账号 |
| `confirm_email_change(old_token, new_token)` | — | `None` | INVALID_TOKEN | token 校验 IP |
| `request_deletion(session_token, password)` / `cancel_deletion(session_token)` | — | `None` | REAUTH_FAILED, NOT_AUTHENTICATED | — |
| `ban_user / unban_user(actor, user_id)` | `ActorContext{actor_id, role}` | `None` | PERMISSION_DENIED | — |
| `bulk_force_reset(actor, user_ids)` | — | `{affected:int}` | PERMISSION_DENIED | — |
| `export_affected_users(actor, start_ts, end_ts)` | UTC ISO-8601 | `list[str]`（user_id） | PERMISSION_DENIED | — |
| `purge_unverified_accounts() / purge_deleted_accounts() / purge_expired_sessions() / purge_expired_tokens()` | — | `{purged:int}` | — | — |

\* `ACCOUNT_LOCKED` 仅以 `retry_after` 形式区别于一般失败，文案与 `RATE_LIMITED` 一致化处理以兼顾防枚举（锁定计数对不存在账号同样生效，见 SR-03）。

### 5.3 错误码枚举（errors.py）

`VALIDATION_ERROR, UNEXPECTED_FIELD, CONSENT_REQUIRED, WEAK_PASSWORD, BREACHED_PASSWORD, INVALID_CREDENTIALS, INVALID_TOKEN, NOT_AUTHENTICATED, REAUTH_FAILED, PERMISSION_DENIED, RATE_LIMITED, ACCOUNT_LOCKED, PASSWORD_RESET_REQUIRED, ILLEGAL_STATE, STORAGE_ERROR, CONFIG_ERROR, SENDER_PARAM_ERROR`。所有异常 message 为固定通用文案（SR-19）。

### 5.4 未来 HTTP 映射建议（部署阶段参考，非本期交付）

`POST /auth/register`、`POST /auth/verify-email`、`POST /auth/login`、`POST /auth/logout`、`POST /auth/password/forgot`、`POST /auth/password/reset`、`POST /auth/password/change`、`GET/PATCH /me`、`POST /me/email-change`、`DELETE /me`；管理端点独立挂载于隔离的管理面（SR-37）。HTTP 层须落实 SR-23/24/29/30。

## 6. 数据模型

SQLite（生产可平迁服务化数据库，SR-27）。所有时间为 UTC ISO-8601 文本。

| 实体 | 字段 | 类型 | 敏感标注（加密/脱敏/审计） |
|---|---|---|---|
| users | id | TEXT PK（UUIDv4） | 假名化锚点（SR-15） |
| users | email | TEXT NULL | **PII-高**：静态加密由部署层（SR-26）；展示必脱敏（SR-14）；注销置 NULL |
| users | email_bidx | TEXT UNIQUE NULL | 盲索引 HMAC-SHA256（SR-14），不可逆 |
| users | phone | TEXT NULL | **PII-高**：同 email 处理；可选字段（SR-17） |
| users | password_hash | TEXT NULL | **凭据-极高**：scrypt 格式串（SR-01），永不出现在日志/返回值 |
| users | role | TEXT DEFAULT 'user' | 仅服务端/ADMIN 可写（SR-10/21） |
| users | status | TEXT | 状态机约束（SR-08），变更全审计 |
| users | failed_count / next_allowed_at / lockout_until | INTEGER / TEXT / TEXT | SR-03（失败键另含未注册邮箱的独立 lockout_keys 表） |
| users | force_password_reset | INTEGER DEFAULT 0 | SR-20 |
| users | mfa_enabled / mfa_secret_enc | INTEGER / TEXT NULL | 预留（SR-25）；secret 必须密文，本期恒 NULL |
| users | created_at / email_verified_at / purge_after | TEXT | SR-08 / SR-15 |
| sessions | token_hash | TEXT PK | **凭据-极高**：仅 SHA-256 哈希（SR-06），无明文 |
| sessions | user_id / created_at / last_seen_at / expires_at / ip / user_agent | — | ip/UA 仅取证用（SR-13），展示脱敏 |
| tokens | token_hash | TEXT PK | **凭据-极高**：仅 SHA-256 哈希（SR-07/08/12） |
| tokens | user_id / purpose（email_verify, password_reset, email_change_old, email_change_new）/ created_at / expires_at / used_at / payload | — | payload 仅存新邮箱密文/盲索引引用，不存明文 PII 于日志 |
| lockout_keys | email_key（规范化邮箱的 HMAC）/ failed_count / next_allowed_at / lockout_until | TEXT/… | 防枚举：不存在账号也计数（SR-03/05），键为 HMAC 不留明文邮箱 |
| rate_limits | bucket_key / window_start / count | TEXT/TEXT/INTEGER | SR-04；bucket_key 中邮箱以 HMAC 形式出现 |
| consent_records | user_id / consent_version / consented_at / ip | — | SR-16 |
| audit_events | event_id / event_type / ts / user_id / actor_id / ip / user_agent / result / detail(JSON) | — | **强制脱敏**（SR-13）：无口令/token 明文、PII 一律掩码；注销后仅余 UUID（SR-15） |

## 7. 技术选型与架构

- **语言/运行时**：Python 3.11，仅标准库（环境无法安装第三方包——本身消除了 SCA 攻击面，SR-34 的依赖扫描在本期天然满足）。
- **关键标准库选型与安全考量**：
  - `hashlib.scrypt`（n=2**14, r=8, p=1, dklen=64, 16B 随机盐）：标准库中唯一 OWASP 认可的内存困难 KDF；**生产推荐迁移 argon2id**（C-01 原要求），存储格式自描述前缀保证可迁移。
  - `secrets`：全部 token/盐生成（CSPRNG，禁用 `random`）。
  - `hmac`：盲索引（SR-14）与所有哈希比较（`compare_digest`，防时序侧信道）。
  - `sqlite3`：全程参数化查询（SR-09）；`busy_timeout=5000`；外键约束开启。
  - `unittest`：全部功能与安全测试；注入式 `Clock` 实现时间相关用例确定性。
- **模块划分**：

```
auth_core/
  __init__.py      # 公开 API 导出
  service.py       # AuthService：业务编排、防枚举、锁定、RBAC 守卫
  models.py        # DTO（from_dict 白名单）、状态机、枚举、AuthConfig
  storage.py       # sqlite3 仓储：参数化查询、schema 迁移、清理任务
  password.py      # scrypt 哈希/校验、口令策略、BreachChecker 接口与本地实现
  tokens.py        # token 生成/哈希/校验（会话、验证、重置、换绑）
  ratelimit.py     # 滑动窗口限流器（sqlite 持久化）
  audit.py         # 结构化审计 + sanitize 脱敏强制
  notify.py        # EmailSender/SmsSender 抽象 + Fake 实现 + 参数白名单网关
  masking.py       # mask_email / mask_phone / blind_index
  errors.py        # 类型化异常与错误码枚举（统一通用文案）
  clock.py         # Clock 抽象 / SystemClock / 测试用 FakeClock
tests/             # unittest：test_functional_*.py / test_security_*.py
```

- **依赖注入边界**：EmailSender/SmsSender、BreachChecker、Clock、pepper、AuthConfig 全部构造期注入——生产替换真实实现时核心逻辑零修改（支撑 SR-26/32/33/36 的部署替换）。

## 8. 测试要求

框架：`unittest`；时间相关用例使用 `FakeClock`；邮件断言使用 `FakeEmailSender.sent` 记录。**每条 SR 至少一条安全测试**（代码 SR → 自动化用例；部署 SR → 部署验收检查单）。

### 8.1 功能测试

| 用例 ID | 对应 FR | 描述 | 预期 |
|---|---|---|---|
| FT-01 | FR-01 | 合法注册（含/不含手机号、含同意版本） | 账号 PENDING_VERIFICATION，FakeSender 收到激活邮件，同意记录落库 |
| FT-02 | FR-01 | 重复邮箱注册 | 返回与新注册一致；收到"您已有账号"邮件 |
| FT-03 | FR-02 | 有效 token 激活 | 状态 ACTIVE，token 置 used |
| FT-04 | FR-03 | 正确凭据登录 | 返回会话 token，审计 LOGIN_SUCCESS |
| FT-05 | FR-04/05 | 登出后校验 | NOT_AUTHENTICATED |
| FT-06 | FR-06/07 | 找回密码全流程 | 新口令可登录，旧口令失败，旧会话全失效 |
| FT-07 | FR-08 | 修改口令 | 返回新会话，旧会话失效，收到通知邮件 |
| FT-08 | FR-09 | 查看资料（默认/完整） | 默认脱敏；完整查看产生审计 |
| FT-09 | FR-10 | 改手机号与换绑邮箱（双 token） | 双向验证后生效，双邮箱收通知 |
| FT-10 | FR-11 | 注销→撤销 / 注销→30 天清除 | 撤销恢复 ACTIVE；到期 PII 置 NULL |
| FT-11 | FR-12 | ADMIN 封禁/解封/批量重置/导出 | 生效且全审计 |
| FT-12 | FR-13 | 三类清理任务 | 返回正确清理计数 |
| FT-13 | FR-03 | 登录成功重置失败计数 | failed_count 归零 |

### 8.2 安全测试

| 用例 ID | 对应 SR | 描述 | 预期 |
|---|---|---|---|
| ST-01 | SR-01 | 检查存储哈希格式/盐独立性/无明文；错误口令拒绝 | `scrypt$n=16384,...` 前缀；两次注册哈希不同 |
| ST-02 | SR-02 | 11 字符 / `password123456` / 含邮箱本地部分口令注册 | 分别 WEAK_PASSWORD / BREACHED_PASSWORD / WEAK_PASSWORD |
| ST-03 | SR-03 | 5 次失败后退避、10 次后锁定 15 分钟 + 通知邮件；锁定中找回密码可用；不存在邮箱同样触发锁定行为 | retry_after 生效、邮件 1 封、审计 ACCOUNT_LOCKED、防枚举一致 |
| ST-04 | SR-04 | 四类限流逐一打满（登录 IP、注册 IP、重置账号 1/min+5/day、token 校验 IP） | 均 RATE_LIMITED 且窗口后恢复 |
| ST-05 | SR-05 | 存在/不存在邮箱登录失败响应逐字段比对 + 200 次耗时分布；找回密码两种结果比对 | 完全一致；耗时中位数差 < 20% |
| ST-06 | SR-06 | DB 无 token 明文；空闲 31min/绝对 24h+1s 失效；改密吊销全部会话；rotate 后旧 token 失效；两次登录 token 不同 | 全部通过 |
| ST-07 | SR-07 | 重置 token 复用/过期/重新申请后旧 token 使用 | 均 INVALID_TOKEN；DB 仅存哈希 |
| ST-08 | SR-08 | 未激活登录、73h 清理、非法状态迁移 | INVALID_CREDENTIALS / 行删除 / IllegalStateError |
| ST-09 | SR-09 | SQL 注入 payload 集（`' OR 1=1 --` 等 10+ 条）打全部入参；超长输入 | 表完好、ValidationError 或常规失败；存储层零拼接 SQL（代码审查项） |
| ST-10 | SR-10 | from_dict 注入 `role/is_admin/email_verified/status` | ValidationError；正常注册落库默认 role/status |
| ST-11 | SR-11 | 用户 A 会话操作用户 B 资源（读/写各一）；ADMIN 例外路径 | 403 语义（PERMISSION_DENIED）；ADMIN 成功且审计 |
| ST-12 | SR-12 | 错误口令执行注销/换绑/改手机号；仅单侧 token 的换绑 | REAUTH_FAILED 且无变更；换绑不生效 |
| ST-13 | SR-13 | 全流程跑完后全表扫描审计：口令/token/完整 PII 检索；sanitize 注入测试；message_id 存在性 | 零泄漏；[REDACTED] 替换；发送事件含 message_id |
| ST-14 | SR-14 | pepper 缺失初始化；按邮箱查询仅走 bidx；mask 函数边界（短本地部分、无 +86 手机号） | ConfigError；断言 SQL；掩码正确 |
| ST-15 | SR-15 | 30 天后清除：PII 列 NULL、会话/token 清空、盲索引查询为空、审计仅 UUID | 全部通过 |
| ST-16 | SR-16 | 无/空 consent_version 注册 | CONSENT_REQUIRED |
| ST-17 | SR-17 | 不含 phone 注册成功；模型无多余 PII 字段（schema 断言） | 通过 |
| ST-18 | SR-18 | Fake sender 捕获参数白名单断言；注入 PII 键经网关 | action_url 无 PII；SenderParamError |
| ST-19 | SR-19 | 注入存储故障后异常文案扫描（"sqlite"/SQL 关键字/路径） | 零泄漏，类型化异常 |
| ST-20 | SR-20 | 强制重置标记下正确口令登录；重置后恢复；导出集合与审计一致 | PASSWORD_RESET_REQUIRED；通过 |
| ST-21 | SR-21 | role=user 与 None actor 遍历全部管理方法 | 全部 PERMISSION_DENIED 且无副作用 |
| ST-22 | SR-22 | 登录 21 次会话上限淘汰；过期会话/限流行清理 | 恰 20 行；清理计数正确 |
| ST-23~ST-40 | SR-23 ~ SR-40 | **部署验收检查单**（每条 SR 的"部署验收"标准逐项执行：testssl 扫描、Cookie 属性、KMS/秘钥扫描、append-only 验证、WAF 压测、Referrer 抓包、SPF/DKIM/DMARC 校验、API key 权限、重试演练、CI 门禁、漂移告警、供应商证明、管理面隔离渗透、备份恢复演练、告警注入、72h 泄露演练；SR-25 验收延至下期） | 逐项通过并归档证据 |

## 9. 非目标（Out of Scope）

1. **HTTP/Web 层**：不实现任何 HTTP 框架、路由、Cookie 写入、CSRF 防护、前端页面（SR-23/24/29/30 列为部署层要求）。
2. **真实邮件/短信发送**：仅抽象接口 + Fake 实现；SMTP/API 集成、异步队列、备用通道切换（SR-33）为部署阶段工作。
3. **管理后台（P3）**：不实现管理 UI 与管理 HTTP API；本库仅提供带 RBAC 守卫的管理 service 方法（SR-21）作为未来接入点。
4. **MFA（TOTP/恢复码/风险自适应二次确认）**：有意延期至下期（理由与门禁见 SR-25）。
5. **字段级 AES 加密与 KMS**：标准库限制，由部署层承接（SR-26）；本库交付盲索引与脱敏使切换无感。
6. **CAPTCHA、WAF、抗 DDoS、TLS 配置、备份、日志外送系统**：部署层（SR-23/26/28/29/38）。
7. **HIBP 在线泄露口令查询**：本期用本地清单实现接口，生产替换（SR-36）。
8. **隐私政策 UI、同意撤回交互、政策更新重确认**：上层产品范围（SR-36）；本库仅持久化同意记录。
9. **组织级流程**：季度权限复核执行、安全培训、供应商年审、变更审批流程本身（SR-35/36/37 仅定义技术支撑与验收标准）。
10. **多语言/国际化、用户名登录、社交登录（OAuth）**：不在本需求范围。

---

## 附：自检记录（SPEC 完成检查）

- [x] 上游 C-01~C-18 全部出现在追溯矩阵且各有 ≥ 1 条 SR（C-03 为记录在案的延期项，含门禁）。
- [x] 高风险 12 项、中风险 17 项威胁全部被 SR 覆盖；低风险 T-22/T-30 沿用上游接受决策并部分覆盖。
- [x] 每条 SR 标注来源、含可判定的验收标准（阈值/格式/行为均量化）。
- [x] 每条 SR 对应至少一条安全测试（ST-01~ST-22 自动化；ST-23~ST-40 部署验收检查单）。
- [x] 一个不了解背景的工程师可凭本文档实现：构造函数签名、方法清单、错误码、表结构、默认配置、模块划分、scrypt/token 参数均已给出。
