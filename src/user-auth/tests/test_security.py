"""安全测试 ST-01 ~ ST-22（SPEC §8.2，与 SR-01 ~ SR-22 一一对应）。"""
import inspect
import json
import statistics
import time
import unittest

from auth_core import (AccountStatus, ActorContext, AuthConfig, AuthError,
                       AuthService, ConfigError, ErrorCode, FakeClock,
                       FakeEmailSender, FakeSmsSender, IllegalStateError,
                       LocalListBreachChecker, RegisterRequest, Role,
                       StorageError, ValidationError, mask_email, mask_phone)
from auth_core import storage as storage_module
from auth_core.masking import blind_index
from auth_core.notify import send_email
from tests.helpers import (GOOD_PASSWORD, PEPPER, client, make_service,
                           register, register_and_activate, token_from)


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.svc, self.clock, self.sender = make_service()

    def _user_row(self, email: str):
        return self.svc.storage.find_user_by_bidx(blind_index(PEPPER, email))

    # ------------------------------------------------------------------
    def test_st01_password_hash_storage(self):
        """ST-01 / SR-01: scrypt 格式、盐独立、无明文、校验正确性。"""
        register(self.svc, self.sender, "a1@example.com")
        register(self.svc, self.sender, "a2@example.com", ip="203.0.113.2")
        h1 = self._user_row("a1@example.com")["password_hash"]
        h2 = self._user_row("a2@example.com")["password_hash"]
        self.assertTrue(h1.startswith("scrypt$n=16384,r=8,p=1$"))
        self.assertNotIn(GOOD_PASSWORD, h1)
        self.assertNotEqual(h1, h2)  # 同口令不同盐
        from auth_core.password import verify_password
        self.assertTrue(verify_password(GOOD_PASSWORD, h1))
        self.assertFalse(verify_password("wrong-password-000", h1))

    def test_st02_password_policy(self):
        """ST-02 / SR-02: 长度 / 泄露口令 / 含邮箱本地部分。"""
        cases = [
            ("short11pass", ErrorCode.WEAK_PASSWORD),            # 11 字符
            ("password123456", ErrorCode.BREACHED_PASSWORD),     # 泄露清单
            ("Liuyin0214-aaaa", ErrorCode.WEAK_PASSWORD),        # 含本地部分
        ]
        for pwd, code in cases:
            with self.assertRaises(ValidationError, msg=pwd) as cm:
                register(self.svc, self.sender, "liuyin0214@example.com",
                         password=pwd)
            self.assertEqual(cm.exception.code, code, pwd)
        register(self.svc, self.sender, "liuyin0214@example.com")  # 合规口令通过

    def test_st03_backoff_lockout_notification(self):
        """ST-03 / SR-03: 退避、软锁定、通知、找回通道兜底、防枚举一致。"""
        register_and_activate(self.svc, self.sender, "victim@example.com")
        # 连续 5 次失败后，第 6 次（正确口令）也被退避拒绝
        for _ in range(5):
            with self.assertRaises(AuthError):
                self.svc.login("victim@example.com", "wrong-password-123", client())
        with self.assertRaises(AuthError) as cm:
            self.svc.login("victim@example.com", GOOD_PASSWORD, client())
        self.assertEqual(cm.exception.code, ErrorCode.ACCOUNT_LOCKED)
        self.assertGreaterEqual(cm.exception.retry_after, 1)
        # 继续到 10 次 → 锁定 15 分钟 + 1 封通知 + 审计
        for _ in range(5):
            self.clock.advance(seconds=61)
            with self.assertRaises(AuthError):
                self.svc.login("victim@example.com", "wrong-password-123", client())
        locked_mails = [m for m in self.sender.sent
                        if m["template_id"] == "account_locked"]
        self.assertEqual(len(locked_mails), 1)
        self.assertEqual(len(self.svc.storage.query_audit("ACCOUNT_LOCKED")), 1)
        with self.assertRaises(AuthError) as cm:
            self.svc.login("victim@example.com", GOOD_PASSWORD,
                           client(ip="203.0.113.50"))
        locked_exc = cm.exception
        self.assertEqual(locked_exc.code, ErrorCode.ACCOUNT_LOCKED)
        # 锁定中找回密码通道可用（T-11 兜底）
        self.svc.request_password_reset("victim@example.com", client())
        self.assertEqual(self.sender.sent[-1]["template_id"], "password_reset")
        # 不存在邮箱触发同样的锁定行为（防枚举）
        for _ in range(10):
            self.clock.advance(seconds=61)
            with self.assertRaises(AuthError):
                self.svc.login("ghost@example.com", "wrong-password-123",
                               client(ip="203.0.113.60"))
        with self.assertRaises(AuthError) as cm:
            self.svc.login("ghost@example.com", "wrong-password-123",
                           client(ip="203.0.113.61"))
        self.assertEqual(cm.exception.code, locked_exc.code)
        self.assertEqual(str(cm.exception), str(locked_exc))

    def test_st04_rate_limits(self):
        """ST-04 / SR-04: 登录 IP / 注册 IP / 重置账号 / token 校验 IP 四维限流。"""
        # 登录同 IP 10/min（不同邮箱避免锁定干扰）
        for i in range(10):
            with self.assertRaises(AuthError):
                self.svc.login("u%d@example.com" % i, "wrong-password-123",
                               client(ip="198.51.100.1"))
        with self.assertRaises(AuthError) as cm:
            self.svc.login("u10@example.com", "wrong-password-123",
                           client(ip="198.51.100.1"))
        self.assertEqual(cm.exception.code, ErrorCode.RATE_LIMITED)
        # 窗口过后恢复
        self.clock.advance(seconds=61)
        with self.assertRaises(AuthError) as cm:
            self.svc.login("u11@example.com", "wrong-password-123",
                           client(ip="198.51.100.1"))
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_CREDENTIALS)
        # 注册同 IP 10/min
        for i in range(10):
            register(self.svc, self.sender, "r%d@example.com" % i,
                     ip="198.51.100.2")
        with self.assertRaises(AuthError) as cm:
            register(self.svc, self.sender, "r10@example.com", ip="198.51.100.2")
        self.assertEqual(cm.exception.code, ErrorCode.RATE_LIMITED)
        # 找回密码：同账号 1/min
        self.clock.advance(seconds=61)
        self.svc.request_password_reset("r0@example.com", client(ip="198.51.100.3"))
        with self.assertRaises(AuthError) as cm:
            self.svc.request_password_reset("r0@example.com",
                                            client(ip="198.51.100.4"))
        self.assertEqual(cm.exception.code, ErrorCode.RATE_LIMITED)
        # 找回密码：同账号 5/day（每次隔 61s 绕开分钟限）
        for _ in range(4):
            self.clock.advance(seconds=61)
            self.svc.request_password_reset("r0@example.com",
                                            client(ip="198.51.100.5"))
        self.clock.advance(seconds=61)
        with self.assertRaises(AuthError) as cm:
            self.svc.request_password_reset("r0@example.com",
                                            client(ip="198.51.100.6"))
        self.assertEqual(cm.exception.code, ErrorCode.RATE_LIMITED)
        # token 校验同 IP 10/min（防在线枚举）
        for _ in range(10):
            with self.assertRaises(AuthError):
                self.svc.verify_email("not-a-real-token-aaaaaaaaaaaaaaaaaaaa",
                                      client(ip="198.51.100.7"))
        with self.assertRaises(AuthError) as cm:
            self.svc.verify_email("not-a-real-token-aaaaaaaaaaaaaaaaaaaa",
                                  client(ip="198.51.100.7"))
        self.assertEqual(cm.exception.code, ErrorCode.RATE_LIMITED)

    def test_st05_anti_enumeration_uniform_response_and_timing(self):
        """ST-05 / SR-05: 统一响应逐字段一致 + 恒时校验（200 次耗时分布）。"""
        register_and_activate(self.svc, self.sender, "real@example.com")
        # 响应一致性
        def fail(email, ip):
            try:
                self.svc.login(email, "wrong-password-123", client(ip=ip))
            except AuthError as exc:
                return exc
            self.fail("expected AuthError")
        e1 = fail("real@example.com", "198.51.100.10")
        e2 = fail("missing@example.com", "198.51.100.11")
        self.assertEqual(e1.code, e2.code)
        self.assertEqual(str(e1), str(e2))
        # 找回密码两种情况返回值逐字段相等
        r1 = self.svc.request_password_reset("real@example.com",
                                             client(ip="198.51.100.12"))
        r2 = self.svc.request_password_reset("missing@example.com",
                                             client(ip="198.51.100.13"))
        self.assertEqual(r1, r2)
        # 恒时：200 次比较耗时中位数差异 < 20%（dummy scrypt 生效）
        N = 200
        times_real, times_missing = [], []
        for i in range(N):
            self.clock.advance(minutes=16)  # 绕开退避/锁定与限流窗口
            ip = "198.51.%d.%d" % (101 + i // 200, i % 200)
            t0 = time.perf_counter()
            fail("real@example.com", ip)
            times_real.append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            fail("missing@example.com", ip)
            times_missing.append(time.perf_counter() - t0)
        med_real = statistics.median(times_real)
        med_missing = statistics.median(times_missing)
        diff = abs(med_real - med_missing) / max(med_real, med_missing)
        self.assertLess(diff, 0.20,
                        "timing medians: real=%.4fs missing=%.4fs" %
                        (med_real, med_missing))

    def test_st06_session_lifecycle(self):
        """ST-06 / SR-06: 哈希存储、超时、改密吊销、轮换、token 唯一。"""
        login1 = register_and_activate(self.svc, self.sender, "alice@example.com")
        self.clock.advance(seconds=61)
        login2 = self.svc.login("alice@example.com", GOOD_PASSWORD, client())
        self.assertNotEqual(login1.session_token, login2.session_token)
        # DB 仅存 64 位十六进制哈希，无明文
        row = self.svc.storage.find_session(
            __import__("auth_core.tokens", fromlist=["hash_token"])
            .hash_token(login2.session_token))
        self.assertIsNotNone(row)
        self.assertEqual(len(row["token_hash"]), 64)
        self.assertNotEqual(row["token_hash"], login2.session_token)
        # 空闲 31 分钟失效
        self.clock.advance(minutes=31)
        with self.assertRaises(AuthError):
            self.svc.validate_session(login2.session_token)
        # 绝对 24 小时失效（持续保活也不行）
        self.clock.advance(seconds=61)
        login3 = self.svc.login("alice@example.com", GOOD_PASSWORD, client())
        for _ in range(49):  # 49 × 29min ≈ 23.7h，全程保活
            self.clock.advance(minutes=29)
            self.svc.validate_session(login3.session_token)
        self.clock.advance(minutes=29)  # 累计超过 24h
        with self.assertRaises(AuthError):
            self.svc.validate_session(login3.session_token)
        # 改密吊销全部会话（FT-07 验证），轮换后旧 token 失效
        self.clock.advance(seconds=61)
        login4 = self.svc.login("alice@example.com", GOOD_PASSWORD, client())
        new_token = self.svc.rotate_session(login4.session_token)
        with self.assertRaises(AuthError):
            self.svc.validate_session(login4.session_token)
        self.svc.validate_session(new_token)

    def test_st07_reset_token_security(self):
        """ST-07 / SR-07: 复用 / 过期 / 重新申请失效；DB 仅存哈希。"""
        register_and_activate(self.svc, self.sender, "alice@example.com")
        self.svc.request_password_reset("alice@example.com", client())
        token1 = token_from(self.sender.sent[-1])
        # DB 仅存哈希
        from auth_core.tokens import hash_token
        self.assertIsNotNone(
            self.svc.storage.find_token(hash_token(token1), "password_reset"))
        self.assertIsNone(
            self.svc.storage.find_token(token1, "password_reset"))
        # 重新申请 → 旧 token 失效
        self.clock.advance(seconds=61)
        self.svc.request_password_reset("alice@example.com", client())
        token2 = token_from(self.sender.sent[-1])
        with self.assertRaises(AuthError) as cm:
            self.svc.reset_password(token1, "another-good-password-55", client())
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_TOKEN)
        # 正常使用一次后复用被拒
        self.svc.reset_password(token2, "another-good-password-55", client())
        with self.assertRaises(AuthError) as cm:
            self.svc.reset_password(token2, "another-good-password-66", client())
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_TOKEN)
        # 过期（31 分钟）
        self.clock.advance(seconds=61)
        self.svc.request_password_reset("alice@example.com", client())
        token3 = token_from(self.sender.sent[-1])
        self.clock.advance(minutes=31)
        with self.assertRaises(AuthError) as cm:
            self.svc.reset_password(token3, "another-good-password-77", client())
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_TOKEN)

    def test_st08_state_machine(self):
        """ST-08 / SR-08: 未激活登录、72h 清理、非法迁移、迁移审计。"""
        register(self.svc, self.sender, "pending@example.com")
        with self.assertRaises(AuthError) as cm:
            self.svc.login("pending@example.com", GOOD_PASSWORD, client())
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_CREDENTIALS)
        # 未激活账号找回密码：发激活提醒而非重置邮件
        self.svc.request_password_reset("pending@example.com", client())
        self.assertEqual(self.sender.sent[-1]["template_id"], "activation_reminder")
        # 非法迁移：PENDING_VERIFICATION → BANNED
        admin = ActorContext(actor_id="admin-001", role=Role.ADMIN)
        row = self._user_row("pending@example.com")
        with self.assertRaises(IllegalStateError):
            self.svc.ban_user(admin, row["id"])
        # 73h 后清理
        self.clock.advance(hours=73)
        self.assertEqual(self.svc.purge_unverified_accounts()["purged"], 1)
        self.assertIsNone(self._user_row("pending@example.com"))
        # 状态迁移审计存在
        register_and_activate(self.svc, self.sender, "active@example.com",
                              ip="203.0.113.30")
        self.assertTrue(self.svc.storage.query_audit("STATUS_CHANGED"))

    def test_st09_sql_injection_and_input_limits(self):
        """ST-09 / SR-09: 注入 payload 集、超长输入、存储层零拼接 SQL。"""
        register_and_activate(self.svc, self.sender, "victim@example.com")
        payloads = [
            "' OR 1=1 --", "\"; DROP TABLE users;--", "admin'--",
            "' UNION SELECT * FROM users --", "1; DELETE FROM users",
            "' OR ''='", "\" OR \"\"=\"", "'; INSERT INTO users VALUES(1)--",
            "%' OR 1=1#", "\\'; EXEC xp_cmdshell('id')--", "${7*7}@x.com",
        ]
        for i, payload in enumerate(payloads):
            ip = "198.51.200.%d" % i
            # 登录：注入串要么格式校验拒绝，要么按"无此用户"常规失败
            with self.assertRaises((ValidationError, AuthError), msg=payload):
                self.svc.login(payload, "whatever-password-123", client(ip=ip))
            # 注册：RFC 合法但含特殊字符的串（如 ${7*7}@x.com）允许作为普通
            # 邮箱注册——参数化查询保证其仅作为数据落库，不被解释执行
            try:
                req = RegisterRequest.from_dict({
                    "email": payload, "password": GOOD_PASSWORD,
                    "consent_version": "v1",
                })
                self.svc.register(req, client(ip=ip))
            except (ValidationError, AuthError):
                pass
        # users 表完好，受害者可正常登录
        self.clock.advance(seconds=61)
        self.svc.login("victim@example.com", GOOD_PASSWORD, client())
        # 超长输入
        with self.assertRaises(ValidationError):
            self.svc.login("x" * 250 + "@e.com", GOOD_PASSWORD, client())
        with self.assertRaises(ValidationError):
            self.svc.login("a@example.com", "p" * 129, client())
        # 存储层零拼接（无 f-string / %-format 构造 SQL）
        source = inspect.getsource(storage_module)
        self.assertNotIn('f"', source)
        self.assertNotIn("f'", source)
        self.assertNotIn('% (', source)

    def test_st10_dto_whitelist(self):
        """ST-10 / SR-10: 提权字段注入被拒；默认 role/status 由服务端写入。"""
        for extra in ({"role": "admin"}, {"is_admin": True},
                      {"email_verified": True}, {"status": "ACTIVE"}):
            data = {"email": "evil@example.com", "password": GOOD_PASSWORD,
                    "consent_version": "v1", **extra}
            with self.assertRaises(ValidationError) as cm:
                RegisterRequest.from_dict(data)
            self.assertEqual(cm.exception.code, ErrorCode.UNEXPECTED_FIELD)
        register(self.svc, self.sender, "normal@example.com")
        row = self._user_row("normal@example.com")
        self.assertEqual(row["role"], "user")
        self.assertEqual(row["status"], AccountStatus.PENDING_VERIFICATION.value)

    def test_st11_object_level_authorization(self):
        """ST-11 / SR-11: 横向越权拒绝；ADMIN 例外路径审计；UUIDv4 主键。"""
        import uuid as uuid_module
        login_a = register_and_activate(self.svc, self.sender, "a@example.com")
        login_b = register_and_activate(self.svc, self.sender, "b@example.com",
                                        ip="203.0.113.31")
        self.assertEqual(uuid_module.UUID(login_a.user_id).version, 4)
        with self.assertRaises(AuthError) as cm:
            self.svc.get_profile(login_a.session_token, user_id=login_b.user_id)
        self.assertEqual(cm.exception.code, ErrorCode.PERMISSION_DENIED)
        with self.assertRaises(AuthError) as cm:
            self.svc.update_phone(login_a.session_token, GOOD_PASSWORD,
                                  "+8613800001111", user_id=login_b.user_id)
        self.assertEqual(cm.exception.code, ErrorCode.PERMISSION_DENIED)
        # ADMIN 例外路径成功且审计含 actor_id
        admin = ActorContext(actor_id="admin-001", role=Role.ADMIN)
        profile = self.svc.get_profile(login_a.session_token,
                                       user_id=login_b.user_id, actor=admin)
        self.assertEqual(profile.user_id, login_b.user_id)
        events = self.svc.storage.query_audit("PII_FULL_VIEW")
        self.assertTrue(any(e["actor_id"] == "admin-001" for e in events))

    def test_st12_reauthentication(self):
        """ST-12 / SR-12: 错误口令的敏感操作拒绝且无变更；换绑需双 token。"""
        login = register_and_activate(self.svc, self.sender, "alice@example.com",
                                      phone="+8613812341234")
        for op in (
            lambda: self.svc.request_deletion(login.session_token, "wrong-pw-123456"),
            lambda: self.svc.update_phone(login.session_token, "wrong-pw-123456",
                                          "+8613900002222"),
            lambda: self.svc.request_email_change(login.session_token,
                                                  "wrong-pw-123456",
                                                  "new@example.com"),
        ):
            with self.assertRaises(AuthError) as cm:
                op()
            self.assertEqual(cm.exception.code, ErrorCode.REAUTH_FAILED)
        full = self.svc.get_profile(login.session_token, masked=False)
        self.assertEqual(full.email, "alice@example.com")
        self.assertEqual(full.phone, "+8613812341234")
        self.assertEqual(full.status, AccountStatus.ACTIVE.value)
        # 换绑仅单侧 token 不生效
        self.svc.request_email_change(login.session_token, GOOD_PASSWORD,
                                      "alice-new@example.com")
        new_token = token_from(self.sender.sent[-1])
        with self.assertRaises(AuthError):
            self.svc.confirm_email_change("garbage-old-token-000000000000",
                                          new_token)
        self.assertIsNotNone(self._user_row("alice@example.com"))
        self.assertIsNone(self._user_row("alice-new@example.com"))

    def test_st13_audit_no_leakage(self):
        """ST-13 / SR-13: 审计全表零泄漏、sanitize 拦截、message_id 存在。"""
        login = register_and_activate(self.svc, self.sender, "alice@example.com",
                                      phone="+8613812341234")
        self.svc.request_password_reset("alice@example.com", client())
        reset_token = token_from(self.sender.sent[-1])
        self.svc.reset_password(reset_token, "another-good-password-55", client())
        # 收集全部已签发 token 明文与口令明文
        secrets_plain = {GOOD_PASSWORD, "another-good-password-55",
                         login.session_token, reset_token}
        secrets_plain |= {token_from(m) for m in self.sender.sent
                          if "action_url" in m["params"]}
        rows = self.svc.storage.query_audit()
        self.assertTrue(rows)
        blob = json.dumps([dict(r) for r in rows], ensure_ascii=False)
        for secret in secrets_plain:
            self.assertNotIn(secret, blob)
        self.assertNotIn("alice@example.com", blob)     # 完整邮箱
        self.assertNotIn("+8613812341234", blob)        # 完整手机号
        # sanitize 注入测试：故意写入 token 样式字符串
        self.svc.audit.log("TEST_EVENT", detail={
            "leak": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "password": "should-never-appear",
        })
        row = self.svc.storage.query_audit("TEST_EVENT")[0]
        detail = json.loads(row["detail"])
        self.assertEqual(detail["leak"], "[REDACTED]")
        self.assertEqual(detail["password"], "[REDACTED]")
        # 发送事件含 message_id（T-22 举证）
        sent_events = self.svc.storage.query_audit("EMAIL_SENT")
        self.assertTrue(sent_events)
        self.assertIn("message_id", json.loads(sent_events[0]["detail"]))

    def test_st14_blind_index_and_masking(self):
        """ST-14 / SR-14: pepper 缺失拒绝初始化；检索仅走 bidx；掩码边界。"""
        with self.assertRaises(ConfigError):
            AuthService(db_path=":memory:", config=AuthConfig(),
                        email_sender=FakeEmailSender(), sms_sender=FakeSmsSender(),
                        breach_checker=LocalListBreachChecker(),
                        pepper=b"", clock=FakeClock())
        source = inspect.getsource(storage_module)
        self.assertIn("email_bidx = ?", source)
        self.assertNotIn("WHERE email = ?", source)  # 不存在按明文邮箱检索路径
        self.assertEqual(mask_email("liuyin0214@gmail.com"), "l***@gmail.com")
        self.assertEqual(mask_email("a@b.com"), "***@b.com")
        self.assertEqual(mask_phone("+8613812341234"), "+86138****1234")
        self.assertEqual(mask_phone("+123"), "***")

    def test_st15_account_purge(self):
        """ST-15 / SR-15: 30 天后 PII 置 NULL、关联数据清空、盲索引查询为空。"""
        login = register_and_activate(self.svc, self.sender, "alice@example.com",
                                      phone="+8613812341234")
        user_id = login.user_id
        self.svc.request_deletion(login.session_token, GOOD_PASSWORD)
        self.clock.advance(days=31)
        self.assertEqual(self.svc.purge_deleted_accounts()["purged"], 1)
        row = self.svc.storage.find_user_by_id(user_id)
        for col in ("email", "email_bidx", "phone", "password_hash"):
            self.assertIsNone(row[col], col)
        self.assertEqual(row["status"], AccountStatus.PURGED.value)
        self.assertIsNone(self._user_row("alice@example.com"))
        self.assertEqual(self.svc.storage.count_sessions(user_id), 0)
        # 审计中无完整 PII（UUID + 掩码）
        blob = json.dumps([dict(r) for r in self.svc.storage.query_audit()],
                          ensure_ascii=False)
        self.assertNotIn("alice@example.com", blob)
        # 宽限期内撤销则数据完整保留（FT-10 验证撤销路径）

    def test_st16_consent_required(self):
        """ST-16 / SR-16: 无/空同意版本拒绝注册。"""
        for consent in (None, ""):
            with self.assertRaises(ValidationError) as cm:
                RegisterRequest.from_dict({
                    "email": "x@example.com", "password": GOOD_PASSWORD,
                    "consent_version": consent,
                })
            self.assertEqual(cm.exception.code, ErrorCode.CONSENT_REQUIRED)

    def test_st17_data_minimization(self):
        """ST-17 / SR-17: phone 严格可选；users 表无认证无关 PII 字段。"""
        register(self.svc, self.sender, "nophone@example.com")
        self.assertIsNone(self._user_row("nophone@example.com")["phone"])
        cur = self.svc.storage._conn.execute("PRAGMA table_info(users)")
        columns = {r[1] for r in cur.fetchall()}
        expected = {"id", "email", "email_bidx", "phone", "password_hash",
                    "role", "status", "force_password_reset", "mfa_enabled",
                    "mfa_secret_enc", "created_at", "email_verified_at",
                    "purge_after"}
        self.assertEqual(columns, expected)

    def test_st18_sender_param_whitelist(self):
        """ST-18 / SR-18: 发送参数白名单；action_url 无 PII；网关拦截注入。"""
        register_and_activate(self.svc, self.sender, "alice@example.com")
        self.svc.request_password_reset("alice@example.com", client())
        from auth_core.notify import ALLOWED_PARAM_KEYS
        for mail in self.sender.sent:
            self.assertTrue(set(mail["params"]).issubset(ALLOWED_PARAM_KEYS),
                            mail["params"])
            url = mail["params"].get("action_url", "")
            self.assertNotIn("@", url)
            self.assertNotIn("+86", url)
        with self.assertRaises(Exception) as cm:
            send_email(self.sender, "x@example.com", "t",
                       {"user_email": "leak@example.com"})
        self.assertEqual(cm.exception.code, ErrorCode.SENDER_PARAM_ERROR)

    def test_st19_storage_error_opacity(self):
        """ST-19 / SR-19: 存储故障转译为 StorageError，文案零内部细节。"""
        self.svc.storage._conn.close()  # 注入存储故障
        with self.assertRaises(StorageError) as cm:
            self.svc.login("a@example.com", "whatever-password-1", client())
        text = str(cm.exception).lower()
        self.assertNotIn("sqlite", text)
        self.assertNotIn("select", text)
        self.assertNotIn("/", text)

    def test_st20_bulk_force_reset_and_export(self):
        """ST-20 / SR-20: 强制重置下口令正确也无会话；重置后恢复；导出一致。"""
        login = register_and_activate(self.svc, self.sender, "alice@example.com")
        admin = ActorContext(actor_id="admin-001", role=Role.ADMIN)
        self.svc.bulk_force_reset(admin, [login.user_id])
        with self.assertRaises(AuthError):
            self.svc.validate_session(login.session_token)  # 会话已吊销
        self.clock.advance(seconds=61)
        with self.assertRaises(AuthError) as cm:
            self.svc.login("alice@example.com", GOOD_PASSWORD, client())
        self.assertEqual(cm.exception.code, ErrorCode.PASSWORD_RESET_REQUIRED)
        # 经找回密码流程后恢复
        self.svc.request_password_reset("alice@example.com", client())
        self.svc.reset_password(token_from(self.sender.sent[-1]),
                                "another-good-password-55", client())
        self.clock.advance(seconds=61)
        self.svc.login("alice@example.com", "another-good-password-55", client())
        # 导出与审计用户集合一致
        exported = self.svc.export_affected_users(
            admin, "2020-01-01T00:00:00+00:00", "2030-01-01T00:00:00+00:00")
        audit_users = {r["user_id"] for r in self.svc.storage.query_audit()
                       if r["user_id"]}
        self.assertEqual(set(exported), audit_users)

    def test_st21_rbac_default_deny(self):
        """ST-21 / SR-21: 非 ADMIN actor 调用全部管理方法一律拒绝且无副作用。"""
        login = register_and_activate(self.svc, self.sender, "alice@example.com")
        for actor in (None, ActorContext(actor_id="user-1", role=Role.USER)):
            for op in (
                lambda a=actor: self.svc.ban_user(a, login.user_id),
                lambda a=actor: self.svc.unban_user(a, login.user_id),
                lambda a=actor: self.svc.bulk_force_reset(a, [login.user_id]),
                lambda a=actor: self.svc.export_affected_users(
                    a, "2020-01-01T00:00:00+00:00", "2030-01-01T00:00:00+00:00"),
            ):
                with self.assertRaises(AuthError) as cm:
                    op()
                self.assertEqual(cm.exception.code, ErrorCode.PERMISSION_DENIED)
        row = self.svc.storage.find_user_by_id(login.user_id)
        self.assertEqual(row["status"], AccountStatus.ACTIVE.value)
        self.assertEqual(row["force_password_reset"], 0)
        self.svc.validate_session(login.session_token)  # 会话未被吊销

    def test_st22_growth_protection(self):
        """ST-22 / SR-22: 单用户 20 会话上限淘汰最旧；过期数据可清理。"""
        login1 = register_and_activate(self.svc, self.sender, "alice@example.com")
        tokens = [login1.session_token]
        for _ in range(20):
            self.clock.advance(seconds=61)
            tokens.append(self.svc.login("alice@example.com", GOOD_PASSWORD,
                                         client()).session_token)
        self.assertEqual(self.svc.storage.count_sessions(login1.user_id), 20)
        with self.assertRaises(AuthError):
            self.svc.validate_session(tokens[0])  # 最旧会话已被淘汰
        self.svc.validate_session(tokens[-1])
        self.clock.advance(hours=25)
        self.assertGreaterEqual(self.svc.purge_expired_sessions()["purged"], 1)
        self.assertGreaterEqual(self.svc.purge_expired_tokens()["purged"], 0)


if __name__ == "__main__":
    unittest.main()
