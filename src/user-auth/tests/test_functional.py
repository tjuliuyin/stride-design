"""功能测试 FT-01 ~ FT-13（SPEC §8.1）。"""
import unittest

from auth_core import (AccountStatus, ActorContext, AuthError, ErrorCode,
                       RegisterRequest, Role)
from tests.helpers import (GOOD_PASSWORD, client, make_service, register,
                           register_and_activate, token_from)


class FunctionalTests(unittest.TestCase):
    def setUp(self):
        self.svc, self.clock, self.sender = make_service()

    def _user_row(self, email: str):
        from auth_core.masking import blind_index
        from tests.helpers import PEPPER
        return self.svc.storage.find_user_by_bidx(blind_index(PEPPER, email))

    def test_ft01_register(self):
        register(self.svc, self.sender, "alice@example.com", phone="+8613812341234")
        row = self._user_row("alice@example.com")
        self.assertEqual(row["status"], AccountStatus.PENDING_VERIFICATION.value)
        self.assertEqual(self.sender.sent[-1]["template_id"], "activation")
        consent = self.svc.get_consent(row["id"])
        self.assertEqual(consent[0]["consent_version"], "v1.0")
        # 无手机号注册同样成功（FR-01 / SR-17）
        register(self.svc, self.sender, "bob@example.com", ip="203.0.113.2")
        self.assertIsNone(self._user_row("bob@example.com")["phone"])

    def test_ft02_duplicate_register(self):
        register(self.svc, self.sender, "alice@example.com")
        req = RegisterRequest.from_dict({
            "email": "alice@example.com", "password": GOOD_PASSWORD,
            "consent_version": "v1.0",
        })
        result = self.svc.register(req, client())
        self.assertTrue(result.ok)
        self.assertEqual(self.sender.sent[-1]["template_id"], "account_exists")

    def test_ft03_verify_email(self):
        token = register(self.svc, self.sender, "alice@example.com")
        self.svc.verify_email(token)
        self.assertEqual(self._user_row("alice@example.com")["status"],
                         AccountStatus.ACTIVE.value)
        with self.assertRaises(AuthError) as cm:
            self.svc.verify_email(token)  # token 一次性
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_TOKEN)

    def test_ft04_login_success(self):
        login = register_and_activate(self.svc, self.sender, "alice@example.com")
        self.assertTrue(login.session_token)
        events = self.svc.storage.query_audit("LOGIN_SUCCESS")
        self.assertEqual(len(events), 1)

    def test_ft05_logout(self):
        login = register_and_activate(self.svc, self.sender, "alice@example.com")
        self.svc.logout(login.session_token)
        with self.assertRaises(AuthError) as cm:
            self.svc.validate_session(login.session_token)
        self.assertEqual(cm.exception.code, ErrorCode.NOT_AUTHENTICATED)

    def test_ft06_password_reset_flow(self):
        login = register_and_activate(self.svc, self.sender, "alice@example.com")
        self.svc.request_password_reset("alice@example.com", client())
        reset_token = token_from(self.sender.sent[-1])
        new_password = "brand-new-secret-password-77"
        self.svc.reset_password(reset_token, new_password, client())
        # 旧会话全失效
        with self.assertRaises(AuthError):
            self.svc.validate_session(login.session_token)
        # 旧口令失败、新口令成功
        with self.assertRaises(AuthError) as cm:
            self.svc.login("alice@example.com", GOOD_PASSWORD, client())
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_CREDENTIALS)
        self.clock.advance(seconds=61)
        login2 = self.svc.login("alice@example.com", new_password, client())
        self.assertTrue(login2.session_token)

    def test_ft07_change_password(self):
        login = register_and_activate(self.svc, self.sender, "alice@example.com")
        new_password = "brand-new-secret-password-77"
        new_token = self.svc.change_password(login.session_token, GOOD_PASSWORD,
                                             new_password)
        self.assertTrue(self.svc.validate_session(new_token))
        with self.assertRaises(AuthError):
            self.svc.validate_session(login.session_token)
        templates = [m["template_id"] for m in self.sender.sent]
        self.assertIn("password_changed", templates)

    def test_ft08_get_profile(self):
        login = register_and_activate(self.svc, self.sender, "alice@example.com",
                                      phone="+8613812341234")
        profile = self.svc.get_profile(login.session_token)
        self.assertEqual(profile.email, "a***@example.com")
        self.assertEqual(profile.phone, "+86138****1234")
        full = self.svc.get_profile(login.session_token, masked=False)
        self.assertEqual(full.email, "alice@example.com")
        self.assertTrue(self.svc.storage.query_audit("PII_FULL_VIEW"))

    def test_ft09_update_phone_and_email_change(self):
        login = register_and_activate(self.svc, self.sender, "alice@example.com")
        self.svc.update_phone(login.session_token, GOOD_PASSWORD, "+8613900001111")
        full = self.svc.get_profile(login.session_token, masked=False)
        self.assertEqual(full.phone, "+8613900001111")
        # 换绑双 token
        self.svc.request_email_change(login.session_token, GOOD_PASSWORD,
                                      "alice-new@example.com")
        new_mail = self.sender.sent[-1]
        old_mail = self.sender.sent[-2]
        self.assertEqual(old_mail["template_id"], "email_change_confirm_old")
        self.assertEqual(new_mail["template_id"], "email_change_verify_new")
        self.svc.confirm_email_change(token_from(old_mail), token_from(new_mail))
        notified = [m["to"] for m in self.sender.sent
                    if m["template_id"] == "email_changed_notice"]
        self.assertCountEqual(notified,
                              ["alice@example.com", "alice-new@example.com"])
        self.assertIsNotNone(self._user_row("alice-new@example.com"))
        self.assertIsNone(self._user_row("alice@example.com"))

    def test_ft10_deletion_cancel_and_purge(self):
        login = register_and_activate(self.svc, self.sender, "alice@example.com")
        self.svc.request_deletion(login.session_token, GOOD_PASSWORD)
        row = self._user_row("alice@example.com")
        self.assertEqual(row["status"], AccountStatus.PENDING_DELETION.value)
        # 宽限期内重新登录并撤销
        self.clock.advance(seconds=61)
        login2 = self.svc.login("alice@example.com", GOOD_PASSWORD, client())
        self.svc.cancel_deletion(login2.session_token)
        self.assertEqual(self._user_row("alice@example.com")["status"],
                         AccountStatus.ACTIVE.value)
        # 再次注销并到期清除
        self.svc.request_deletion(login2.session_token, GOOD_PASSWORD)
        self.clock.advance(days=31)
        result = self.svc.purge_deleted_accounts()
        self.assertEqual(result["purged"], 1)
        self.assertIsNone(self._user_row("alice@example.com"))

    def test_ft11_admin_operations(self):
        login = register_and_activate(self.svc, self.sender, "alice@example.com")
        admin = ActorContext(actor_id="admin-001", role=Role.ADMIN)
        self.svc.ban_user(admin, login.user_id)
        row = self._user_row("alice@example.com")
        self.assertEqual(row["status"], AccountStatus.BANNED.value)
        self.svc.unban_user(admin, login.user_id)
        self.assertEqual(self.svc.bulk_force_reset(admin, [login.user_id]),
                         {"affected": 1})
        exported = self.svc.export_affected_users(
            admin, "2020-01-01T00:00:00+00:00", "2030-01-01T00:00:00+00:00")
        self.assertIn(login.user_id, exported)
        for ev in ("ADMIN_BAN", "ADMIN_UNBAN", "ADMIN_BULK_FORCE_RESET",
                   "ADMIN_EXPORT"):
            self.assertTrue(self.svc.storage.query_audit(ev), ev)

    def test_ft12_maintenance_tasks(self):
        register(self.svc, self.sender, "stale@example.com")
        register_and_activate(self.svc, self.sender, "alice@example.com",
                              ip="203.0.113.9")
        self.clock.advance(hours=73)
        self.assertEqual(self.svc.purge_unverified_accounts()["purged"], 1)
        self.assertGreaterEqual(self.svc.purge_expired_sessions()["purged"], 1)
        self.assertGreaterEqual(self.svc.purge_expired_tokens()["purged"], 1)

    def test_ft13_login_success_resets_failures(self):
        register_and_activate(self.svc, self.sender, "alice@example.com")
        for _ in range(3):
            self.clock.advance(seconds=61)
            with self.assertRaises(AuthError):
                self.svc.login("alice@example.com", "wrong-password-123", client())
        self.clock.advance(seconds=61)
        self.svc.login("alice@example.com", GOOD_PASSWORD, client())
        from auth_core.masking import blind_index
        from tests.helpers import PEPPER
        key = blind_index(PEPPER, "lockout:alice@example.com")
        self.assertIsNone(self.svc.storage.get_lockout(key))


if __name__ == "__main__":
    unittest.main()
