"""AuthService：业务编排、防枚举、锁定、限流与 RBAC 守卫。

SR 实现索引（详见各方法注释）：
SR-03 登录退避/软锁定/通知    SR-04 多维限流          SR-05 防枚举统一响应+恒时
SR-06 会话全生命周期          SR-07 重置 token 安全    SR-08 状态机与激活
SR-11 对象级授权（防 IDOR）   SR-12 敏感操作重新认证   SR-13 审计（经 audit.py）
SR-15 注销与数据销毁          SR-16 同意记录          SR-20 批量强制重置/导出
SR-21 管理方法 RBAC 默认拒绝  SR-22 会话/数据增长保护
"""
import uuid
from datetime import timedelta

from . import password as pw
from .audit import AuditLog
from .clock import Clock, SystemClock, iso, parse_iso
from .errors import AuthError, ConfigError, ErrorCode, ValidationError
from .masking import blind_index, mask_email, mask_phone
from .models import (AccountStatus, ActorContext, AuthConfig, ClientInfo,
                     LoginResult, Profile, RegisterRequest, RegisterResult,
                     Role, SessionContext, check_transition, normalize_email,
                     validate_phone)
from .notify import EmailSender, SmsSender, send_email
from .ratelimit import RateLimiter
from .storage import Storage
from .tokens import generate_token, hash_token

# token purpose 常量（SPEC §6 tokens.purpose）
_P_VERIFY = "email_verify"
_P_RESET = "password_reset"
_P_CHANGE_OLD = "email_change_old"
_P_CHANGE_NEW = "email_change_new"

# 审计事件类型（SR-13.1 覆盖清单）
EV_REGISTER = "REGISTER"
EV_LOGIN_SUCCESS = "LOGIN_SUCCESS"
EV_LOGIN_FAILURE = "LOGIN_FAILURE"
EV_LOGOUT = "LOGOUT"
EV_ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
EV_RATE_LIMITED = "RATE_LIMITED"
EV_EMAIL_VERIFIED = "EMAIL_VERIFIED"
EV_STATUS_CHANGED = "STATUS_CHANGED"
EV_RESET_REQUESTED = "RESET_REQUESTED"
EV_PASSWORD_RESET = "PASSWORD_RESET"
EV_PASSWORD_CHANGED = "PASSWORD_CHANGED"
EV_REAUTH_FAILED = "REAUTH_FAILED"
EV_PHONE_UPDATED = "PHONE_UPDATED"
EV_EMAIL_CHANGE_REQUESTED = "EMAIL_CHANGE_REQUESTED"
EV_EMAIL_CHANGED = "EMAIL_CHANGED"
EV_DELETION_REQUESTED = "DELETION_REQUESTED"
EV_DELETION_CANCELLED = "DELETION_CANCELLED"
EV_ACCOUNT_PURGED = "ACCOUNT_PURGED"
EV_PII_FULL_VIEW = "PII_FULL_VIEW"
EV_ADMIN_BAN = "ADMIN_BAN"
EV_ADMIN_UNBAN = "ADMIN_UNBAN"
EV_ADMIN_BULK_FORCE_RESET = "ADMIN_BULK_FORCE_RESET"
EV_ADMIN_EXPORT = "ADMIN_EXPORT"
EV_EMAIL_SENT = "EMAIL_SENT"
EV_MAINTENANCE = "MAINTENANCE"


class AuthService:
    def __init__(self, db_path: str, config: AuthConfig,
                 email_sender: EmailSender, sms_sender: SmsSender | None,
                 breach_checker: pw.BreachChecker, pepper: bytes,
                 clock: Clock | None = None):
        # SR-14.1: pepper 必须由配置注入，空值拒绝初始化（禁止硬编码默认值）
        if not pepper:
            raise ConfigError()
        self._config = config
        self._clock = clock or SystemClock()
        self._storage = Storage(db_path)
        self._audit = AuditLog(self._storage, self._clock)
        self._limiter = RateLimiter(self._storage, self._clock)
        self._email = email_sender
        self._sms = sms_sender
        self._breach = breach_checker
        self._pepper = pepper

    # ------------------------------------------------------------------
    # 内部工具
    # ------------------------------------------------------------------

    def _bidx(self, normalized_email: str) -> str:
        return blind_index(self._pepper, normalized_email)

    def _send_mail(self, to_email: str, template_id: str, params: dict,
                   user_id: str | None) -> None:
        """统一发信出口：经白名单网关（SR-18），message_id 写审计（SR-13/T-22）。"""
        result = send_email(self._email, to_email, template_id, params)
        self._audit.log(EV_EMAIL_SENT, user_id=user_id, detail={
            "template_id": template_id,
            "message_id": result.message_id,
            "to": mask_email(to_email),
        })

    def _action_url(self, path: str, token: str) -> str:
        # SR-18.3: 链接仅含不透明 token，无 PII 参数
        return self._config.base_url + path + "?token=" + token

    def _issue_token(self, user_id: str, purpose: str, ttl: timedelta,
                     payload: str | None = None) -> str:
        token = generate_token()
        now = self._clock.now()
        self._storage.create_token(
            token_hash=hash_token(token), user_id=user_id, purpose=purpose,
            created_at=iso(now), expires_at=iso(now + ttl), payload=payload,
        )
        return token

    def _consume_token(self, token: str, purpose: str):
        """SR-07: 一次性、限时；不存在/过期/已用统一 INVALID_TOKEN（SR-05.5）。"""
        row = self._storage.find_token(hash_token(token), purpose)
        if row is None or row["used_at"] is not None \
                or parse_iso(row["expires_at"]) <= self._clock.now():
            raise AuthError(ErrorCode.INVALID_TOKEN)
        self._storage.mark_token_used(row["token_hash"], iso(self._clock.now()))
        return row

    def _check_token_rate(self, client: ClientInfo | None) -> None:
        # SR-04: token 校验同 IP 限流（防在线枚举，T-03.3）
        if client is not None:
            self._rate("tokchk:ip:" + client.ip,
                       self._config.token_check_ip_per_minute, 60, client)

    def _rate(self, bucket: str, limit: int, window: int,
              client: ClientInfo | None) -> None:
        try:
            self._limiter.check(bucket, limit, window)
        except AuthError as exc:
            self._audit.log(EV_RATE_LIMITED,
                            ip=client.ip if client else None,
                            result="blocked", detail={"bucket_kind": bucket.split(":")[0]})
            raise exc

    def _session_context(self, session_token: str) -> tuple[SessionContext, str]:
        """校验会话（SR-06.3 空闲/绝对超时），返回 (上下文, token_hash)。"""
        th = hash_token(session_token)
        row = self._storage.find_session(th)
        if row is None:
            raise AuthError(ErrorCode.NOT_AUTHENTICATED)
        now = self._clock.now()
        idle_deadline = parse_iso(row["last_seen_at"]) + timedelta(
            minutes=self._config.session_idle_minutes)
        abs_deadline = parse_iso(row["created_at"]) + timedelta(
            hours=self._config.session_absolute_hours)
        if now > idle_deadline or now > abs_deadline:
            self._storage.delete_session(th)
            raise AuthError(ErrorCode.NOT_AUTHENTICATED)
        self._storage.touch_session(th, iso(now))
        user = self._storage.find_user_by_id(row["user_id"])
        if user is None:
            self._storage.delete_session(th)
            raise AuthError(ErrorCode.NOT_AUTHENTICATED)
        return SessionContext(
            user_id=row["user_id"], role=Role(user["role"]),
            issued_at=row["created_at"],
        ), th

    def _new_session(self, user_id: str, client: ClientInfo) -> str:
        # SR-22.2: 单用户活跃会话上限，超限淘汰最旧
        while self._storage.count_sessions(user_id) >= self._config.sessions_per_user_max:
            self._storage.delete_oldest_session(user_id)
        token = generate_token()  # SR-06.1/4: 每次登录全新 token（消除会话固定）
        now = self._clock.now()
        self._storage.create_session(
            token_hash=hash_token(token), user_id=user_id, created_at=iso(now),
            expires_at=iso(now + timedelta(hours=self._config.session_absolute_hours)),
            ip=client.ip, user_agent=client.user_agent,
        )
        return token

    def _require_role(self, actor: ActorContext | None, role: Role) -> None:
        """SR-21: 管理方法统一守卫——默认拒绝，先鉴权后执行。"""
        if actor is None or not isinstance(actor, ActorContext) or actor.role != role:
            raise AuthError(ErrorCode.PERMISSION_DENIED)

    def _reauth(self, user, password: str, email_key: str) -> None:
        """SR-12: 敏感操作重新认证；失败计入 SR-03 失败计数。"""
        if not pw.verify_password(password, user["password_hash"] or ""):
            self._record_failure(email_key, user)
            self._audit.log(EV_REAUTH_FAILED, user_id=user["id"], result="failure")
            raise AuthError(ErrorCode.REAUTH_FAILED)

    # ---- SR-03: 失败计数 / 退避 / 软锁定（键 = 规范化邮箱 HMAC，覆盖不存在账号） ----

    def _lockout_key(self, normalized_email: str) -> str:
        return blind_index(self._pepper, "lockout:" + normalized_email)

    def _check_lockout(self, email_key: str) -> None:
        row = self._storage.get_lockout(email_key)
        if row is None:
            return
        now = self._clock.now()
        for col in ("lockout_until", "next_allowed_at"):
            if row[col] is not None:
                deadline = parse_iso(row[col])
                if now < deadline:
                    # SR-03: 退避/锁定期间直接拒绝，不执行口令校验
                    retry = int((deadline - now).total_seconds()) or 1
                    raise AuthError(ErrorCode.ACCOUNT_LOCKED, retry_after=retry)

    def _record_failure(self, email_key: str, user) -> None:
        row = self._storage.get_lockout(email_key)
        count = (row["failed_count"] if row else 0) + 1
        now = self._clock.now()
        next_allowed = None
        lockout_until = None
        if count >= self._config.backoff_start_at:
            # SR-03: 第 5 次起指数退避 min(2^(n-4), 60) 秒
            delay = min(2 ** (count - self._config.backoff_start_at + 1), 60)
            next_allowed = iso(now + timedelta(seconds=delay))
        if count >= self._config.lockout_threshold:
            # SR-03: ≥10 次软锁定 15 分钟 + 通知 + 审计
            lockout_until = iso(now + timedelta(minutes=self._config.lockout_minutes))
            already_locked = row is not None and row["lockout_until"] is not None \
                and parse_iso(row["lockout_until"]) > now
            if not already_locked:
                self._audit.log(EV_ACCOUNT_LOCKED,
                                user_id=user["id"] if user else None,
                                result="locked", detail={"failed_count": count})
                if user is not None and user["email"]:
                    self._send_mail(user["email"], "account_locked", {
                        "retry_after": self._config.lockout_minutes * 60,
                    }, user["id"])
        self._storage.upsert_lockout(email_key, count, next_allowed, lockout_until)

    # ------------------------------------------------------------------
    # FR-01 注册
    # ------------------------------------------------------------------

    def register(self, req: RegisterRequest, client: ClientInfo) -> RegisterResult:
        email = normalize_email(req.email)          # SR-09.2
        phone = validate_phone(req.phone) if req.phone is not None else None  # SR-17
        if not req.consent_version:
            raise ValidationError(ErrorCode.CONSENT_REQUIRED)  # SR-16
        self._rate("reg:ip:" + client.ip,
                   self._config.register_ip_per_minute, 60, client)  # SR-04
        pw.check_password_policy(req.password, email, self._breach)  # SR-02

        existing = self._storage.find_user_by_bidx(self._bidx(email))
        if existing is not None:
            # SR-05.4: 重复注册返回与新注册一致，改发"您已有账号"邮件（防枚举）
            self._send_mail(email, "account_exists", {}, existing["id"])
            self._audit.log(EV_REGISTER, user_id=existing["id"], ip=client.ip,
                            user_agent=client.user_agent, result="duplicate",
                            detail={"email": mask_email(email)})
            return RegisterResult()

        user_id = str(uuid.uuid4())  # SR-11: UUIDv4 主键不可遍历
        now = self._clock.now()
        # SR-10.3: role/status 由服务端默认值写入，不存在用户输入直达路径
        self._storage.create_user(
            user_id=user_id, email=email, email_bidx=self._bidx(email),
            phone=phone, password_hash=pw.hash_password(req.password),  # SR-01
            status=AccountStatus.PENDING_VERIFICATION.value, created_at=iso(now),
        )
        self._storage.add_consent(user_id=user_id,
                                  consent_version=req.consent_version,
                                  consented_at=iso(now), ip=client.ip)  # SR-16
        verify_token = self._issue_token(
            user_id, _P_VERIFY, timedelta(hours=self._config.verify_token_hours))
        self._send_mail(email, "activation", {
            "action_url": self._action_url("/verify-email", verify_token),
            "expires_minutes": self._config.verify_token_hours * 60,
        }, user_id)
        self._audit.log(EV_REGISTER, user_id=user_id, ip=client.ip,
                        user_agent=client.user_agent,
                        detail={"email": mask_email(email)})
        return RegisterResult()

    # ------------------------------------------------------------------
    # FR-02 邮箱验证激活
    # ------------------------------------------------------------------

    def verify_email(self, token: str, client: ClientInfo | None = None) -> None:
        self._check_token_rate(client)
        row = self._consume_token(token, _P_VERIFY)
        user = self._storage.find_user_by_id(row["user_id"])
        if user is None:
            raise AuthError(ErrorCode.INVALID_TOKEN)
        self._transition(user, AccountStatus.ACTIVE)  # SR-08
        self._storage.update_user_fields(
            user["id"], email_verified_at=iso(self._clock.now()))
        self._audit.log(EV_EMAIL_VERIFIED, user_id=user["id"])

    def _transition(self, user, new_status: AccountStatus) -> None:
        old = AccountStatus(user["status"])
        check_transition(old, new_status)  # SR-08.2: 非法迁移抛 IllegalStateError
        self._storage.update_user_fields(user["id"], status=new_status.value)
        # SR-08.3: 每次状态变更写审计（who/when/old→new）
        self._audit.log(EV_STATUS_CHANGED, user_id=user["id"],
                        detail={"old": old.value, "new": new_status.value})

    # ------------------------------------------------------------------
    # FR-03 登录
    # ------------------------------------------------------------------

    def login(self, email: str, password: str, client: ClientInfo) -> LoginResult:
        email = normalize_email(email)
        if not isinstance(password, str) or len(password) > pw.PASSWORD_MAX:
            raise ValidationError(ErrorCode.VALIDATION_ERROR)  # SR-09.2
        self._rate("login:ip:" + client.ip,
                   self._config.login_ip_per_minute, 60, client)  # SR-04
        email_key = self._lockout_key(email)
        self._check_lockout(email_key)  # SR-03: 退避/锁定期间不执行口令校验

        user = self._storage.find_user_by_bidx(self._bidx(email))
        if user is None:
            pw.dummy_verify()  # SR-05.2: 恒时——不存在账号也执行等参数哈希
            self._record_failure(email_key, None)  # SR-03: 不存在账号同样计数
            self._audit.log(EV_LOGIN_FAILURE, ip=client.ip,
                            user_agent=client.user_agent, result="failure",
                            detail={"email": mask_email(email)})
            raise AuthError(ErrorCode.INVALID_CREDENTIALS)  # SR-05.1

        ok = pw.verify_password(password, user["password_hash"] or "")
        status = AccountStatus(user["status"])
        # FR-11: 宽限期内可登录以撤销注销；其余非 ACTIVE 状态一律视同凭据错误（SR-05/SR-08.5）
        allowed_status = status in (AccountStatus.ACTIVE, AccountStatus.PENDING_DELETION)
        if not ok or not allowed_status:
            self._record_failure(email_key, user)
            self._audit.log(EV_LOGIN_FAILURE, user_id=user["id"], ip=client.ip,
                            user_agent=client.user_agent, result="failure")
            raise AuthError(ErrorCode.INVALID_CREDENTIALS)  # SR-05.1: 统一响应

        if user["force_password_reset"]:
            # SR-20.1: 强制重置标记下口令正确也不签发会话
            raise AuthError(ErrorCode.PASSWORD_RESET_REQUIRED)

        self._storage.clear_lockout(email_key)  # SR-03: 成功清零
        token = self._new_session(user["id"], client)
        self._audit.log(EV_LOGIN_SUCCESS, user_id=user["id"], ip=client.ip,
                        user_agent=client.user_agent)
        return LoginResult(session_token=token, user_id=user["id"])

    # ------------------------------------------------------------------
    # FR-04 / FR-05 登出与会话校验
    # ------------------------------------------------------------------

    def logout(self, session_token: str) -> None:
        ctx, th = self._session_context(session_token)
        self._storage.delete_session(th)  # SR-06.5: 即时失效
        self._audit.log(EV_LOGOUT, user_id=ctx.user_id)

    def validate_session(self, session_token: str) -> SessionContext:
        ctx, _ = self._session_context(session_token)
        return ctx

    def rotate_session(self, session_token: str) -> str:
        """SR-06.4: 权限提升时轮换会话，旧 token 立即失效。"""
        ctx, th = self._session_context(session_token)
        row = self._storage.find_session(th)
        client = ClientInfo(ip=row["ip"] or "0.0.0.0",
                            user_agent=row["user_agent"] or "")
        self._storage.delete_session(th)
        return self._new_session(ctx.user_id, client)

    def list_sessions(self, session_token: str) -> list[dict]:
        ctx, _ = self._session_context(session_token)
        rows = [r for r in self._all_sessions(ctx.user_id)]
        return rows

    def _all_sessions(self, user_id: str):
        # 仅返回非敏感元数据（token_hash 不外泄）
        count = self._storage.count_sessions(user_id)
        return [{"count": count}]

    def revoke_all_sessions(self, user_id: str) -> int:
        return self._storage.delete_sessions_for_user(user_id)

    # ------------------------------------------------------------------
    # FR-06 / FR-07 找回密码与重置
    # ------------------------------------------------------------------

    def request_password_reset(self, email: str, client: ClientInfo) -> dict:
        email = normalize_email(email)
        bidx = self._bidx(email)
        # SR-04: 同账号 1/min + 5/day，同 IP 10/min
        self._rate("reset:acct:" + bidx,
                   self._config.reset_per_account_per_minute, 60, client)
        self._rate("reset:acct:day:" + bidx,
                   self._config.reset_per_account_per_day, 86400, client)
        self._rate("reset:ip:" + client.ip, 10, 60, client)

        user = self._storage.find_user_by_bidx(bidx)
        if user is not None:
            status = AccountStatus(user["status"])
            if status == AccountStatus.PENDING_VERIFICATION:
                # SR-08.5: 未激活账号不发重置邮件，改发激活提醒
                self._send_mail(user["email"], "activation_reminder", {}, user["id"])
            elif status in (AccountStatus.ACTIVE, AccountStatus.PENDING_DELETION):
                # SR-07.5: 重新申请使旧 token 全部失效
                self._storage.invalidate_unused_tokens(
                    user["id"], _P_RESET, iso(self._clock.now()))
                reset_token = self._issue_token(
                    user["id"], _P_RESET,
                    timedelta(minutes=self._config.reset_token_minutes))
                self._send_mail(user["email"], "password_reset", {
                    "action_url": self._action_url("/reset-password", reset_token),
                    "expires_minutes": self._config.reset_token_minutes,
                }, user["id"])
        self._audit.log(EV_RESET_REQUESTED, user_id=user["id"] if user else None,
                        ip=client.ip, user_agent=client.user_agent,
                        detail={"email": mask_email(email)})
        return {"ok": True}  # SR-05.3: 无论邮箱是否注册返回统一成功

    def reset_password(self, token: str, new_password: str,
                       client: ClientInfo | None = None) -> None:
        self._check_token_rate(client)  # SR-04 / SR-07.7
        row = self._consume_token(token, _P_RESET)
        user = self._storage.find_user_by_id(row["user_id"])
        if user is None:
            raise AuthError(ErrorCode.INVALID_TOKEN)
        pw.check_password_policy(new_password, user["email"] or "", self._breach)
        self._storage.update_user_fields(
            user["id"],
            password_hash=pw.hash_password(new_password),
            force_password_reset=0,  # SR-20.1: 经找回密码流程后解除强制重置
        )
        self._storage.delete_sessions_for_user(user["id"])  # SR-07.6 / SR-06.5
        self._storage.clear_lockout(self._lockout_key(user["email"]))
        self._send_mail(user["email"], "password_reset_done", {}, user["id"])
        self._audit.log(EV_PASSWORD_RESET, user_id=user["id"],
                        ip=client.ip if client else None)

    # ------------------------------------------------------------------
    # FR-08 修改口令
    # ------------------------------------------------------------------

    def change_password(self, session_token: str, old: str, new: str) -> str:
        ctx, th = self._session_context(session_token)
        user = self._storage.find_user_by_id(ctx.user_id)
        self._reauth(user, old, self._lockout_key(user["email"]))  # SR-12
        pw.check_password_policy(new, user["email"] or "", self._breach)  # SR-02
        self._storage.update_user_fields(
            user["id"], password_hash=pw.hash_password(new))
        row = self._storage.find_session(th)
        client = ClientInfo(ip=row["ip"] or "0.0.0.0",
                            user_agent=row["user_agent"] or "")
        self._storage.delete_sessions_for_user(user["id"])  # SR-06.5: 吊销全部旧会话
        new_token = self._new_session(user["id"], client)
        self._send_mail(user["email"], "password_changed", {}, user["id"])
        self._audit.log(EV_PASSWORD_CHANGED, user_id=user["id"])
        return new_token

    # ------------------------------------------------------------------
    # FR-09 / FR-10 资料查看与更新
    # ------------------------------------------------------------------

    def _resolve_target(self, ctx: SessionContext, user_id: str | None,
                        actor: ActorContext | None, op: str):
        """SR-11: 对象级授权——显式传入的目标 user_id 与会话用户不一致时，
        非 ADMIN 一律 PERMISSION_DENIED（默认拒绝）。"""
        if user_id is None or user_id == ctx.user_id:
            return ctx.user_id
        self._require_role(actor, Role.ADMIN)
        self._audit.log(EV_PII_FULL_VIEW, user_id=user_id,
                        actor_id=actor.actor_id, detail={"op": op, "cross_user": True})
        return user_id

    def get_profile(self, session_token: str, masked: bool = True,
                    user_id: str | None = None,
                    actor: ActorContext | None = None) -> Profile:
        ctx, _ = self._session_context(session_token)
        target = self._resolve_target(ctx, user_id, actor, "get_profile")
        user = self._storage.find_user_by_id(target)
        if user is None:
            raise AuthError(ErrorCode.PERMISSION_DENIED)
        email, phone = user["email"], user["phone"]
        if masked:
            # SR-14.2: 默认脱敏展示
            email = mask_email(email) if email else None
            phone = mask_phone(phone) if phone else None
        else:
            # FR-09: 完整 PII 查看写审计
            self._audit.log(EV_PII_FULL_VIEW, user_id=target,
                            actor_id=actor.actor_id if actor else None,
                            detail={"op": "get_profile"})
        return Profile(user_id=user["id"], email=email, phone=phone,
                       status=user["status"], created_at=user["created_at"])

    def update_phone(self, session_token: str, password: str, new_phone: str,
                     user_id: str | None = None,
                     actor: ActorContext | None = None) -> None:
        ctx, _ = self._session_context(session_token)
        target = self._resolve_target(ctx, user_id, actor, "update_phone")  # SR-11
        user = self._storage.find_user_by_id(ctx.user_id)
        self._reauth(user, password, self._lockout_key(user["email"]))  # SR-12
        phone = validate_phone(new_phone)  # SR-09.2: E.164
        self._storage.update_user_fields(target, phone=phone)
        self._audit.log(EV_PHONE_UPDATED, user_id=target,
                        detail={"phone": mask_phone(phone)})

    def request_email_change(self, session_token: str, password: str,
                             new_email: str) -> None:
        ctx, _ = self._session_context(session_token)
        user = self._storage.find_user_by_id(ctx.user_id)
        self._reauth(user, password, self._lockout_key(user["email"]))  # SR-12
        new_email = normalize_email(new_email)
        # SR-12: 双向验证——旧邮箱确认 token + 新邮箱验证 token，各 24h 一次性
        # payload 存新邮箱；该列与 users.email 同级 PII，静态加密由部署层承接（SR-26）
        old_token = self._issue_token(
            user["id"], _P_CHANGE_OLD,
            timedelta(hours=self._config.verify_token_hours))
        new_token = self._issue_token(
            user["id"], _P_CHANGE_NEW,
            timedelta(hours=self._config.verify_token_hours), payload=new_email)
        self._send_mail(user["email"], "email_change_confirm_old", {
            "action_url": self._action_url("/email-change/confirm", old_token),
            "expires_minutes": self._config.verify_token_hours * 60,
        }, user["id"])
        self._send_mail(new_email, "email_change_verify_new", {
            "action_url": self._action_url("/email-change/verify", new_token),
            "expires_minutes": self._config.verify_token_hours * 60,
        }, user["id"])
        self._audit.log(EV_EMAIL_CHANGE_REQUESTED, user_id=user["id"],
                        detail={"new_email": mask_email(new_email)})

    def confirm_email_change(self, old_token: str, new_token: str,
                             client: ClientInfo | None = None) -> None:
        self._check_token_rate(client)
        old_row = self._consume_token(old_token, _P_CHANGE_OLD)
        new_row = self._consume_token(new_token, _P_CHANGE_NEW)
        if old_row["user_id"] != new_row["user_id"]:
            raise AuthError(ErrorCode.INVALID_TOKEN)
        user = self._storage.find_user_by_id(old_row["user_id"])
        if user is None or not new_row["payload"]:
            raise AuthError(ErrorCode.INVALID_TOKEN)
        new_email = new_row["payload"]
        old_email = user["email"]
        # SR-14: email 与盲索引同步更新
        self._storage.update_user_fields(
            user["id"], email=new_email, email_bidx=self._bidx(new_email))
        self._send_mail(old_email, "email_changed_notice", {}, user["id"])
        self._send_mail(new_email, "email_changed_notice", {}, user["id"])
        self._audit.log(EV_EMAIL_CHANGED, user_id=user["id"], detail={
            "old_email": mask_email(old_email), "new_email": mask_email(new_email),
        })

    # ------------------------------------------------------------------
    # FR-11 注销
    # ------------------------------------------------------------------

    def request_deletion(self, session_token: str, password: str) -> None:
        ctx, _ = self._session_context(session_token)
        user = self._storage.find_user_by_id(ctx.user_id)
        self._reauth(user, password, self._lockout_key(user["email"]))  # SR-12
        self._transition(user, AccountStatus.PENDING_DELETION)  # SR-08
        purge_after = iso(self._clock.now()
                          + timedelta(days=self._config.deletion_grace_days))
        self._storage.update_user_fields(user["id"], purge_after=purge_after)
        self._storage.delete_sessions_for_user(user["id"])  # SR-06.5
        self._send_mail(user["email"], "deletion_requested", {
            "expires_minutes": self._config.deletion_grace_days * 24 * 60,
        }, user["id"])
        self._audit.log(EV_DELETION_REQUESTED, user_id=user["id"])

    def cancel_deletion(self, session_token: str) -> None:
        ctx, _ = self._session_context(session_token)
        user = self._storage.find_user_by_id(ctx.user_id)
        self._transition(user, AccountStatus.ACTIVE)  # SR-08: PENDING_DELETION→ACTIVE
        self._storage.update_user_fields(user["id"], purge_after=None)
        self._audit.log(EV_DELETION_CANCELLED, user_id=user["id"])

    # ------------------------------------------------------------------
    # FR-12 库级管理功能（SR-20 / SR-21）
    # ------------------------------------------------------------------

    def ban_user(self, actor: ActorContext | None, user_id: str) -> None:
        self._require_role(actor, Role.ADMIN)  # SR-21: 先鉴权后执行
        user = self._storage.find_user_by_id(user_id)
        if user is None:
            raise AuthError(ErrorCode.PERMISSION_DENIED)
        self._transition(user, AccountStatus.BANNED)
        self._storage.delete_sessions_for_user(user_id)  # SR-06.5
        self._audit.log(EV_ADMIN_BAN, user_id=user_id, actor_id=actor.actor_id)

    def unban_user(self, actor: ActorContext | None, user_id: str) -> None:
        self._require_role(actor, Role.ADMIN)
        user = self._storage.find_user_by_id(user_id)
        if user is None:
            raise AuthError(ErrorCode.PERMISSION_DENIED)
        self._transition(user, AccountStatus.ACTIVE)
        self._audit.log(EV_ADMIN_UNBAN, user_id=user_id, actor_id=actor.actor_id)

    def bulk_force_reset(self, actor: ActorContext | None,
                         user_ids: list[str]) -> dict:
        """SR-20.1: 吊销目标集合全部会话并置强制重置标记。"""
        self._require_role(actor, Role.ADMIN)
        affected = 0
        for uid in user_ids:
            user = self._storage.find_user_by_id(uid)
            if user is None:
                continue
            self._storage.delete_sessions_for_user(uid)
            self._storage.update_user_fields(uid, force_password_reset=1)
            self._audit.log(EV_ADMIN_BULK_FORCE_RESET, user_id=uid,
                            actor_id=actor.actor_id)
            affected += 1
        return {"affected": affected}

    def export_affected_users(self, actor: ActorContext | None,
                              start_ts: str, end_ts: str) -> list[str]:
        """SR-20.2: 基于审计日志导出时间窗内受影响用户（泄露响应，C-18）。"""
        self._require_role(actor, Role.ADMIN)
        users = self._storage.distinct_audit_users_between(start_ts, end_ts)
        self._audit.log(EV_ADMIN_EXPORT, actor_id=actor.actor_id,
                        detail={"start": start_ts, "end": end_ts,
                                "count": len(users)})
        return users

    # ------------------------------------------------------------------
    # FR-13 后台维护任务
    # ------------------------------------------------------------------

    def purge_unverified_accounts(self) -> dict:
        """SR-08.4: 超 72h 未激活账号整行删除。"""
        cutoff = iso(self._clock.now()
                     - timedelta(hours=self._config.unverified_purge_hours))
        ids = self._storage.list_unverified_before(cutoff)
        for uid in ids:
            self._storage.delete_user(uid)
        self._audit.log(EV_MAINTENANCE, detail={"task": "purge_unverified",
                                                "purged": len(ids)})
        return {"purged": len(ids)}

    def purge_deleted_accounts(self) -> dict:
        """SR-15: 宽限期满硬删除——PII 列置 NULL、状态 PURGED（保留 UUID 行壳
        维持审计引用），会话与 token 全部删除（crypto-shredding 由部署层 SR-26/38 叠加）。"""
        ids = self._storage.list_purgeable(iso(self._clock.now()))
        for uid in ids:
            user = self._storage.find_user_by_id(uid)
            self._transition(user, AccountStatus.PURGED)
            self._storage.update_user_fields(
                uid, email=None, email_bidx=None, phone=None, password_hash=None)
            self._storage.delete_sessions_for_user(uid)
            self._storage.delete_tokens_for_user(uid)
            self._audit.log(EV_ACCOUNT_PURGED, user_id=uid)
        return {"purged": len(ids)}

    def purge_expired_sessions(self) -> dict:
        now = self._clock.now()
        idle_cutoff = iso(now - timedelta(minutes=self._config.session_idle_minutes))
        purged = self._storage.purge_sessions_before(iso(now), idle_cutoff)
        self._audit.log(EV_MAINTENANCE, detail={"task": "purge_sessions",
                                                "purged": purged})
        return {"purged": purged}

    def purge_expired_tokens(self) -> dict:
        purged = self._storage.purge_expired_tokens(iso(self._clock.now()))
        purged += self._limiter.purge_expired()  # SR-22.3
        self._audit.log(EV_MAINTENANCE, detail={"task": "purge_tokens",
                                                "purged": purged})
        return {"purged": purged}

    # ------------------------------------------------------------------
    # 查询辅助（SR-16）
    # ------------------------------------------------------------------

    def get_consent(self, user_id: str) -> list[dict]:
        rows = self._storage.get_consent(user_id)
        return [{"consent_version": r["consent_version"],
                 "consented_at": r["consented_at"]} for r in rows]

    # 测试/审查可见性（只读）
    @property
    def audit(self) -> AuditLog:
        return self._audit

    @property
    def storage(self) -> Storage:
        return self._storage
