"""DTO（白名单绑定）、账号状态机、枚举与配置。

SR-10 [来源: T-12, C-16.2, C-07.2]: from_dict 仅接受声明字段，未知键拒绝。
SR-08 [来源: C-06, T-12]: 账号状态机，非法迁移抛 IllegalStateError。
SR-09 [来源: T-04, C-16.2]: 输入白名单校验（邮箱/手机号格式、长度上限）。
SR-17 [来源: C-16.1]: 注册必填项最小化，phone 严格可选。
"""
import re
from dataclasses import dataclass, field
from enum import Enum

from .errors import ErrorCode, IllegalStateError, ValidationError

_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
_PHONE_RE = re.compile(r"^\+[1-9]\d{6,14}$")  # SR-09.2: E.164

EMAIL_MAX = 254
USER_AGENT_MAX = 512
IP_MAX = 45


class Role(str, Enum):
    USER = "user"
    ADMIN = "admin"


class AccountStatus(str, Enum):
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    ACTIVE = "ACTIVE"
    BANNED = "BANNED"
    PENDING_DELETION = "PENDING_DELETION"
    PURGED = "PURGED"


# SR-08.2: 状态机白名单，未列出的迁移一律非法
_ALLOWED_TRANSITIONS = {
    (AccountStatus.PENDING_VERIFICATION, AccountStatus.ACTIVE),
    (AccountStatus.ACTIVE, AccountStatus.BANNED),
    (AccountStatus.BANNED, AccountStatus.ACTIVE),
    (AccountStatus.ACTIVE, AccountStatus.PENDING_DELETION),
    (AccountStatus.PENDING_DELETION, AccountStatus.ACTIVE),
    (AccountStatus.PENDING_DELETION, AccountStatus.PURGED),
}


def check_transition(old: AccountStatus, new: AccountStatus) -> None:
    if (old, new) not in _ALLOWED_TRANSITIONS:
        raise IllegalStateError()


def normalize_email(email) -> str:
    """SR-09.2: 邮箱白名单校验 + 小写规范化。不合法不进入存储层。"""
    if not isinstance(email, str) or len(email) > EMAIL_MAX or not _EMAIL_RE.match(email):
        raise ValidationError(ErrorCode.VALIDATION_ERROR)
    return email.lower()


def validate_phone(phone) -> str:
    if not isinstance(phone, str) or not _PHONE_RE.match(phone):
        raise ValidationError(ErrorCode.VALIDATION_ERROR)
    return phone


@dataclass(frozen=True)
class ClientInfo:
    ip: str
    user_agent: str

    def __post_init__(self):
        # SR-09.2: 所有字符串入参设长度上限
        if not isinstance(self.ip, str) or not self.ip or len(self.ip) > IP_MAX:
            raise ValidationError(ErrorCode.VALIDATION_ERROR)
        if not isinstance(self.user_agent, str) or len(self.user_agent) > USER_AGENT_MAX:
            raise ValidationError(ErrorCode.VALIDATION_ERROR)


@dataclass(frozen=True)
class ActorContext:
    """库级管理方法的调用者上下文（SR-21）。actor_id 须为个人化账号标识（T-28）。"""
    actor_id: str
    role: Role


@dataclass(frozen=True)
class RegisterRequest:
    email: str
    password: str
    consent_version: str
    phone: str | None = None

    _ALLOWED_KEYS = frozenset({"email", "password", "phone", "consent_version"})

    @classmethod
    def from_dict(cls, data: dict, audit=None) -> "RegisterRequest":
        """SR-10.1: 字段白名单绑定。未知键（role/status/email_verified/is_admin 等）
        一律拒绝；可选 audit 回调用于记录告警事件。"""
        if not isinstance(data, dict):
            raise ValidationError(ErrorCode.VALIDATION_ERROR)
        unknown = set(data.keys()) - cls._ALLOWED_KEYS
        if unknown:
            if audit is not None:
                # 审计告警：注入提权字段的尝试（T-12）；键名本身非敏感数据
                audit("UNEXPECTED_FIELD", detail={"keys": sorted(unknown)})
            raise ValidationError(ErrorCode.UNEXPECTED_FIELD)
        if not data.get("consent_version"):
            raise ValidationError(ErrorCode.CONSENT_REQUIRED)  # SR-16
        return cls(
            email=data.get("email"),
            password=data.get("password"),
            phone=data.get("phone"),
            consent_version=data["consent_version"],
        )


@dataclass(frozen=True)
class RegisterResult:
    ok: bool = True  # SR-05.4: 新注册与重复注册返回完全一致


@dataclass(frozen=True)
class LoginResult:
    session_token: str
    user_id: str


@dataclass(frozen=True)
class SessionContext:
    user_id: str
    role: Role
    issued_at: str


@dataclass(frozen=True)
class Profile:
    user_id: str
    email: str | None
    phone: str | None
    status: str
    created_at: str


@dataclass(frozen=True)
class AuthConfig:
    """SPEC §5.1 安全基线默认值。配置项不可被请求数据覆盖（SR-04）。"""
    session_idle_minutes: int = 30
    session_absolute_hours: int = 24
    sessions_per_user_max: int = 20
    lockout_threshold: int = 10
    lockout_minutes: int = 15
    backoff_start_at: int = 5
    reset_token_minutes: int = 30
    verify_token_hours: int = 24
    login_ip_per_minute: int = 10
    register_ip_per_minute: int = 10
    reset_per_account_per_minute: int = 1
    reset_per_account_per_day: int = 5
    token_check_ip_per_minute: int = 10
    deletion_grace_days: int = 30
    unverified_purge_hours: int = 72
    password_min: int = 12
    password_max: int = 128
    base_url: str = "https://example.com"
